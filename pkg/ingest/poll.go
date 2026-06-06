// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/securityportal/securityportal-api/pkg/config"
	"github.com/securityportal/securityportal-api/pkg/database"
)

// watermarkKey is the ingest_state key under which the provider-wide watermark
// is stored. v1 targets a single Trusted Provider, so one key per provider URL
// is sufficient; the table is keyed by feed_url to leave room for per-feed
// watermarks later without a schema change.
//
// NOTE: incremental skipping via this watermark is deferred pending OQ-6. The
// cycle currently always pulls completely so the present-set is authoritative
// for the deletion sweep; the watermark is recorded for resumability/future use.
func watermarkKey(providerURL string) string { return providerURL }

// maxSweepWithdrawFraction caps how much of the currently-active corpus a single
// deletion sweep may tombstone. Tombstoning is destructive and irreversible
// within a cycle, so if a sweep would withdraw more than this fraction of the
// live advisories we refuse it and log loudly for an operator to investigate,
// rather than mass-withdrawing on what is far more likely a provider regression,
// a partial outage, or a config mistake than a legitimate bulk retirement. The
// guard is intentionally conservative: err on the side of NOT deleting. A
// genuine large retirement can be applied after operator review (or it converges
// over subsequent cycles once each advisory truly disappears).
//
// The guard only engages once the corpus is large enough that a fraction is
// meaningful (see minCorpusForFractionGuard); below that, the empty-present-set
// guard alone protects against the catastrophic wipe case.
const maxSweepWithdrawFraction = 0.5

// minCorpusForFractionGuard is the number of active advisories below which the
// fraction guard is not applied. With only a handful of advisories, a legitimate
// cycle can easily change a large fraction (e.g. 1 of 2 retired), so the
// fraction test would produce false positives; the empty-present guard still
// applies at all sizes.
const minCorpusForFractionGuard = 10

// RunOnce performs a single complete ingestion cycle: fetch + verify every
// current advisory, persist the publishable ones, advance the watermark, and —
// only when a complete, healthy enumeration can be proven — run the deletion
// (tombstone) sweep. It returns the persistence counts.
//
// Design note on completeness vs. the incremental watermark: the tombstone sweep
// may only run after a COMPLETE enumeration of the feeds — otherwise advisories
// that are merely absent because an incremental poll skipped them, or because a
// feed transiently failed to load, would be wrongly withdrawn. A cycle therefore
// always pulls completely (ageAccept = nil) so the present-set is authoritative.
// The watermark is recorded each successful cycle for resumability and future
// incremental optimisation (deferred pending OQ-6); it is advanced ONLY after a
// fully successful cycle, so an interrupted run simply re-pulls next time.
//
// Tombstoning is destructive, so it requires affirmative proof of a complete,
// healthy enumeration. Two independent guards protect the corpus:
//
//	Layer 1 (positive evidence): the sweep runs only when EVERY publishable feed
//	in the PMD fetched and parsed without error (sum.Health.EnumeratedAll). gocsaf
//	swallows per-feed fetch errors and still reports the run "complete", so we
//	probe the feeds independently; if any expected feed failed we keep whatever we
//	verified but skip the sweep this cycle.
//
//	Layer 2 (defence in depth): even with positive evidence, the sweep never runs
//	on an empty present-set, and refuses to withdraw an implausibly large fraction
//	of the active corpus in one cycle (see maxSweepWithdrawFraction). When in
//	doubt, do not sweep.
func RunOnce(ctx context.Context, cfg *config.Config, store Store) (PersistCounts, error) {
	persister := NewPersister(ctx, cfg, store)

	// Complete pull (ageAccept nil): every current file is enumerated and
	// downloaded, so the present-set is authoritative for the sweep.
	sum, err := FetchAndVerify(ctx, cfg, persister.Handle, nil)
	if err != nil {
		// A failed cycle must not advance the watermark or sweep — the feed view
		// is incomplete and tombstoning now could wipe the portal.
		return persister.Counts(), fmt.Errorf("ingestion cycle failed: %w", err)
	}
	if !sum.Complete {
		// Defensive: RunOnce always requests a complete pull. If that ever changes
		// without updating this guard, refuse to sweep rather than risk deletion.
		return persister.Counts(), errors.New("refusing to sweep after an incomplete enumeration")
	}

	counts := persister.Counts()
	present := persister.Present()

	withdrawn, swept, err := maybeSweep(ctx, cfg, store, sum, present)
	if err != nil {
		return counts, err
	}

	// Advance the watermark only now that the whole cycle (fetch, persist, and the
	// sweep decision) has succeeded, so it stays consistent with what is stored.
	if err := store.SetWatermark(ctx, watermarkKey(cfg.ProviderURL), time.Now().UTC()); err != nil {
		return counts, fmt.Errorf("recording watermark failed: %w", err)
	}

	slog.Info("ingestion cycle complete",
		"provider_url", cfg.ProviderURL,
		"verified", sum.Verified,
		"stored", counts.Stored,
		"duplicate", counts.Duplicate,
		"skipped_verify", sum.Skipped,
		"skipped_feed", sum.SkippedFeed,
		"skipped_tlp", counts.SkippedTLP,
		"feeds_expected", sum.Health.Expected,
		"feeds_loaded", sum.Health.Loaded,
		"swept", swept,
		"withdrawn", withdrawn,
		"present", len(present),
	)
	return counts, nil
}

// maybeSweep applies the two-layer safety gate and runs TombstoneAbsent only when
// it is provably safe. It returns the number of advisories withdrawn and whether
// the sweep actually ran. A skipped sweep is NOT an error — the cycle still
// succeeds, having persisted whatever it verified; the next healthy cycle
// reconciles deletions.
func maybeSweep(
	ctx context.Context,
	cfg *config.Config,
	store Store,
	sum Summary,
	present []database.AdvisoryKey,
) (withdrawn int64, swept bool, err error) {
	// Layer 1: positive evidence of a complete, healthy enumeration. Without it
	// an absent advisory cannot be distinguished from a transiently-failed feed.
	if !sum.Health.EnumeratedAll {
		slog.Warn("skipping deletion sweep: enumeration was not provably complete",
			"provider_url", cfg.ProviderURL,
			"feeds_expected", sum.Health.Expected,
			"feeds_loaded", sum.Health.Loaded)
		return 0, false, nil
	}

	// Layer 2a: never tombstone on an empty present-set. Even a "healthy" cycle
	// that legitimately yielded zero publishable documents must not withdraw the
	// entire corpus; treat zero-present as "nothing reliably enumerated".
	if len(present) == 0 {
		slog.Warn("skipping deletion sweep: present-set is empty",
			"provider_url", cfg.ProviderURL)
		return 0, false, nil
	}

	// Layer 2b: refuse to withdraw an implausibly large fraction of the live
	// corpus in a single cycle. Anything absent from present would be withdrawn,
	// so (active - present-that-are-active) is an upper bound on the sweep size;
	// we approximate conservatively with (active - len(present)) clamped at zero.
	active, err := store.CountActiveAdvisories(ctx)
	if err != nil {
		return 0, false, fmt.Errorf("counting active advisories before sweep: %w", err)
	}
	if active >= minCorpusForFractionGuard {
		wouldWithdraw := active - int64(len(present))
		if wouldWithdraw < 0 {
			wouldWithdraw = 0
		}
		if float64(wouldWithdraw) > maxSweepWithdrawFraction*float64(active) {
			slog.Warn("skipping deletion sweep: would withdraw an implausibly large fraction of the corpus; "+
				"operator review required",
				"provider_url", cfg.ProviderURL,
				"active", active,
				"present", len(present),
				"would_withdraw", wouldWithdraw,
				"max_fraction", maxSweepWithdrawFraction)
			return 0, false, nil
		}
	}

	withdrawn, err = store.TombstoneAbsent(ctx, present)
	if err != nil {
		return 0, false, fmt.Errorf("deletion sweep failed: %w", err)
	}
	return withdrawn, true, nil
}

// Poll runs RunOnce immediately and then once per cfg.PollInterval until the
// context is cancelled. A failed cycle is logged and the loop continues — a
// transient provider problem must not crash the worker — and crucially a failed
// cycle never advances the watermark or tombstones, so the next cycle resumes
// cleanly. Poll returns the context's error once cancelled.
func Poll(ctx context.Context, cfg *config.Config, store Store) error {
	if err := cfg.ValidateForIngest(); err != nil {
		return fmt.Errorf("ingest configuration invalid: %w", err)
	}

	runCycle := func() {
		counts, err := RunOnce(ctx, cfg, store)
		if err != nil {
			// Ignore cancellation noise: a cancel during a cycle is the shutdown
			// path, reported by the loop below.
			if ctx.Err() != nil {
				return
			}
			slog.Error("ingestion cycle failed", "error", err)
			return
		}
		slog.Info("ingestion cycle stored advisories",
			"stored", counts.Stored, "duplicate", counts.Duplicate, "skipped_tlp", counts.SkippedTLP)
	}

	// Run one cycle straight away so the portal populates without waiting a full
	// interval on startup.
	runCycle()

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("ingestion poll loop stopping", "reason", ctx.Err())
			return ctx.Err()
		case <-ticker.C:
			runCycle()
		}
	}
}
