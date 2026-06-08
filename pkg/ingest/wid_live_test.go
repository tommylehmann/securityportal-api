// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

//go:build wid_live

// Package ingest — live integration test against the real BSI WID CSAF provider.
//
// # What this test does
//
// It exercises the full ingest pipeline — LoadProviderMetadata → NewDownloader →
// Run — against the real BSI WID Trusted Provider at
// https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json. The test is
// bounded: only the first N advisories enumerated by the ROLIE feed are downloaded,
// verified, and (when DinD Postgres is available) persisted. The full corpus is
// large (thousands of mostly-German TLP:WHITE advisories) and ingestion performs a
// full pull every cycle (OQ-6), so an uncapped run would be expensive.
//
// # How to run
//
//	SECURITYPORTAL_WID_LIVE=1 go test -tags wid_live ./pkg/ingest/ -run WID -v -timeout 120s
//
// Override the advisory cap (default 10):
//
//	SECURITYPORTAL_WID_LIVE=1 WID_LIVE_MAX=20 go test -tags wid_live ./pkg/ingest/ -run WID -v -timeout 120s
//
// The wid_live build tag excludes this file from the default `go test ./...` run
// so it never breaks CI or offline builds.
//
// # BSI WID corpus notes
//
//   - Provider: https://wid.cert-bund.de
//   - Language: mostly German; a subset of advisories carry an English lang field.
//   - TLP: predominantly TLP:WHITE (public). The publishable set is WHITE + UNLABELED.
//   - Full-pull cost (OQ-6): a complete enumeration fetches every advisory on every
//     poll cycle. With thousands of advisories this can take tens of minutes.
//     Set SECURITYPORTAL_POLL_INTERVAL=6h in production (.env.wid.example).
//   - Persistence: when Docker-in-Docker is available (the devcontainer ships it),
//     the test drives the real Persister → *database.DB path and asserts at least
//     one advisory was stored. If Docker is unavailable, the persistence step is
//     skipped and the test still passes on the verify-only assertion.
package ingest

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gocsaf/csaf/v3/csaf"

	"github.com/securityportal/securityportal-api/internal/dbtest"
	"github.com/securityportal/securityportal-api/pkg/config"
	"github.com/securityportal/securityportal-api/pkg/database"
)

const (
	// widPMDURL is the direct PMD URL for the BSI WID CSAF Trusted Provider.
	// When SECURITYPORTAL_PROVIDER_URL starts with "https://", the gocsaf
	// ProviderMetadataLoader.Load() short-circuits and fetches the JSON directly
	// from this URL — no well-known / security.txt / DNS discovery required. No
	// code change to pkg/ingest/provider.go is needed (spec §16.6).
	widPMDURL = "https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json"

	// widLiveDefaultMax caps the number of advisories downloaded and verified in
	// one test run. Kept low to avoid hammering the provider and to keep the test
	// fast. Override via WID_LIVE_MAX env var.
	widLiveDefaultMax = 10
)

// liveBoundSentinel is returned by the bounded handler once enough advisories have
// been verified. The downloader wraps it in a fmt.Errorf chain; we use errors.As
// to detect it so the test does not treat it as a real failure.
type liveBoundSentinel struct{}

func (e *liveBoundSentinel) Error() string { return "live test bound reached" }

// TestWIDLiveIngestBoundedSubset exercises the full ingest pipeline against the
// real BSI WID provider, bounded to the first N advisories in the feed.
//
// It asserts:
//   - provider-metadata.json loads and is valid,
//   - at least one advisory passes hash + PGP verification,
//   - (optional) at least one advisory is stored in DinD Postgres.
func TestWIDLiveIngestBoundedSubset(t *testing.T) {
	// Secondary guard: even with the build tag, require the explicit env flag so
	// the test cannot run accidentally from a compiled binary.
	if os.Getenv("SECURITYPORTAL_WID_LIVE") != "1" {
		t.Skip("set SECURITYPORTAL_WID_LIVE=1 to run the live WID integration test")
	}

	max := widLiveDefaultMax
	if s := os.Getenv("WID_LIVE_MAX"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 1 {
			t.Fatalf("WID_LIVE_MAX must be a positive integer, got %q", s)
		}
		max = v
	}
	t.Logf("WID live test: downloading at most %d advisory(ies) from %s", max, widPMDURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	client := newHTTPClient()

	// --- Step 1: load and validate the real provider-metadata.json. ---
	t.Log("Loading provider-metadata.json from BSI WID...")
	lpmd, pmd, err := LoadProviderMetadata(client, widPMDURL)
	if err != nil {
		t.Fatalf("LoadProviderMetadata(%q): %v", widPMDURL, err)
	}
	if !lpmd.Valid() {
		t.Fatal("BSI WID provider-metadata.json is not valid")
	}
	t.Logf("PMD loaded: source=%s PGP_keys=%d distributions=%d",
		lpmd.URL, len(pmd.PGPKeys), len(pmd.Distributions))

	// --- Step 2: bounded handler — stops once max advisories are verified. ---
	var verified []VerifiedAdvisory
	sentinel := &liveBoundSentinel{}
	handler := func(va VerifiedAdvisory) error {
		verified = append(verified, va)
		slog.Info("WID live: advisory verified",
			"n", len(verified), "url", va.URL, "tlp", va.TLP, "bytes", len(va.Raw))
		if len(verified) >= max {
			// Return the sentinel to abort enumeration. The downloader wraps it
			// in fmt.Errorf; Run returns a non-nil error, which we detect below.
			return sentinel
		}
		return nil
	}

	// --- Step 3: build the downloader with the real WID PGP key ring. ---
	dl, err := NewDownloader(client, lpmd, pmd, handler)
	if err != nil {
		t.Fatalf("NewDownloader: %v — the BSI WID provider may have no usable PGP keys", err)
	}
	// Apply the standard publishable-TLP gate (WHITE + UNLABELED).
	dl.SetPublishable(func(label csaf.TLPLabel) bool {
		switch label {
		case csaf.TLPLabelWhite, csaf.TLPLabelUnlabeled:
			return true
		default:
			return false
		}
	})

	// --- Step 4: run enumeration (bounded by the handler sentinel). ---
	t.Logf("Enumerating BSI WID feeds (will stop after %d verified)...", max)
	sum, runErr := dl.Run(ctx, nil)

	// The sentinel propagates up through the handler error chain. Any OTHER error
	// is a real failure.
	var lbs *liveBoundSentinel
	if runErr != nil && !errors.As(runErr, &lbs) {
		t.Fatalf("Run returned an unexpected error: %v", runErr)
	}
	if errors.As(runErr, &lbs) {
		t.Logf("Bound reached (%d advisory(ies) verified); enumeration stopped", max)
	}

	t.Logf("Run summary: verified=%d skipped=%d skipped_feed=%d",
		sum.Verified, sum.Skipped, sum.SkippedFeed)

	// Core assertion: at least one advisory must have passed hash + PGP
	// verification against the real WID key ring and the real advisory corpus.
	if len(verified) == 0 {
		t.Fatal("no advisories were verified — hash or PGP verification failed for all fetched files; " +
			"check network connectivity and BSI WID key availability")
	}
	t.Logf("PASS (verify): %d advisory(ies) verified against real BSI WID hash+PGP pipeline", len(verified))
	for i, va := range verified {
		t.Logf("  [%d] TLP=%s bytes=%d URL=%s", i+1, va.TLP, len(va.Raw), va.URL)
	}

	// --- Step 5 (optional): persist into DinD Postgres. ---
	// Skip if Docker is unavailable; the verify assertion above is the primary one.
	if !dockerAvailable() {
		t.Log("Docker unavailable; skipping Postgres persistence step (verify assertion passed)")
		return
	}
	t.Log("Docker available — running Postgres persistence step...")

	// Use a separate bounded context for the Postgres step so the 5-minute
	// enumeration timeout does not carry over.
	pgCtx, pgCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer pgCancel()

	pool, dsn, dbCtx := dbtest.StartPostgres(t)
	// StartPostgres may call t.Skip internally; if it returns a valid pool we
	// proceed, otherwise we're done.
	if pool == nil {
		t.Log("StartPostgres skipped (docker not reachable); persistence step skipped")
		return
	}
	_ = dbCtx // dbCtx is tied to the test via t.Cleanup; we use our own pgCtx below.
	defer pool.Close()

	db, err := database.NewDB(pgCtx, dsn, 0)
	if err != nil {
		t.Fatalf("database.NewDB: %v", err)
	}
	defer db.Close()
	if err := db.Migrate(pgCtx); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}

	cfg := &config.Config{
		ProviderURL:    widPMDURL,
		PublishableTLP: []csaf.TLPLabel{csaf.TLPLabelWhite, csaf.TLPLabelUnlabeled},
		PollInterval:   6 * time.Hour,
	}

	persister := NewPersister(pgCtx, cfg, db)
	for _, va := range verified {
		if err := persister.Handle(va); err != nil {
			t.Fatalf("persister.Handle(%s): %v", va.URL, err)
		}
	}
	counts := persister.Counts()
	t.Logf("Persistence: stored=%d duplicate=%d skipped_tlp=%d",
		counts.Stored, counts.Duplicate, counts.SkippedTLP)

	// At least one advisory must have been stored or found as a duplicate (meaning
	// it was already present — both outcomes mean the pipeline end-to-end worked).
	if counts.Stored+counts.Duplicate == 0 {
		t.Fatal("no advisories were stored or found as duplicate in Postgres — " +
			"the TLP gate may be dropping all WID advisories (check PublishableTLP config)")
	}
	t.Logf("PASS (persist): %d advisory(ies) stored in DinD Postgres (%d duplicate(s))",
		counts.Stored, counts.Duplicate)

	_ = pgCtx // suppress unused warning; pgCancel runs via defer.
}

// dockerAvailable returns true when the docker daemon is reachable. It mirrors
// the check in dbtest.StartPostgres so we can gate the persistence step without
// relying on t.Skip from inside a sub-test.
func dockerAvailable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	out, err := exec.Command("docker", "info").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "Server Version")
}
