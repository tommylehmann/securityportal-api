// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package ingest

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/securityportal/securityportal-api/pkg/config"
)

// FetchAndVerify runs a single ingestion pass against the configured provider:
// it loads and validates the provider-metadata.json, enumerates the ROLIE
// feeds, and downloads + verifies every advisory, handing each verified
// document to handler. It performs no persistence — the handler decides what to
// do with verified advisories (the persistence handler wires in the database
// upsert and the per-document TLP publish gate). A summary of the run is
// returned.
//
// The context cancels the pass at file boundaries. When ageAccept is non-nil it
// limits enumeration to files newer than the watermark it encodes (an
// incremental poll); a nil ageAccept performs a complete pull. The configured
// publishable-TLP set is installed as an early feed-level filter so restricted
// feeds are never downloaded.
func FetchAndVerify(
	ctx context.Context,
	cfg *config.Config,
	handler AdvisoryHandler,
	ageAccept func(time.Time) bool,
) (Summary, error) {
	if err := cfg.ValidateForIngest(); err != nil {
		return Summary{}, fmt.Errorf("ingest configuration invalid: %w", err)
	}

	client := newHTTPClient()

	lpmd, pmd, err := LoadProviderMetadata(client, cfg.ProviderURL)
	if err != nil {
		return Summary{}, err
	}

	downloader, err := NewDownloader(client, lpmd, pmd, handler)
	if err != nil {
		return Summary{}, err
	}
	downloader.SetPublishable(cfg.IsPublishable)

	sum, err := downloader.Run(ctx, ageAccept)
	if err != nil {
		return sum, err
	}

	// Establish positive evidence that every publishable feed loaded cleanly.
	// gocsaf swallows per-feed fetch errors, so a "complete" run with no error is
	// NOT proof that the present-set is authoritative; the sweep keys off this
	// probe, never off sum.Complete alone.
	sum.Health = checkFeedHealth(client, pmd, downloader.pmdURL, cfg.IsPublishable)

	slog.Info("ingestion pass complete",
		"provider_url", cfg.ProviderURL,
		"verified", sum.Verified,
		"skipped", sum.Skipped,
		"skipped_feed", sum.SkippedFeed,
		"complete", sum.Complete,
		"feeds_expected", sum.Health.Expected,
		"feeds_loaded", sum.Health.Loaded,
		"enumerated_all", sum.Health.EnumeratedAll,
	)
	return sum, nil
}
