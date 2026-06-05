// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 SecurityPortal contributors

package ingest

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/util"
)

// FeedHealth is positive evidence that every publishable ROLIE feed listed in
// the provider-metadata.json was fetched and parsed without error during this
// cycle. The deletion sweep (TombstoneAbsent) is destructive, so it must only
// run when EnumeratedAll is true: an absent advisory is then provably gone from
// the provider rather than merely missing because a feed transiently failed.
//
// This is a deliberate, independent re-check of feed reachability. The gocsaf
// AdvisoryFileProcessor.processROLIE swallows per-feed fetch/parse failures with
// a logged `continue` and still returns nil, so a provider 500 on a feed yields
// zero files and a "complete" (ageAccept==nil) run with no error. We therefore
// cannot trust Summary.Complete as evidence of healthy enumeration; we probe the
// feeds ourselves and only declare the enumeration trustworthy when every
// publishable feed loaded cleanly.
type FeedHealth struct {
	// Expected is the number of publishable ROLIE feeds advertised by the PMD.
	Expected int
	// Loaded is the number of those feeds that fetched and parsed successfully.
	Loaded int
	// EnumeratedAll is true only when every expected publishable feed loaded
	// without error (and at least one feed was expected). It is the precondition
	// for running the deletion sweep.
	EnumeratedAll bool
}

// checkFeedHealth probes every publishable ROLIE feed referenced by the provider
// metadata and reports whether they all loaded cleanly. publishable is the
// per-feed TLP gate (nil accepts all feeds); only feeds we would actually ingest
// are required to be healthy, so a restricted feed that is intentionally skipped
// does not block the sweep.
//
// A directory/index.txt-based provider (no ROLIE feeds) yields Expected == 0 and
// EnumeratedAll == false: we have no per-feed reachability signal for that layout,
// so — erring on the side of NOT deleting — the sweep is skipped. v1 targets a
// ROLIE Trusted Provider, so this conservative stance is acceptable.
func checkFeedHealth(
	client util.Client,
	pmd *csaf.ProviderMetadata,
	pmdURL *url.URL,
	publishable func(csaf.TLPLabel) bool,
) FeedHealth {
	var health FeedHealth

	for i := range pmd.Distributions {
		rolie := pmd.Distributions[i].Rolie
		if rolie == nil {
			continue
		}
		for j := range rolie.Feeds {
			feed := &rolie.Feeds[j]
			if feed.URL == nil {
				continue
			}
			// Only feeds we would actually ingest matter for the sweep: a
			// restricted feed is intentionally never enumerated, so its
			// reachability must not gate deletion.
			if publishable != nil {
				var label csaf.TLPLabel
				if feed.TLPLabel != nil {
					label = *feed.TLPLabel
				}
				if !publishable(label) {
					continue
				}
			}
			health.Expected++
			if err := probeFeed(client, pmdURL, string(*feed.URL)); err != nil {
				slog.Warn("feed health probe failed; deletion sweep will be skipped this cycle",
					"feed_url", string(*feed.URL), "error", err)
				continue
			}
			health.Loaded++
		}
	}

	health.EnumeratedAll = health.Expected > 0 && health.Loaded == health.Expected
	return health
}

// probeFeed fetches a single ROLIE feed URL and confirms it parses as a ROLIE
// feed. It returns a non-nil error for exactly the failures gocsaf swallows: an
// unreachable feed, a non-200 status, or an unparseable body.
func probeFeed(client util.Client, pmdURL *url.URL, feedURL string) error {
	parsed, err := url.Parse(feedURL)
	if err != nil {
		return fmt.Errorf("parsing feed URL %q: %w", feedURL, err)
	}
	if !parsed.IsAbs() {
		parsed = pmdURL.ResolveReference(parsed)
	}

	resp, err := client.Get(parsed.String())
	if err != nil {
		return fmt.Errorf("fetching feed %q: %w", parsed, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching feed %q: %s (%d)",
			parsed, http.StatusText(resp.StatusCode), resp.StatusCode)
	}
	if _, err := csaf.LoadROLIEFeed(resp.Body); err != nil {
		return fmt.Errorf("parsing feed %q: %w", parsed, err)
	}
	return nil
}
