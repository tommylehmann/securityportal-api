// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 SecurityPortal contributors

package ingest

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gocsaf/csaf/v3/csaf"

	"github.com/securityportal/securityportal-api/pkg/config"
	"github.com/securityportal/securityportal-api/pkg/database"
)

// Store is the persistence seam the ingester writes through. It is satisfied by
// *database.DB; defining it here keeps the ingest package testable without a
// real database and avoids a hard dependency direction surprise.
type Store interface {
	StoreDocument(
		ctx context.Context,
		trackingID, publisher string,
		document map[string]any,
		original []byte,
	) (database.StoreResult, error)
	Watermark(ctx context.Context, feedURL string) (time.Time, bool, error)
	SetWatermark(ctx context.Context, feedURL string, watermark time.Time) error
	CountActiveAdvisories(ctx context.Context) (int64, error)
	TombstoneAbsent(ctx context.Context, present []database.AdvisoryKey) (int64, error)
}

// PersistCounts accumulates what a persisting run did, for structured logging.
type PersistCounts struct {
	// Stored is the number of new document revisions written.
	Stored int
	// Duplicate is the number of revisions already present (idempotent no-ops).
	Duplicate int
	// SkippedTLP is the number of verified advisories dropped by the per-document
	// TLP publish gate.
	SkippedTLP int
}

// Persister is an AdvisoryHandler factory that gates verified advisories on the
// publish-TLP policy and upserts the publishable ones into the store. It also
// records the (tracking_id, publisher) of every publishable advisory it saw so
// the poll loop can compute which advisories have vanished from the feed.
type Persister struct {
	cfg    *config.Config
	store  Store
	ctx    context.Context
	counts PersistCounts
	// present collects the natural key of every publishable advisory handled in
	// the current run, deduplicated.
	present map[database.AdvisoryKey]struct{}
}

// NewPersister builds a Persister bound to a context, config, and store.
func NewPersister(ctx context.Context, cfg *config.Config, store Store) *Persister {
	return &Persister{
		cfg:     cfg,
		store:   store,
		ctx:     ctx,
		present: make(map[database.AdvisoryKey]struct{}),
	}
}

// Handle is the AdvisoryHandler. It applies the TLP gate, extracts the advisory
// key, and persists the revision. Returning an error aborts the run (a real
// persistence failure must stop the cycle so the watermark is not advanced and
// the tombstone sweep does not run on incomplete data).
func (p *Persister) Handle(va VerifiedAdvisory) error {
	// TLP gate (defense in depth): both the feed TLP and the document's own
	// /document/distribution/tlp/label must be publishable. An absent or unknown
	// document label is treated as non-publishable (fail-closed).
	if !p.cfg.IsPublishable(va.TLP) {
		slog.Warn("dropping advisory: feed TLP not publishable", "url", va.URL, "feed_tlp", va.TLP)
		p.counts.SkippedTLP++
		return nil
	}
	docTLP, ok := documentTLP(va.Document)
	if !ok || !p.cfg.IsPublishable(csaf.TLPLabel(docTLP)) {
		slog.Warn("dropping advisory: document TLP not publishable",
			"url", va.URL, "document_tlp", docTLP)
		p.counts.SkippedTLP++
		return nil
	}

	trackingID, publisher, err := advisoryKey(va.Document)
	if err != nil {
		// A verified document missing its tracking id / publisher is malformed;
		// skip it rather than abort the whole run, but log loudly.
		slog.Warn("dropping advisory: cannot extract key", "url", va.URL, "error", err)
		p.counts.SkippedTLP++
		return nil
	}

	res, err := p.store.StoreDocument(p.ctx, trackingID, publisher, va.Document, va.Raw)
	if err != nil {
		return fmt.Errorf("storing advisory %q: %w", va.URL, err)
	}
	if res.Inserted {
		p.counts.Stored++
	} else {
		p.counts.Duplicate++
	}
	p.present[database.AdvisoryKey{TrackingID: trackingID, Publisher: publisher}] = struct{}{}
	return nil
}

// Counts returns the accumulated per-run counts.
func (p *Persister) Counts() PersistCounts { return p.counts }

// Present returns the deduplicated set of advisory keys seen this run.
func (p *Persister) Present() []database.AdvisoryKey {
	keys := make([]database.AdvisoryKey, 0, len(p.present))
	for key := range p.present {
		keys = append(keys, key)
	}
	return keys
}

// documentTLP reads /document/distribution/tlp/label from the parsed CSAF map.
// It returns the label and whether it was present as a string.
func documentTLP(doc map[string]any) (string, bool) {
	document, ok := doc["document"].(map[string]any)
	if !ok {
		return "", false
	}
	distribution, ok := document["distribution"].(map[string]any)
	if !ok {
		return "", false
	}
	tlp, ok := distribution["tlp"].(map[string]any)
	if !ok {
		return "", false
	}
	label, ok := tlp["label"].(string)
	if !ok {
		return "", false
	}
	return label, true
}

// advisoryKey extracts (tracking_id, publisher) — /document/tracking/id and
// /document/publisher/name — which key the advisories parent.
func advisoryKey(doc map[string]any) (trackingID, publisher string, err error) {
	document, ok := doc["document"].(map[string]any)
	if !ok {
		return "", "", fmt.Errorf("missing /document")
	}
	tracking, ok := document["tracking"].(map[string]any)
	if !ok {
		return "", "", fmt.Errorf("missing /document/tracking")
	}
	if id, ok := tracking["id"].(string); ok {
		trackingID = strings.TrimSpace(id)
	}
	pub, ok := document["publisher"].(map[string]any)
	if !ok {
		return "", "", fmt.Errorf("missing /document/publisher")
	}
	if name, ok := pub["name"].(string); ok {
		publisher = strings.TrimSpace(name)
	}
	if trackingID == "" {
		return "", "", fmt.Errorf("empty /document/tracking/id")
	}
	if publisher == "" {
		return "", "", fmt.Errorf("empty /document/publisher/name")
	}
	return trackingID, publisher, nil
}
