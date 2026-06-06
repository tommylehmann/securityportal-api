// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package ingest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/securityportal/securityportal-api/internal/dbtest"
	"github.com/securityportal/securityportal-api/pkg/config"
	"github.com/securityportal/securityportal-api/pkg/database"
)

// These tests drive the real Persister -> *database.DB persistence path and the
// tombstone sweep against a live postgres:16-alpine (docker-in-docker), covering
// the plan-task-7/8 behaviour at the ingest seam: the two-layer TLP gate, the
// deletion tombstone over a full cycle, and the critical partial-poll data-loss
// guard. They skip cleanly when docker is absent.

// migratedStore starts a container, applies the migrations through the real DB
// wrapper, and returns the *database.DB store plus an inspection pool.
func migratedStore(t *testing.T) (*database.DB, *pgxpool.Pool, context.Context) {
	t.Helper()
	pool, dsn, ctx := dbtest.StartPostgres(t)
	db, err := database.NewDB(ctx, dsn)
	if err != nil {
		t.Fatalf("opening DB: %v", err)
	}
	t.Cleanup(db.Close)
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	return db, pool, ctx
}

// publishConfig returns a config whose publishable set is the resolved policy
// (WHITE + UNLABELED, OQ-1). ProviderURL is set so ValidateForIngest passes;
// individual tests override it when they need a (failing) real fetch.
func publishConfig() *config.Config {
	return &config.Config{
		ProviderURL:    "https://provider.example.test",
		PublishableTLP: []csaf.TLPLabel{csaf.TLPLabelWhite, csaf.TLPLabelUnlabeled},
		PollInterval:   time.Minute,
	}
}

// verifiedAdvisory builds a VerifiedAdvisory carrying a feed TLP and a document
// whose own /document/distribution/tlp/label is docTLP, for driving the gate.
func verifiedAdvisory(trackingID, publisher, feedTLP, docTLP string) VerifiedAdvisory {
	doc := map[string]any{
		"document": map[string]any{
			"category": "csaf_security_advisory",
			"title":    "Advisory " + trackingID,
			"lang":     "en",
			"publisher": map[string]any{
				"name":      publisher,
				"namespace": "https://example.test",
			},
			"distribution": map[string]any{
				"tlp": map[string]any{"label": docTLP},
			},
			"tracking": map[string]any{
				"id":                   trackingID,
				"version":              "1.0.0",
				"status":               "final",
				"current_release_date": "2026-02-01T00:00:00Z",
				"initial_release_date": "2026-01-01T00:00:00Z",
				"revision_history":     []any{map[string]any{"number": "1"}},
			},
		},
	}
	return VerifiedAdvisory{
		TLP:      csaf.TLPLabel(feedTLP),
		URL:      "https://provider.example.test/" + trackingID + ".json",
		Document: doc,
	}
}

// verifiedAdvisoryNoDocTLP builds a verified advisory whose document carries no
// /document/distribution/tlp/label at all (the fail-closed gate must drop it).
func verifiedAdvisoryNoDocTLP(trackingID, publisher, feedTLP string) VerifiedAdvisory {
	va := verifiedAdvisory(trackingID, publisher, feedTLP, "WHITE")
	doc := va.Document["document"].(map[string]any)
	delete(doc, "distribution")
	return va
}

func advisoryStored(t *testing.T, ctx context.Context, pool *pgxpool.Pool, trackingID, publisher string) bool {
	t.Helper()
	var n int
	err := pool.QueryRow(ctx,
		`SELECT count(*) FROM advisories WHERE tracking_id = $1 AND publisher = $2`,
		trackingID, publisher).Scan(&n)
	if err != nil {
		t.Fatalf("counting advisory %s: %v", trackingID, err)
	}
	return n > 0
}

func withdrawnState(t *testing.T, ctx context.Context, pool *pgxpool.Pool, trackingID, publisher string) bool {
	t.Helper()
	var withdrawn bool
	err := pool.QueryRow(ctx,
		`SELECT withdrawn FROM advisories WHERE tracking_id = $1 AND publisher = $2`,
		trackingID, publisher).Scan(&withdrawn)
	if err != nil {
		t.Fatalf("reading withdrawn for %s: %v", trackingID, err)
	}
	return withdrawn
}

// TestPersisterTLPGate exercises the two-layer publish gate end to end through
// the real store: only an advisory whose feed TLP AND document TLP are both
// publishable is persisted; non-publishable feed, non-publishable document, and
// missing document label are all dropped (fail-closed).
func TestPersisterTLPGate(t *testing.T) {
	db, pool, ctx := migratedStore(t)
	const publisher = "SecurityPortal Test Publisher"

	persister := NewPersister(ctx, publishConfig(), db)

	cases := []struct {
		name       string
		advisory   VerifiedAdvisory
		wantStored bool
	}{
		{
			name:       "white feed and white document is stored",
			advisory:   verifiedAdvisory("PORTAL-TLP-WHITE", publisher, "WHITE", "WHITE"),
			wantStored: true,
		},
		{
			name:       "unlabeled feed and unlabeled document is stored",
			advisory:   verifiedAdvisory("PORTAL-TLP-UNLABELED", publisher, "UNLABELED", "UNLABELED"),
			wantStored: true,
		},
		{
			name:       "amber document is not stored even on a white feed",
			advisory:   verifiedAdvisory("PORTAL-TLP-AMBERDOC", publisher, "WHITE", "AMBER"),
			wantStored: false,
		},
		{
			name:       "amber feed is not stored even with a white document",
			advisory:   verifiedAdvisory("PORTAL-TLP-AMBERFEED", publisher, "AMBER", "WHITE"),
			wantStored: false,
		},
		{
			name:       "green is excluded by policy (OQ-1)",
			advisory:   verifiedAdvisory("PORTAL-TLP-GREEN", publisher, "GREEN", "GREEN"),
			wantStored: false,
		},
		{
			name:       "document missing a TLP label is dropped fail-closed",
			advisory:   verifiedAdvisoryNoDocTLP("PORTAL-TLP-NOLABEL", publisher, "WHITE"),
			wantStored: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := persister.Handle(tc.advisory); err != nil {
				t.Fatalf("Handle returned an error (gate must drop, not error): %v", err)
			}
			trackingID := tc.advisory.Document["document"].(map[string]any)["tracking"].(map[string]any)["id"].(string)
			got := advisoryStored(t, ctx, pool, trackingID, publisher)
			if got != tc.wantStored {
				t.Errorf("advisory stored = %v, want %v", got, tc.wantStored)
			}
		})
	}

	// Exactly the two publishable advisories made it into the store.
	var total int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM advisories`).Scan(&total); err != nil {
		t.Fatalf("counting advisories: %v", err)
	}
	if total != 2 {
		t.Errorf("expected exactly 2 publishable advisories stored, got %d", total)
	}
	if c := persister.Counts(); c.Stored != 2 || c.SkippedTLP != 4 {
		t.Errorf("counts = %+v, want Stored=2 SkippedTLP=4", c)
	}
}

// TestTombstoneSweepOverFullCycle models the deletion handling across cycles
// exactly as RunOnce composes it (persist present advisories, then
// TombstoneAbsent over the present-set): an advisory that is present, then
// absent in a later full cycle, gets withdrawn (not deleted); when it reappears
// it is un-tombstoned.
func TestTombstoneSweepOverFullCycle(t *testing.T) {
	db, pool, ctx := migratedStore(t)
	const publisher = "SecurityPortal Test Publisher"
	cfg := publishConfig()

	// Cycle 1: both X and Y are present in the feed.
	c1 := NewPersister(ctx, cfg, db)
	if err := c1.Handle(verifiedAdvisory("PORTAL-X", publisher, "WHITE", "WHITE")); err != nil {
		t.Fatalf("cycle1 handle X: %v", err)
	}
	if err := c1.Handle(verifiedAdvisory("PORTAL-Y", publisher, "WHITE", "WHITE")); err != nil {
		t.Fatalf("cycle1 handle Y: %v", err)
	}
	if _, err := db.TombstoneAbsent(ctx, c1.Present()); err != nil {
		t.Fatalf("cycle1 sweep: %v", err)
	}
	if withdrawnState(t, ctx, pool, "PORTAL-X", publisher) {
		t.Error("X must not be withdrawn while present")
	}

	// Cycle 2: X has vanished from the feed; only Y is present.
	c2 := NewPersister(ctx, cfg, db)
	if err := c2.Handle(verifiedAdvisory("PORTAL-Y", publisher, "WHITE", "WHITE")); err != nil {
		t.Fatalf("cycle2 handle Y: %v", err)
	}
	n, err := db.TombstoneAbsent(ctx, c2.Present())
	if err != nil {
		t.Fatalf("cycle2 sweep: %v", err)
	}
	if n != 1 {
		t.Errorf("cycle2 should tombstone exactly X, got %d", n)
	}
	if !withdrawnState(t, ctx, pool, "PORTAL-X", publisher) {
		t.Error("X must be withdrawn after vanishing from the feed")
	}
	if withdrawnState(t, ctx, pool, "PORTAL-Y", publisher) {
		t.Error("Y must remain published")
	}
	// Tombstone, not hard delete: X's row and its document survive.
	if !advisoryStored(t, ctx, pool, "PORTAL-X", publisher) {
		t.Error("withdrawn X must be retained, not deleted (permalink stability)")
	}

	// Cycle 3: X reappears -> the marker is cleared.
	c3 := NewPersister(ctx, cfg, db)
	if err := c3.Handle(verifiedAdvisory("PORTAL-X", publisher, "WHITE", "WHITE")); err != nil {
		t.Fatalf("cycle3 handle X: %v", err)
	}
	if err := c3.Handle(verifiedAdvisory("PORTAL-Y", publisher, "WHITE", "WHITE")); err != nil {
		t.Fatalf("cycle3 handle Y: %v", err)
	}
	if _, err := db.TombstoneAbsent(ctx, c3.Present()); err != nil {
		t.Fatalf("cycle3 sweep: %v", err)
	}
	if withdrawnState(t, ctx, pool, "PORTAL-X", publisher) {
		t.Error("X must be un-tombstoned after reappearing in the feed")
	}
}

// TestRunOncePartialPollDoesNotTombstone is the critical data-loss guard: a
// failed/partial poll (here, the provider's provider-metadata.json is
// unreachable) must NOT tombstone existing advisories. RunOnce must return an
// error before the sweep, leaving every previously stored advisory published.
func TestRunOncePartialPollDoesNotTombstone(t *testing.T) {
	db, pool, ctx := migratedStore(t)
	const publisher = "SecurityPortal Test Publisher"

	// Pre-seed an advisory as if a prior successful cycle had stored it.
	seed := NewPersister(ctx, publishConfig(), db)
	if err := seed.Handle(verifiedAdvisory("PORTAL-SURVIVOR", publisher, "WHITE", "WHITE")); err != nil {
		t.Fatalf("seeding advisory: %v", err)
	}
	if withdrawnState(t, ctx, pool, "PORTAL-SURVIVOR", publisher) {
		t.Fatal("precondition: seeded advisory must be published")
	}

	// A provider whose metadata endpoint fails: the enumeration cannot complete,
	// so the present-set is empty/partial. This is the data-loss trap.
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "provider temporarily unavailable", http.StatusInternalServerError)
	}))
	t.Cleanup(provider.Close)

	cfg := publishConfig()
	cfg.ProviderURL = provider.URL

	_, err := RunOnce(ctx, cfg, db)
	if err == nil {
		t.Fatal("RunOnce must fail when the provider is unreachable (partial poll)")
	}

	// The guard's whole point: nothing was tombstoned by the failed cycle.
	if withdrawnState(t, ctx, pool, "PORTAL-SURVIVOR", publisher) {
		t.Error("BLOCKER: a failed/partial poll tombstoned an existing advisory")
	}
	if !advisoryStored(t, ctx, pool, "PORTAL-SURVIVOR", publisher) {
		t.Error("the pre-existing advisory must survive a failed poll")
	}
}

// TestRunOnceZeroAdvisoriesFromProviderErrorDoesNotTombstone covers the related
// trap where the provider responds but yields zero advisories because of an
// error condition. If the cycle errored, no sweep runs and existing data stays.
func TestRunOnceZeroAdvisoriesFromProviderErrorDoesNotTombstone(t *testing.T) {
	db, pool, ctx := migratedStore(t)
	const publisher = "SecurityPortal Test Publisher"

	seed := NewPersister(ctx, publishConfig(), db)
	if err := seed.Handle(verifiedAdvisory("PORTAL-KEEPME", publisher, "WHITE", "WHITE")); err != nil {
		t.Fatalf("seeding advisory: %v", err)
	}

	// Provider returns a malformed (non-JSON) provider-metadata.json: the loader
	// fails, the cycle errors, the sweep is skipped.
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("this is not valid json"))
	}))
	t.Cleanup(provider.Close)

	cfg := publishConfig()
	cfg.ProviderURL = provider.URL

	if _, err := RunOnce(ctx, cfg, db); err == nil {
		t.Fatal("RunOnce must fail when the provider metadata is unusable")
	}
	if withdrawnState(t, ctx, pool, "PORTAL-KEEPME", publisher) {
		t.Error("BLOCKER: a provider error that yields zero advisories tombstoned existing data")
	}
}
