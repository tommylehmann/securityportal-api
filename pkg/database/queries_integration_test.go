// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 SecurityPortal contributors

package database

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests drive the real read-only query layer (ListAdvisories, GetDocument,
// LastIngest, Ping) against a live postgres:16-alpine seeded with CSAF-shaped
// JSONB fixtures, covering plan-tasks 9/10/11 at the SQL seam. They skip cleanly
// when docker is absent (via the shared dbtest fixture). The httptest handler
// tests with a fake Querier live in pkg/web/handlers_test.go; these exercise the
// SQL the fake stands in for.

// publishableSet is the canonical publishable-TLP allow-list the read API passes
// to every query (config.PublishableTLPSet for the default policy): WHITE +
// UNLABELED, with WHITE expanded to also match the TLP 2.0 CLEAR spelling.
var publishableSet = []string{"WHITE", "CLEAR", "UNLABELED"}

// facetDoc builds a CSAF-shaped document map with controllable facet fields. The
// generated columns in the documents table are derived from this JSONB, so the
// knobs here drive what ListAdvisories/GetDocument return. Functional options let
// a test pin individual facets (category, lang, publisher, CVSS scores) without a
// combinatorial set of constructors.
func facetDoc(trackingID, publisher, version, releaseDate, tlp string, revLen int, opts ...func(doc map[string]any)) map[string]any {
	history := make([]any, revLen)
	for i := range history {
		history[i] = map[string]any{"number": itoa(i + 1)}
	}
	doc := map[string]any{
		"document": map[string]any{
			"category": "csaf_security_advisory",
			"title":    "Advisory " + trackingID + " " + version,
			"lang":     "en",
			"publisher": map[string]any{
				"name":      publisher,
				"namespace": "https://example.test",
			},
			"distribution": map[string]any{
				"tlp": map[string]any{"label": tlp},
			},
			"tracking": map[string]any{
				"id":                   trackingID,
				"version":              version,
				"status":               "final",
				"current_release_date": releaseDate,
				"initial_release_date": "2026-01-01T00:00:00Z",
				"revision_history":     history,
			},
		},
	}
	for _, opt := range opts {
		opt(doc)
	}
	return doc
}

// withCVSS sets a single vulnerability score, driving the critical/cvss columns.
func withCVSS(v2, v3 float64) func(map[string]any) {
	return func(doc map[string]any) {
		doc["vulnerabilities"] = []any{
			map[string]any{
				"scores": []any{
					map[string]any{
						"cvss_v2": map[string]any{"baseScore": v2},
						"cvss_v3": map[string]any{"baseScore": v3},
					},
				},
			},
		}
	}
}

// withDocField overrides a top-level /document field (e.g. category, lang).
func withDocField(key string, value any) func(map[string]any) {
	return func(doc map[string]any) {
		doc["document"].(map[string]any)[key] = value
	}
}

// seed stores one revision and fails the test on error.
func seed(t *testing.T, db *DB, ctx context.Context, trackingID, publisher string, doc map[string]any) {
	t.Helper()
	if _, err := db.StoreDocument(ctx, trackingID, publisher, doc, rawJSON(t, doc)); err != nil {
		t.Fatalf("seeding %s: %v", trackingID, err)
	}
}

// trackingIDs returns the tracking ids of a list page in order.
func trackingIDs(list AdvisoryList) []string {
	ids := make([]string, len(list.Advisories))
	for i, a := range list.Advisories {
		ids[i] = a.TrackingID
	}
	return ids
}

func defaultSort() ListOptions {
	return ListOptions{Limit: 100, Offset: 0, Sort: SortCurrentReleaseDate, Descending: true}
}

// --- Scenario 1: latest-per-advisory with correct facet fields ---------------

func TestListAdvisoriesReturnsLatestRevisionWithFacets(t *testing.T) {
	db, _, ctx := migratedDB(t)

	const (
		trackingID = "PORTAL-LATEST-1"
		publisher  = "Acme Security Team"
	)
	rev1 := facetDoc(trackingID, publisher, "1.0.0", "2026-02-01T00:00:00Z", "WHITE", 1,
		withCVSS(4.0, 5.5), withDocField("lang", "en"))
	rev2 := facetDoc(trackingID, publisher, "2.0.0", "2026-03-15T08:30:00Z", "WHITE", 2,
		withCVSS(4.0, 9.8), withDocField("lang", "en"))
	seed(t, db, ctx, trackingID, publisher, rev1)
	seed(t, db, ctx, trackingID, publisher, rev2)

	list, err := db.ListAdvisories(ctx, defaultSort(), publishableSet)
	if err != nil {
		t.Fatalf("ListAdvisories: %v", err)
	}

	if len(list.Advisories) != 1 {
		t.Fatalf("expected exactly one row (latest per advisory), got %d: %v",
			len(list.Advisories), trackingIDs(list))
	}
	if list.Total != 1 {
		t.Errorf("total = %d, want 1", list.Total)
	}

	adv := list.Advisories[0]
	if adv.TrackingID != trackingID {
		t.Errorf("tracking_id = %q, want %q", adv.TrackingID, trackingID)
	}
	if adv.Version == nil || *adv.Version != "2.0.0" {
		t.Errorf("version = %v, want the latest revision 2.0.0", adv.Version)
	}
	if adv.TLP == nil || *adv.TLP != "WHITE" {
		t.Errorf("tlp = %v, want WHITE", adv.TLP)
	}
	if adv.Critical == nil || *adv.Critical != 9.8 {
		t.Errorf("critical = %v, want 9.8 (coalesce v3)", adv.Critical)
	}
	if adv.PublisherName == nil || *adv.PublisherName != publisher {
		t.Errorf("publisher_name = %v, want %q", adv.PublisherName, publisher)
	}
	if adv.Category == nil || *adv.Category != "csaf_security_advisory" {
		t.Errorf("category = %v, want csaf_security_advisory", adv.Category)
	}
	if adv.Lang == nil || *adv.Lang != "en" {
		t.Errorf("lang = %v, want en", adv.Lang)
	}
	if adv.Title == nil || !strings.Contains(*adv.Title, "2.0.0") {
		t.Errorf("title = %v, want the latest revision's title", adv.Title)
	}
	wantDate := time.Date(2026, 3, 15, 8, 30, 0, 0, time.UTC)
	if adv.CurrentReleaseDate == nil || !adv.CurrentReleaseDate.Equal(wantDate) {
		t.Errorf("current_release_date = %v, want %v", adv.CurrentReleaseDate, wantDate)
	}
}

// --- Scenario 2: pagination + total count ------------------------------------

func TestListAdvisoriesPaginatesWithStableTotal(t *testing.T) {
	db, _, ctx := migratedDB(t)

	const publisher = "Acme Security Team"
	const total = 7
	// Distinct release dates so the default desc order is deterministic.
	for i := 0; i < total; i++ {
		id := "PORTAL-PAGE-" + itoa(i)
		date := time.Date(2026, 1, 1+i, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
		seed(t, db, ctx, id, publisher, facetDoc(id, publisher, "1.0.0", date, "WHITE", 1))
	}

	page1, err := db.ListAdvisories(ctx, ListOptions{Limit: 3, Offset: 0, Sort: SortCurrentReleaseDate, Descending: true}, publishableSet)
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if page1.Total != total {
		t.Errorf("page1 total = %d, want %d (full filtered set, not the page)", page1.Total, total)
	}
	if len(page1.Advisories) != 3 {
		t.Errorf("page1 size = %d, want 3", len(page1.Advisories))
	}

	page3, err := db.ListAdvisories(ctx, ListOptions{Limit: 3, Offset: 6, Sort: SortCurrentReleaseDate, Descending: true}, publishableSet)
	if err != nil {
		t.Fatalf("page3: %v", err)
	}
	if page3.Total != total {
		t.Errorf("page3 total = %d, want %d", page3.Total, total)
	}
	if len(page3.Advisories) != 1 {
		t.Errorf("last page size = %d, want 1 (remainder)", len(page3.Advisories))
	}

	// Pages must not overlap and must cover the whole set.
	all := map[string]bool{}
	for off := 0; off < total; off += 3 {
		p, err := db.ListAdvisories(ctx, ListOptions{Limit: 3, Offset: off, Sort: SortCurrentReleaseDate, Descending: true}, publishableSet)
		if err != nil {
			t.Fatalf("offset %d: %v", off, err)
		}
		for _, id := range trackingIDs(p) {
			if all[id] {
				t.Errorf("advisory %s appeared on more than one page", id)
			}
			all[id] = true
		}
	}
	if len(all) != total {
		t.Errorf("paging covered %d distinct advisories, want %d", len(all), total)
	}
}

// --- Scenario 3: sort whitelist + hostile sort rejection ----------------------

func TestListAdvisoriesSortsByWhitelistedColumns(t *testing.T) {
	db, _, ctx := migratedDB(t)

	const publisher = "Acme Security Team"
	// low: old date, low score; high: new date, high score.
	low := facetDoc("PORTAL-SORT-LOW", publisher, "1.0.0", "2026-01-01T00:00:00Z", "WHITE", 1, withCVSS(2.0, 2.0))
	high := facetDoc("PORTAL-SORT-HIGH", publisher, "1.0.0", "2026-06-01T00:00:00Z", "WHITE", 1, withCVSS(9.0, 9.8))
	seed(t, db, ctx, "PORTAL-SORT-LOW", publisher, low)
	seed(t, db, ctx, "PORTAL-SORT-HIGH", publisher, high)

	// Default: current_release_date desc -> newest (high) first.
	byDate, err := db.ListAdvisories(ctx, defaultSort(), publishableSet)
	if err != nil {
		t.Fatalf("date sort: %v", err)
	}
	if got := trackingIDs(byDate); got[0] != "PORTAL-SORT-HIGH" {
		t.Errorf("default date-desc order = %v, want PORTAL-SORT-HIGH first", got)
	}

	// critical asc -> lowest severity first.
	byCritAsc, err := db.ListAdvisories(ctx,
		ListOptions{Limit: 100, Sort: SortCritical, Descending: false}, publishableSet)
	if err != nil {
		t.Fatalf("critical asc: %v", err)
	}
	if got := trackingIDs(byCritAsc); got[0] != "PORTAL-SORT-LOW" {
		t.Errorf("critical asc order = %v, want PORTAL-SORT-LOW first", got)
	}

	// critical desc -> highest severity first.
	byCritDesc, err := db.ListAdvisories(ctx,
		ListOptions{Limit: 100, Sort: SortCritical, Descending: true}, publishableSet)
	if err != nil {
		t.Fatalf("critical desc: %v", err)
	}
	if got := trackingIDs(byCritDesc); got[0] != "PORTAL-SORT-HIGH" {
		t.Errorf("critical desc order = %v, want PORTAL-SORT-HIGH first", got)
	}
}

// TestListAdvisoriesHostileSortNeverReachesSQL confirms that a SQL-injection
// payload smuggled into the sort selection can never reach the query: ListSort
// is a closed whitelist and orderClause only ever emits one of two fixed column
// names. A hostile ListSort value falls back to the default column rather than
// being interpolated, so the query still succeeds and returns rows (no injection,
// no error, no dropped table).
func TestListAdvisoriesHostileSortNeverReachesSQL(t *testing.T) {
	db, _, ctx := migratedDB(t)

	const publisher = "Acme Security Team"
	seed(t, db, ctx, "PORTAL-INJ-1", publisher,
		facetDoc("PORTAL-INJ-1", publisher, "1.0.0", "2026-02-01T00:00:00Z", "WHITE", 1))

	hostile := ListSort("id; DROP TABLE documents; --")
	opts := ListOptions{Limit: 100, Sort: hostile, Descending: true}

	// The clause must be one of the two whitelisted columns, never the payload.
	clause := opts.orderClause()
	if strings.Contains(clause, "DROP") || strings.Contains(strings.ToLower(clause), "drop table") {
		t.Fatalf("hostile sort reached the ORDER BY clause: %q", clause)
	}

	list, err := db.ListAdvisories(ctx, opts, publishableSet)
	if err != nil {
		t.Fatalf("ListAdvisories with hostile sort must succeed safely, got error: %v", err)
	}
	if len(list.Advisories) != 1 {
		t.Errorf("expected the seeded row to survive, got %d rows", len(list.Advisories))
	}

	// The documents table must still exist and be queryable.
	if _, err := db.ListAdvisories(ctx, defaultSort(), publishableSet); err != nil {
		t.Fatalf("documents table must be intact after hostile sort: %v", err)
	}
}

// --- Scenario 4: TLP filtering ------------------------------------------------

func TestListAdvisoriesFiltersToPublishableTLP(t *testing.T) {
	db, _, ctx := migratedDB(t)

	const publisher = "Acme Security Team"
	seedTLP := func(id, tlp string) {
		seed(t, db, ctx, id, publisher,
			facetDoc(id, publisher, "1.0.0", "2026-02-01T00:00:00Z", tlp, 1))
	}
	seedTLP("PORTAL-WHITE", "WHITE")
	seedTLP("PORTAL-UNLABELED", "UNLABELED")
	seedTLP("PORTAL-GREEN", "GREEN")
	seedTLP("PORTAL-AMBER", "AMBER")
	seedTLP("PORTAL-RED", "RED")
	seedTLP("PORTAL-CLEAR", "CLEAR") // TLP 2.0 alias for WHITE

	list, err := db.ListAdvisories(ctx, defaultSort(), publishableSet)
	if err != nil {
		t.Fatalf("ListAdvisories: %v", err)
	}

	got := map[string]bool{}
	for _, id := range trackingIDs(list) {
		got[id] = true
	}
	wantPresent := []string{"PORTAL-WHITE", "PORTAL-UNLABELED", "PORTAL-CLEAR"}
	wantAbsent := []string{"PORTAL-GREEN", "PORTAL-AMBER", "PORTAL-RED"}
	for _, id := range wantPresent {
		if !got[id] {
			t.Errorf("%s should appear in the publishable list", id)
		}
	}
	for _, id := range wantAbsent {
		if got[id] {
			t.Errorf("%s (restricted TLP) must NEVER appear in the public list", id)
		}
	}
	if list.Total != int64(len(wantPresent)) {
		t.Errorf("total = %d, want %d publishable advisories", list.Total, len(wantPresent))
	}
}

// --- Scenario 5: withdrawn exclusion vs permalink stability -------------------

func TestWithdrawnAdvisoryHiddenFromListButDocumentStillServed(t *testing.T) {
	db, pool, ctx := migratedDB(t)

	const (
		trackingID = "PORTAL-WD-1"
		publisher  = "Acme Security Team"
	)
	doc := facetDoc(trackingID, publisher, "1.0.0", "2026-02-01T00:00:00Z", "WHITE", 1)
	seed(t, db, ctx, trackingID, publisher, doc)

	docID := documentIDFor(t, ctx, pool, trackingID, publisher)

	// Withdraw it (deletion sweep tombstone).
	if _, err := db.TombstoneAbsent(ctx, []AdvisoryKey{{TrackingID: "OTHER", Publisher: publisher}}); err != nil {
		t.Fatalf("TombstoneAbsent: %v", err)
	}
	assertWithdrawn(t, ctx, pool, trackingID, publisher, true)

	// Absent from the list...
	list, err := db.ListAdvisories(ctx, defaultSort(), publishableSet)
	if err != nil {
		t.Fatalf("ListAdvisories: %v", err)
	}
	for _, id := range trackingIDs(list) {
		if id == trackingID {
			t.Errorf("withdrawn advisory %s must not appear in the list", trackingID)
		}
	}

	// ...but its document is STILL resolvable by id (permalink stability).
	raw, err := db.GetDocument(ctx, docID, publishableSet)
	if err != nil {
		t.Fatalf("GetDocument on withdrawn advisory's document must still serve it: %v", err)
	}
	if len(raw) == 0 {
		t.Error("expected non-empty document JSON for a withdrawn advisory's permalink")
	}
}

// --- Scenario 6: single document fetch ---------------------------------------

func TestGetDocumentReturnsStoredJSONAndEnforcesTLP(t *testing.T) {
	db, pool, ctx := migratedDB(t)

	const publisher = "Acme Security Team"
	white := facetDoc("PORTAL-DOC-WHITE", publisher, "1.0.0", "2026-02-01T00:00:00Z", "WHITE", 1)
	amber := facetDoc("PORTAL-DOC-AMBER", publisher, "1.0.0", "2026-02-01T00:00:00Z", "AMBER", 1)
	seed(t, db, ctx, "PORTAL-DOC-WHITE", publisher, white)
	seed(t, db, ctx, "PORTAL-DOC-AMBER", publisher, amber)

	whiteID := documentIDFor(t, ctx, pool, "PORTAL-DOC-WHITE", publisher)
	amberID := documentIDFor(t, ctx, pool, "PORTAL-DOC-AMBER", publisher)

	// Valid publishable id -> the stored CSAF JSON, semantically equal.
	raw, err := db.GetDocument(ctx, whiteID, publishableSet)
	if err != nil {
		t.Fatalf("GetDocument(white): %v", err)
	}
	assertSameCSAF(t, raw, white)

	// Missing id -> not found.
	if _, err := db.GetDocument(ctx, 999999, publishableSet); err != ErrDocumentNotFound {
		t.Errorf("GetDocument(missing) error = %v, want ErrDocumentNotFound", err)
	}

	// Non-publishable (AMBER) id -> not found (never confirm a restricted doc exists).
	if _, err := db.GetDocument(ctx, amberID, publishableSet); err != ErrDocumentNotFound {
		t.Errorf("GetDocument(AMBER) error = %v, want ErrDocumentNotFound (restricted)", err)
	}
}

// --- Scenario 7: health (LastIngest / Ping) -----------------------------------

func TestPingReportsReachableDatabase(t *testing.T) {
	db, _, ctx := migratedDB(t)
	if err := db.Ping(ctx); err != nil {
		t.Errorf("Ping on a live database should succeed, got %v", err)
	}
}

func TestLastIngestReflectsIngestState(t *testing.T) {
	db, _, ctx := migratedDB(t)

	// Freshly migrated, no poll yet -> no last-ingest time.
	if _, ok, err := db.LastIngest(ctx); err != nil || ok {
		t.Fatalf("before any ingest: ok=%v err=%v, want ok=false", ok, err)
	}

	// A successful poll writes an ingest_state row whose `updated` column is set
	// to CURRENT_TIMESTAMP (the write time), which LastIngest surfaces as the
	// "last successful ingest" signal. The watermark value is the per-feed
	// content cutoff and is deliberately distinct from `updated`.
	before := time.Now().Add(-time.Minute)
	watermark := time.Date(2026, 6, 5, 10, 16, 6, 0, time.UTC)
	if err := db.SetWatermark(ctx, "https://provider.example.test/white/feed.json", watermark); err != nil {
		t.Fatalf("SetWatermark: %v", err)
	}
	last, ok, err := db.LastIngest(ctx)
	if err != nil {
		t.Fatalf("LastIngest: %v", err)
	}
	if !ok {
		t.Fatal("expected a last-ingest time after a recorded ingest-state row")
	}
	// updated tracks the write time, not the watermark.
	if last.Before(before) {
		t.Errorf("last ingest = %v, want a recent write time (>= %v)", last.UTC(), before.UTC())
	}

	// LastIngest reports the newest `updated` across feed rows. A second feed
	// written later has a later `updated`, so the reported time must not regress.
	if err := db.SetWatermark(ctx, "https://provider.example.test/white/feed2.json", watermark.Add(-time.Hour)); err != nil {
		t.Fatalf("SetWatermark feed2: %v", err)
	}
	last2, _, err := db.LastIngest(ctx)
	if err != nil {
		t.Fatalf("LastIngest after second feed: %v", err)
	}
	if last2.Before(last) {
		t.Errorf("last ingest regressed: %v < %v", last2.UTC(), last.UTC())
	}
}

// documentIDFor returns the document id of the latest revision for an advisory.
func documentIDFor(t *testing.T, ctx context.Context, pool *pgxpool.Pool, trackingID, publisher string) int64 {
	t.Helper()
	var id int64
	err := pool.QueryRow(ctx, `
		SELECT d.id
		FROM documents d JOIN advisories a ON a.id = d.advisories_id
		WHERE a.tracking_id = $1 AND a.publisher = $2 AND d.latest`,
		trackingID, publisher).Scan(&id)
	if err != nil {
		t.Fatalf("finding document id for %s: %v", trackingID, err)
	}
	return id
}

// assertSameCSAF checks that raw JSON bytes are semantically equal to the
// expected document map (the jsonb round-trip may reorder keys / reformat
// whitespace, so byte equality is not expected — semantic equality is).
func assertSameCSAF(t *testing.T, raw []byte, want map[string]any) {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("stored document is not valid JSON: %v", err)
	}
	wantTracking := want["document"].(map[string]any)["tracking"].(map[string]any)["id"]
	gotDoc, ok := got["document"].(map[string]any)
	if !ok {
		t.Fatalf("stored document has no /document object: %v", got)
	}
	gotTracking := gotDoc["tracking"].(map[string]any)["id"]
	if gotTracking != wantTracking {
		t.Errorf("stored tracking id = %v, want %v", gotTracking, wantTracking)
	}
}
