// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package database

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests drive the real StoreDocument / TombstoneAbsent / watermark
// persistence layer against a live postgres:16-alpine (docker-in-docker),
// covering plan-task-7/8 behaviour at the database seam. They skip cleanly when
// docker is absent (via the shared dbtest fixture).

// migratedDB starts a container, applies the migrations, and returns a *DB
// wired to the pool plus the bounded context.
func migratedDB(t *testing.T) (*DB, *pgxpool.Pool, context.Context) {
	t.Helper()
	pool, ctx := startPostgres(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return &DB{pool: pool}, pool, ctx
}

// csafDoc builds a CSAF-shaped document map with a controllable tracking id,
// version, release date and TLP label, suitable for StoreDocument (which feeds
// the generated facet columns from this JSONB).
func csafDoc(trackingID, publisher, version, releaseDate, tlp string, revLen int) map[string]any {
	history := make([]any, revLen)
	for i := range history {
		history[i] = map[string]any{"number": itoa(i + 1)}
	}
	return map[string]any{
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
}

// itoa is a tiny dependency-free int-to-string for revision numbers.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func rawJSON(t *testing.T, doc map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshaling fixture: %v", err)
	}
	return b
}

func countDocuments(t *testing.T, ctx context.Context, pool *pgxpool.Pool, trackingID, publisher string) int {
	t.Helper()
	var n int
	err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM documents d JOIN advisories a ON a.id = d.advisories_id
		WHERE a.tracking_id = $1 AND a.publisher = $2`, trackingID, publisher).Scan(&n)
	if err != nil {
		t.Fatalf("counting documents: %v", err)
	}
	return n
}

func countAdvisories(t *testing.T, ctx context.Context, pool *pgxpool.Pool, trackingID, publisher string) int {
	t.Helper()
	var n int
	err := pool.QueryRow(ctx,
		`SELECT count(*) FROM advisories WHERE tracking_id = $1 AND publisher = $2`,
		trackingID, publisher).Scan(&n)
	if err != nil {
		t.Fatalf("counting advisories: %v", err)
	}
	return n
}

// latestVersion returns the version string of the document currently flagged as
// latest for the advisory, and the latest_document_id pointer.
func latestVersion(t *testing.T, ctx context.Context, pool *pgxpool.Pool, trackingID, publisher string) (string, int) {
	t.Helper()
	var (
		version  string
		latestID int
		pointer  int
	)
	err := pool.QueryRow(ctx, `
		SELECT d.version, d.id, a.latest_document_id
		FROM documents d JOIN advisories a ON a.id = d.advisories_id
		WHERE a.tracking_id = $1 AND a.publisher = $2 AND d.latest`,
		trackingID, publisher).Scan(&version, &latestID, &pointer)
	if err != nil {
		t.Fatalf("reading latest revision: %v", err)
	}
	if pointer != latestID {
		t.Errorf("advisories.latest_document_id = %d, want %d (the latest document)", pointer, latestID)
	}
	return version, latestID
}

func TestStoreDocumentIsIdempotent(t *testing.T) {
	db, pool, ctx := migratedDB(t)

	const (
		trackingID = "PORTAL-IDEMP-1"
		publisher  = "SecurityPortal Test Publisher"
	)
	doc := csafDoc(trackingID, publisher, "1.0.0", "2026-02-01T00:00:00Z", "WHITE", 1)

	first, err := db.StoreDocument(ctx, trackingID, publisher, doc, rawJSON(t, doc))
	if err != nil {
		t.Fatalf("first StoreDocument: %v", err)
	}
	if !first.Inserted {
		t.Fatal("first StoreDocument should report Inserted=true")
	}

	// Persisting the identical revision again is a no-op.
	second, err := db.StoreDocument(ctx, trackingID, publisher, doc, rawJSON(t, doc))
	if err != nil {
		t.Fatalf("second StoreDocument: %v", err)
	}
	if second.Inserted {
		t.Error("re-storing an identical revision should report Inserted=false")
	}

	if n := countDocuments(t, ctx, pool, trackingID, publisher); n != 1 {
		t.Errorf("expected exactly one document row after storing twice, got %d", n)
	}
	if n := countAdvisories(t, ctx, pool, trackingID, publisher); n != 1 {
		t.Errorf("expected exactly one advisory row, got %d", n)
	}
}

func TestStoreDocumentNewerRevisionSupersedes(t *testing.T) {
	db, pool, ctx := migratedDB(t)

	const (
		trackingID = "PORTAL-SUP-1"
		publisher  = "SecurityPortal Test Publisher"
	)

	rev1 := csafDoc(trackingID, publisher, "1.0.0", "2026-02-01T00:00:00Z", "WHITE", 1)
	if _, err := db.StoreDocument(ctx, trackingID, publisher, rev1, rawJSON(t, rev1)); err != nil {
		t.Fatalf("storing rev1: %v", err)
	}
	if v, _ := latestVersion(t, ctx, pool, trackingID, publisher); v != "1.0.0" {
		t.Fatalf("after rev1, latest = %q, want 1.0.0", v)
	}

	// rev2 has a higher version and a later release date -> it must lead.
	rev2 := csafDoc(trackingID, publisher, "2.0.0", "2026-03-01T00:00:00Z", "WHITE", 2)
	if _, err := db.StoreDocument(ctx, trackingID, publisher, rev2, rawJSON(t, rev2)); err != nil {
		t.Fatalf("storing rev2: %v", err)
	}

	if v, _ := latestVersion(t, ctx, pool, trackingID, publisher); v != "2.0.0" {
		t.Errorf("after rev2, latest = %q, want 2.0.0", v)
	}
	if n := countDocuments(t, ctx, pool, trackingID, publisher); n != 2 {
		t.Errorf("expected two document rows, got %d", n)
	}
}

func TestStoreDocumentLateOlderRevisionDoesNotRegress(t *testing.T) {
	db, pool, ctx := migratedDB(t)

	const (
		trackingID = "PORTAL-LATE-1"
		publisher  = "SecurityPortal Test Publisher"
	)

	rev2 := csafDoc(trackingID, publisher, "2.0.0", "2026-03-01T00:00:00Z", "WHITE", 2)
	if _, err := db.StoreDocument(ctx, trackingID, publisher, rev2, rawJSON(t, rev2)); err != nil {
		t.Fatalf("storing rev2: %v", err)
	}

	// A late-arriving OLDER revision (rev0) must not become the head.
	rev0 := csafDoc(trackingID, publisher, "0.9.0", "2026-01-15T00:00:00Z", "WHITE", 1)
	if _, err := db.StoreDocument(ctx, trackingID, publisher, rev0, rawJSON(t, rev0)); err != nil {
		t.Fatalf("storing late older rev0: %v", err)
	}

	if v, _ := latestVersion(t, ctx, pool, trackingID, publisher); v != "2.0.0" {
		t.Errorf("after late older rev0, latest = %q, want 2.0.0 (no regression)", v)
	}
}

func TestTombstoneAbsentMarksVanishedAndIsIdempotent(t *testing.T) {
	db, pool, ctx := migratedDB(t)

	const publisher = "SecurityPortal Test Publisher"
	kept := csafDoc("PORTAL-KEPT", publisher, "1.0.0", "2026-02-01T00:00:00Z", "WHITE", 1)
	gone := csafDoc("PORTAL-GONE", publisher, "1.0.0", "2026-02-01T00:00:00Z", "WHITE", 1)
	if _, err := db.StoreDocument(ctx, "PORTAL-KEPT", publisher, kept, rawJSON(t, kept)); err != nil {
		t.Fatalf("storing kept: %v", err)
	}
	if _, err := db.StoreDocument(ctx, "PORTAL-GONE", publisher, gone, rawJSON(t, gone)); err != nil {
		t.Fatalf("storing gone: %v", err)
	}

	// Sweep with only PORTAL-KEPT present -> PORTAL-GONE is tombstoned, not deleted.
	present := []AdvisoryKey{{TrackingID: "PORTAL-KEPT", Publisher: publisher}}
	n, err := db.TombstoneAbsent(ctx, present)
	if err != nil {
		t.Fatalf("TombstoneAbsent: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 advisory tombstoned, got %d", n)
	}

	assertWithdrawn(t, ctx, pool, "PORTAL-GONE", publisher, true)
	assertWithdrawn(t, ctx, pool, "PORTAL-KEPT", publisher, false)
	// The vanished advisory must NOT be hard-deleted (permalink stability, OQ-3).
	if c := countAdvisories(t, ctx, pool, "PORTAL-GONE", publisher); c != 1 {
		t.Errorf("withdrawn advisory must be retained, got %d rows", c)
	}

	// A second identical sweep withdraws nobody new (idempotent).
	n, err = db.TombstoneAbsent(ctx, present)
	if err != nil {
		t.Fatalf("second TombstoneAbsent: %v", err)
	}
	if n != 0 {
		t.Errorf("second sweep should tombstone nobody new, got %d", n)
	}

	// The advisory reappearing clears the marker on the next StoreDocument upsert.
	if _, err := db.StoreDocument(ctx, "PORTAL-GONE", publisher, gone, rawJSON(t, gone)); err != nil {
		t.Fatalf("re-storing reappeared advisory: %v", err)
	}
	assertWithdrawn(t, ctx, pool, "PORTAL-GONE", publisher, false)
}

func TestTombstoneAbsentWithEmptyPresentSetWithdrawsAll(t *testing.T) {
	db, pool, ctx := migratedDB(t)

	const publisher = "SecurityPortal Test Publisher"
	doc := csafDoc("PORTAL-ALONE", publisher, "1.0.0", "2026-02-01T00:00:00Z", "WHITE", 1)
	if _, err := db.StoreDocument(ctx, "PORTAL-ALONE", publisher, doc, rawJSON(t, doc)); err != nil {
		t.Fatalf("storing advisory: %v", err)
	}

	// A genuinely empty feed (every advisory gone) tombstones everything — this
	// is correct ONLY because the caller (RunOnce) guards on a complete poll;
	// the guard itself is covered in the ingest package.
	n, err := db.TombstoneAbsent(ctx, nil)
	if err != nil {
		t.Fatalf("TombstoneAbsent with empty present set: %v", err)
	}
	if n != 1 {
		t.Errorf("expected the sole advisory tombstoned, got %d", n)
	}
	assertWithdrawn(t, ctx, pool, "PORTAL-ALONE", publisher, true)
}

func TestWatermarkRoundTrips(t *testing.T) {
	db, _, ctx := migratedDB(t)

	const feed = "https://provider.example.test/white/feed.json"

	if _, ok, err := db.Watermark(ctx, feed); err != nil || ok {
		t.Fatalf("expected no watermark before first set (ok=%v, err=%v)", ok, err)
	}

	want := time.Date(2026, 3, 15, 12, 30, 0, 0, time.UTC)
	if err := db.SetWatermark(ctx, feed, want); err != nil {
		t.Fatalf("SetWatermark: %v", err)
	}

	got, ok, err := db.Watermark(ctx, feed)
	if err != nil {
		t.Fatalf("Watermark: %v", err)
	}
	if !ok {
		t.Fatal("expected a watermark after SetWatermark")
	}
	if !got.Equal(want) {
		t.Errorf("watermark = %v, want %v", got.UTC(), want)
	}

	// Updating overwrites in place (upsert on conflict).
	later := want.Add(24 * time.Hour)
	if err := db.SetWatermark(ctx, feed, later); err != nil {
		t.Fatalf("second SetWatermark: %v", err)
	}
	got, _, err = db.Watermark(ctx, feed)
	if err != nil {
		t.Fatalf("Watermark after update: %v", err)
	}
	if !got.Equal(later) {
		t.Errorf("watermark after update = %v, want %v", got.UTC(), later)
	}
}

func assertWithdrawn(t *testing.T, ctx context.Context, pool *pgxpool.Pool, trackingID, publisher string, want bool) {
	t.Helper()
	var (
		withdrawn   bool
		withdrawnAt *time.Time
	)
	err := pool.QueryRow(ctx,
		`SELECT withdrawn, withdrawn_at FROM advisories WHERE tracking_id = $1 AND publisher = $2`,
		trackingID, publisher).Scan(&withdrawn, &withdrawnAt)
	if err != nil {
		t.Fatalf("reading withdrawn state for %s: %v", trackingID, err)
	}
	if withdrawn != want {
		t.Errorf("%s withdrawn = %v, want %v", trackingID, withdrawn, want)
	}
	if want && withdrawnAt == nil {
		t.Errorf("%s is withdrawn but withdrawn_at is NULL", trackingID)
	}
	if !want && withdrawnAt != nil {
		t.Errorf("%s is not withdrawn but withdrawn_at is set to %v", trackingID, withdrawnAt)
	}
}
