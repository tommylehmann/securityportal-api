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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/securityportal/securityportal-api/internal/dbtest"
)

// These tests apply the embedded migrations against a real postgres:16-alpine
// container started via docker (docker-in-docker). They are skipped cleanly
// when docker is unavailable so that `go test ./...` still passes in
// environments without a docker daemon. The throwaway-container helper lives in
// internal/dbtest so the database and ingest integration suites share one copy.

// startPostgres starts a throwaway postgres container and returns a ready pool
// plus a bounded context. It is a thin wrapper over the shared dbtest fixture
// that drops the DSN the database-package tests do not need.
func startPostgres(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	pool, _, ctx := dbtest.StartPostgres(t)
	return pool, ctx
}

// revision builds a CSAF-shaped document used as a fixture for the generated
// columns and the latest-tracking triggers.
func revision(trackingID, version, status, releaseDate string, revLen int, opts ...func(map[string]any)) string {
	history := make([]any, revLen)
	for i := range history {
		history[i] = map[string]any{"number": fmt.Sprintf("%d", i+1)}
	}
	doc := map[string]any{
		"document": map[string]any{
			"category": "csaf_security_advisory",
			"title":    "Test advisory " + version,
			"lang":     "en",
			"publisher": map[string]any{
				"name":      "SecurityPortal Test Publisher",
				"namespace": "https://example.test",
			},
			"distribution": map[string]any{
				"tlp": map[string]any{"label": "WHITE"},
			},
			"tracking": map[string]any{
				"id":                   trackingID,
				"version":              version,
				"status":               status,
				"current_release_date": releaseDate,
				"initial_release_date": "2026-01-01T00:00:00Z",
				"revision_history":     history,
			},
		},
		"vulnerabilities": []any{
			map[string]any{
				"scores": []any{
					map[string]any{
						"cvss_v2": map[string]any{"baseScore": 5.0},
						"cvss_v3": map[string]any{"baseScore": 9.8},
					},
				},
			},
		},
	}
	for _, opt := range opts {
		opt(doc["document"].(map[string]any))
	}
	return mustJSON(doc)
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// insertRevision inserts a document for the given advisory and returns its id.
func insertRevision(t *testing.T, ctx context.Context, pool *pgxpool.Pool, advisoriesID int, doc string) int {
	t.Helper()
	var id int
	err := pool.QueryRow(ctx,
		`INSERT INTO documents (advisories_id, document) VALUES ($1, $2::jsonb) RETURNING id`,
		advisoriesID, doc,
	).Scan(&id)
	if err != nil {
		t.Fatalf("inserting revision: %v", err)
	}
	return id
}

func TestMigrateAppliesAndIsIdempotent(t *testing.T) {
	pool, ctx := startPostgres(t)

	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}

	// Second apply must be a no-op and must not error.
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("second (idempotent) Migrate: %v", err)
	}

	// versions must hold exactly one row recorded by the version-0 setup.
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM versions`).Scan(&count); err != nil {
		t.Fatalf("counting versions: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly one versions row after two applies, got %d", count)
	}
}

// TestMigrateRecordsLatestVersionOnFreshDB pins the versions_pkey regression
// fix: a fresh database runs only the consolidated 000-setup.sql, recorded as
// the LATEST known version (not version 0). Recording it as the latest is what
// stops the incremental 001 migration — whose objects are already baked into
// 000 — from also recording the same version and colliding on versions_pkey.
func TestMigrateRecordsLatestVersionOnFreshDB(t *testing.T) {
	pool, ctx := startPostgres(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate on fresh DB: %v", err)
	}

	migs, err := listMigrations()
	if err != nil {
		t.Fatalf("listing migrations: %v", err)
	}
	if len(migs) < 2 {
		t.Fatalf("expected at least two migration files (000 + 001), found %d", len(migs))
	}
	latest := migs[len(migs)-1].version

	// Exactly one row, carrying the latest version — proving 001 did not also
	// insert a (colliding) row on the fresh install.
	var (
		count   int
		version int64
	)
	if err := pool.QueryRow(ctx, `SELECT count(*), coalesce(max(version), -1) FROM versions`).
		Scan(&count, &version); err != nil {
		t.Fatalf("reading versions: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly one versions row on a fresh DB, got %d", count)
	}
	if version != latest {
		t.Errorf("recorded version = %d, want latest %d", version, latest)
	}

	// The objects the incremental 001 carries must be present from 000 alone.
	for _, table := range []string{"ingest_state"} {
		var exists bool
		if err := pool.QueryRow(ctx,
			`SELECT to_regclass('public.' || $1) IS NOT NULL`, table).Scan(&exists); err != nil {
			t.Fatalf("checking table %s: %v", table, err)
		}
		if !exists {
			t.Errorf("expected table %q from the consolidated 000 setup", table)
		}
	}
	for _, col := range []string{"withdrawn", "withdrawn_at"} {
		var exists bool
		if err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_name = 'advisories' AND column_name = $1
			)`, col).Scan(&exists); err != nil {
			t.Fatalf("checking column %s: %v", col, err)
		}
		if !exists {
			t.Errorf("expected advisories.%s from the consolidated 000 setup", col)
		}
	}
}

// TestMigrateAppliesIncrementalOnUpgrade is the in-sequence regression: a
// database created from an EARLIER 000-setup (recorded as version 0, before the
// tombstone/ingest_state objects existed) must, on the next Migrate, run the
// incremental 001 cleanly — applying both migrations in sequence without a
// versions_pkey duplicate — and end up with the new objects.
func TestMigrateAppliesIncrementalOnUpgrade(t *testing.T) {
	pool, ctx := startPostgres(t)

	// Simulate a legacy install: an older base schema that predates the task-8
	// objects, with the versions bookkeeping row recorded at version 0 (the
	// pre-fix scheme). The 001 incremental is written idempotently against this.
	const legacySchema = `
		CREATE TABLE versions (
			version     int PRIMARY KEY,
			description text NOT NULL,
			time        timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		INSERT INTO versions (version, description) VALUES (0, 'setup');
		CREATE TABLE advisories (
			id                 int PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
			tracking_id        text NOT NULL,
			publisher          text NOT NULL,
			latest_document_id int,
			recent             timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(tracking_id, publisher)
		);`
	if _, err := pool.Exec(ctx, legacySchema); err != nil {
		t.Fatalf("seeding legacy schema: %v", err)
	}

	// This must apply 001 (and only 001) on top of the version-0 install.
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate upgrading a legacy DB: %v", err)
	}
	// Idempotent re-apply must also succeed (no pkey collision, no duplicate).
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("second (idempotent) Migrate on upgraded DB: %v", err)
	}

	// versions now holds the 0 row plus the 001 row — and re-apply did not add
	// a third. The incremental did NOT record version 0 again (no collision).
	rows, err := pool.Query(ctx, `SELECT version FROM versions ORDER BY version`)
	if err != nil {
		t.Fatalf("reading versions: %v", err)
	}
	defer rows.Close()
	var versions []int64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("scanning version: %v", err)
		}
		versions = append(versions, v)
	}
	if len(versions) != 2 || versions[0] != 0 || versions[1] != 1 {
		t.Fatalf("versions after upgrade = %v, want [0 1]", versions)
	}

	// The task-8 objects the incremental introduces must now exist.
	var hasState bool
	if err := pool.QueryRow(ctx,
		`SELECT to_regclass('public.ingest_state') IS NOT NULL`).Scan(&hasState); err != nil {
		t.Fatalf("checking ingest_state: %v", err)
	}
	if !hasState {
		t.Error("expected ingest_state table after applying the incremental")
	}
	for _, col := range []string{"withdrawn", "withdrawn_at"} {
		var exists bool
		if err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_name = 'advisories' AND column_name = $1
			)`, col).Scan(&exists); err != nil {
			t.Fatalf("checking column %s: %v", col, err)
		}
		if !exists {
			t.Errorf("expected advisories.%s after applying the incremental", col)
		}
	}
}

func TestMigrateCreatesSchemaObjects(t *testing.T) {
	pool, ctx := startPostgres(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	t.Run("tables", func(t *testing.T) {
		for _, table := range []string{"advisories", "documents", "versions"} {
			var exists bool
			err := pool.QueryRow(ctx,
				`SELECT to_regclass('public.' || $1) IS NOT NULL`, table,
			).Scan(&exists)
			if err != nil {
				t.Fatalf("checking table %s: %v", table, err)
			}
			if !exists {
				t.Errorf("expected table %q to exist", table)
			}
		}
	})

	t.Run("status enum", func(t *testing.T) {
		var labels []string
		rows, err := pool.Query(ctx, `
			SELECT e.enumlabel
			FROM pg_type t
			JOIN pg_enum e ON e.enumtypid = t.oid
			WHERE t.typname = 'status'
			ORDER BY e.enumsortorder`)
		if err != nil {
			t.Fatalf("querying enum labels: %v", err)
		}
		defer rows.Close()
		for rows.Next() {
			var l string
			if err := rows.Scan(&l); err != nil {
				t.Fatalf("scanning enum label: %v", err)
			}
			labels = append(labels, l)
		}
		want := []string{"draft", "final", "interim"}
		if strings.Join(labels, ",") != strings.Join(want, ",") {
			t.Errorf("status enum labels = %v, want %v", labels, want)
		}
	})

	t.Run("helper functions", func(t *testing.T) {
		fns := []string{
			"utc_timestamp", "text_to_status", "revision_history_length",
			"max_cvss2_score", "max_cvss3_score", "update_advisory", "delete_advisory",
		}
		for _, fn := range fns {
			var exists bool
			err := pool.QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM pg_proc WHERE proname = $1)`, fn,
			).Scan(&exists)
			if err != nil {
				t.Fatalf("checking function %s: %v", fn, err)
			}
			if !exists {
				t.Errorf("expected function %q to exist", fn)
			}
		}
	})

	t.Run("indexes", func(t *testing.T) {
		indexes := []string{
			"only_one_latest_constraint",
			"advisories_recent_idx",
			"documents_current_release_date_idx",
			"documents_initial_release_date_idx",
			"documents_tlp_idx",
			"documents_category_idx",
			"documents_publisher_name_idx",
			"documents_lang_idx",
			"documents_critical_idx",
		}
		for _, idx := range indexes {
			var exists bool
			err := pool.QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = $1)`, idx,
			).Scan(&exists)
			if err != nil {
				t.Fatalf("checking index %s: %v", idx, err)
			}
			if !exists {
				t.Errorf("expected index %q to exist", idx)
			}
		}
	})

	t.Run("triggers", func(t *testing.T) {
		triggers := []string{"insert_document", "delete_document"}
		for _, trig := range triggers {
			var exists bool
			err := pool.QueryRow(ctx, `
				SELECT EXISTS (
					SELECT 1 FROM pg_trigger
					WHERE tgname = $1 AND NOT tgisinternal
				)`, trig,
			).Scan(&exists)
			if err != nil {
				t.Fatalf("checking trigger %s: %v", trig, err)
			}
			if !exists {
				t.Errorf("expected trigger %q to exist", trig)
			}
		}
	})
}

func TestGeneratedColumnsExtractFromJSONB(t *testing.T) {
	pool, ctx := startPostgres(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	advID := newAdvisory(t, ctx, pool, "PORTAL-GEN-1", "SecurityPortal Test Publisher")
	doc := revision("PORTAL-GEN-1", "1.0.0", "final", "2026-02-01T10:00:00Z", 1, func(d map[string]any) {
		d["category"] = "csaf_security_advisory"
	})
	id := insertRevision(t, ctx, pool, advID, doc)

	var (
		version     string
		revLen      int
		status      string
		releaseDate time.Time
		tlp         string
		title       string
		category    string
		publisher   string
		cvssV2      float64
		cvssV3      float64
		critical    float64
		lang        string
	)
	err := pool.QueryRow(ctx, `
		SELECT version, rev_history_length, tracking_status, current_release_date,
		       tlp, title, category, publisher_name,
		       cvss_v2_score, cvss_v3_score, critical, lang
		FROM documents WHERE id = $1`, id,
	).Scan(&version, &revLen, &status, &releaseDate, &tlp, &title, &category,
		&publisher, &cvssV2, &cvssV3, &critical, &lang)
	if err != nil {
		t.Fatalf("reading generated columns: %v", err)
	}

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"version", version, "1.0.0"},
		{"rev_history_length", revLen, 1},
		{"tracking_status", status, "final"},
		{"tlp", tlp, "WHITE"},
		{"title", title, "Test advisory 1.0.0"},
		{"category", category, "csaf_security_advisory"},
		{"publisher_name", publisher, "SecurityPortal Test Publisher"},
		{"cvss_v2_score", cvssV2, 5.0},
		{"cvss_v3_score", cvssV3, 9.8},
		{"critical", critical, 9.8},
		{"lang", lang, "en"},
	}
	for _, c := range checks {
		if fmt.Sprintf("%v", c.got) != fmt.Sprintf("%v", c.want) {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}

	if !releaseDate.Equal(time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("current_release_date = %v, want 2026-02-01T10:00:00Z", releaseDate.UTC())
	}
}

func TestLatestTriggerTracksHead(t *testing.T) {
	pool, ctx := startPostgres(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	const (
		trackingID = "PORTAL-LATEST-1"
		publisher  = "SecurityPortal Test Publisher"
	)
	advID := newAdvisory(t, ctx, pool, trackingID, publisher)

	// Revision 1 is the first, so it becomes the head immediately.
	rev1 := insertRevision(t, ctx, pool, advID,
		revision(trackingID, "1.0.0", "final", "2026-02-01T00:00:00Z", 1))
	assertLatest(t, ctx, pool, advID, rev1)

	// Revision 2 is newer, so the head moves to it.
	rev2 := insertRevision(t, ctx, pool, advID,
		revision(trackingID, "2.0.0", "final", "2026-03-01T00:00:00Z", 2))
	assertLatest(t, ctx, pool, advID, rev2)

	// A late-arriving OLDER revision must not regress the head: it stays rev2.
	rev0 := insertRevision(t, ctx, pool, advID,
		revision(trackingID, "0.9.0", "interim", "2026-01-15T00:00:00Z", 1))
	assertLatest(t, ctx, pool, advID, rev2)
	if isLatest(t, ctx, pool, rev0) {
		t.Errorf("late-arriving older revision %d must not be latest", rev0)
	}

	// Deleting the head (rev2) re-promotes the newest remaining revision (rev1).
	if _, err := pool.Exec(ctx, `DELETE FROM documents WHERE id = $1`, rev2); err != nil {
		t.Fatalf("deleting head revision: %v", err)
	}
	assertLatest(t, ctx, pool, advID, rev1)

	// Delete remaining revisions; once the last one goes the advisory is removed.
	if _, err := pool.Exec(ctx, `DELETE FROM documents WHERE id = $1`, rev1); err != nil {
		t.Fatalf("deleting rev1: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM documents WHERE id = $1`, rev0); err != nil {
		t.Fatalf("deleting rev0: %v", err)
	}

	var remaining int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM advisories WHERE id = $1`, advID,
	).Scan(&remaining); err != nil {
		t.Fatalf("counting advisory rows: %v", err)
	}
	if remaining != 0 {
		t.Errorf("advisory %d should be removed once its last document is deleted, got %d rows",
			advID, remaining)
	}
}

// newAdvisory inserts a parent advisory and returns its id.
func newAdvisory(t *testing.T, ctx context.Context, pool *pgxpool.Pool, trackingID, publisher string) int {
	t.Helper()
	var id int
	err := pool.QueryRow(ctx,
		`INSERT INTO advisories (tracking_id, publisher) VALUES ($1, $2) RETURNING id`,
		trackingID, publisher,
	).Scan(&id)
	if err != nil {
		t.Fatalf("inserting advisory: %v", err)
	}
	return id
}

// assertLatest fails the test unless wantDocID is the single latest document for
// the advisory and advisories.latest_document_id points at it.
func assertLatest(t *testing.T, ctx context.Context, pool *pgxpool.Pool, advID, wantDocID int) {
	t.Helper()

	var latestID int
	err := pool.QueryRow(ctx,
		`SELECT id FROM documents WHERE advisories_id = $1 AND latest`, advID,
	).Scan(&latestID)
	if err != nil {
		t.Fatalf("reading latest document for advisory %d: %v", advID, err)
	}
	if latestID != wantDocID {
		t.Errorf("latest document = %d, want %d", latestID, wantDocID)
	}

	var pointer int
	err = pool.QueryRow(ctx,
		`SELECT latest_document_id FROM advisories WHERE id = $1`, advID,
	).Scan(&pointer)
	if err != nil {
		t.Fatalf("reading latest_document_id for advisory %d: %v", advID, err)
	}
	if pointer != wantDocID {
		t.Errorf("advisories.latest_document_id = %d, want %d", pointer, wantDocID)
	}
}

func isLatest(t *testing.T, ctx context.Context, pool *pgxpool.Pool, docID int) bool {
	t.Helper()
	var latest *bool
	if err := pool.QueryRow(ctx,
		`SELECT latest FROM documents WHERE id = $1`, docID,
	).Scan(&latest); err != nil {
		t.Fatalf("reading latest flag for document %d: %v", docID, err)
	}
	return latest != nil && *latest
}
