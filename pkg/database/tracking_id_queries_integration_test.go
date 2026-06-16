// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package database

// Integration tests for GetByTrackingID (ADR-0013, plan task 11a) against a
// live postgres:16-alpine. They verify the security assumptions that must be
// proven at the real-DB level:
//
//   SA-27 — parameterized SQL: SQLi payloads → ErrDocumentNotFound, no DB corruption
//   SA-28 — publishable-TLP gate + no oracle (non-publishable → same error as missing)
//   SA-29 — withdrawn advisory resolves (not ErrDocumentNotFound) so caller can check
//   SA-30 — envelope data (withdrawn=true, withdrawnAt set)
//   SA-34 — duplicate tracking_id → deterministic single result (ORDER BY a.id LIMIT 1)
//
// HTTP-level tests (status codes, envelope shape, nosniff) live in
// pkg/web/tracking_id_integration_test.go and pkg/web/tracking_id_handler_test.go.

import (
	"encoding/json"
	"strings"
	"testing"
)

// publishableSet is already declared in queries_integration_test.go in this package.

// --- SA-28: publishable-TLP gate + 404 parity ---------------------------------

// TestGetByTrackingID_PublishableWhite confirms that a WHITE advisory returns
// its document bytes (not ErrDocumentNotFound) and withdrawn=false.
func TestGetByTrackingID_PublishableWhite(t *testing.T) {
	db, _, ctx := migratedDB(t)

	const (
		trackingID = "TID-WHITE-1"
		publisher  = "Acme Security Team"
	)
	doc := facetDoc(trackingID, publisher, "1.0.0", "2026-03-01T00:00:00Z", "WHITE", 1)
	seed(t, db, ctx, trackingID, publisher, doc)

	raw, withdrawn, withdrawnAt, err := db.GetByTrackingID(ctx, trackingID, publishableSet)
	if err != nil {
		t.Fatalf("GetByTrackingID: %v", err)
	}
	if withdrawn {
		t.Error("withdrawn = true for a non-tombstoned advisory, want false")
	}
	if withdrawnAt != nil {
		t.Errorf("withdrawnAt = %v, want nil for a non-tombstoned advisory", withdrawnAt)
	}
	if len(raw) == 0 {
		t.Error("expected non-empty document bytes for a publishable advisory")
	}
	// The bytes must be valid JSON.
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("document bytes are not valid JSON: %v", err)
	}
	if _, ok := parsed["document"]; !ok {
		t.Error("document bytes missing /document key (expected CSAF JSON)")
	}
}

// TestGetByTrackingID_NonPublishableTLP_SameErrorAsMissing confirms SA-28:
// a non-publishable TLP returns the same ErrDocumentNotFound as a missing id.
func TestGetByTrackingID_NonPublishableTLP_SameErrorAsMissing(t *testing.T) {
	db, _, ctx := migratedDB(t)
	const publisher = "Acme Security Team"

	for _, tlp := range []string{"RED", "AMBER", "GREEN"} {
		id := "TID-RESTRICTED-" + tlp
		doc := facetDoc(id, publisher, "1.0.0", "2026-03-01T00:00:00Z", tlp, 1)
		seed(t, db, ctx, id, publisher, doc)

		_, _, _, err := db.GetByTrackingID(ctx, id, publishableSet)
		if err != ErrDocumentNotFound {
			t.Errorf("SA-28 FAIL: TLP=%s → error = %v, want ErrDocumentNotFound (no oracle)", tlp, err)
		}
	}
}

// TestGetByTrackingID_Missing returns ErrDocumentNotFound for an id that was
// never seeded.
func TestGetByTrackingID_Missing(t *testing.T) {
	db, _, ctx := migratedDB(t)

	_, _, _, err := db.GetByTrackingID(ctx, "NO-SUCH-ID", publishableSet)
	if err != ErrDocumentNotFound {
		t.Fatalf("GetByTrackingID(missing): error = %v, want ErrDocumentNotFound", err)
	}
}

// --- SA-29/SA-30: withdrawn advisory resolves (not 404) with envelope data ----

// TestGetByTrackingID_Withdrawn_ResolvesNotError confirms SA-29:
// a withdrawn advisory returns (raw, withdrawn=true, withdrawnAt!=nil, nil error)
// — NOT ErrDocumentNotFound. The handler needs to distinguish withdrawn from
// missing so it can emit the 200 envelope. Additionally, the raw bytes are still
// returned (the caller must NOT use them when withdrawn=true, but the DB returns
// them for completeness).
func TestGetByTrackingID_Withdrawn_ResolvesNotError(t *testing.T) {
	db, _, ctx := migratedDB(t)

	const (
		trackingID = "TID-WITHDRAWN-1"
		publisher  = "Acme Security Team"
	)
	doc := facetDoc(trackingID, publisher, "1.0.0", "2026-03-01T00:00:00Z", "WHITE", 1)
	seed(t, db, ctx, trackingID, publisher, doc)

	// Tombstone by sweeping with no present advisories.
	if _, err := db.TombstoneAbsent(ctx, nil); err != nil {
		t.Fatalf("TombstoneAbsent: %v", err)
	}

	raw, withdrawn, withdrawnAt, err := db.GetByTrackingID(ctx, trackingID, publishableSet)
	if err != nil {
		// SA-29: a withdrawn advisory must resolve, not error.
		t.Fatalf("SA-29 FAIL: GetByTrackingID on withdrawn advisory returned error %v (want nil)", err)
	}
	if !withdrawn {
		t.Error("SA-29 FAIL: withdrawn = false for a tombstoned advisory, want true")
	}
	if withdrawnAt == nil {
		t.Error("SA-30: withdrawnAt is nil for a tombstoned advisory, want non-nil timestamp")
	}
	// raw bytes are provided but the handler must not use them (C-17/SA-29);
	// we just confirm it is valid JSON to show the query returned the row.
	if len(raw) > 0 {
		if !json.Valid(raw) {
			t.Errorf("returned raw bytes are not valid JSON: %q", string(raw))
		}
	}
}

// --- SA-27: parameterized SQL — SQLi payloads remain inert -------------------

// TestGetByTrackingID_SQLiPayloads_SA27 drives various SQL injection strings as
// the trackingID argument. Each must return ErrDocumentNotFound (the payloads
// are treated as literal strings, not interpreted as SQL). The seeded rows must
// survive unmodified.
func TestGetByTrackingID_SQLiPayloads_SA27(t *testing.T) {
	db, pool, ctx := migratedDB(t)

	const publisher = "Acme Security Team"
	// Seed three rows so we can confirm none of them disappear.
	for _, id := range []string{"SA27-ROW-A", "SA27-ROW-B", "SA27-ROW-C"} {
		doc := facetDoc(id, publisher, "1.0.0", "2026-01-01T00:00:00Z", "WHITE", 1)
		seed(t, db, ctx, id, publisher, doc)
	}

	payloads := []string{
		"' OR 1=1 --",
		"x'; SELECT 1; --",
		`"; DROP TABLE advisories; --`,
		"' UNION SELECT document::text, false, null FROM documents LIMIT 1 --",
		"$1",    // raw placeholder
		"\\x00", // null-byte-ish
	}

	for _, payload := range payloads {
		_, _, _, err := db.GetByTrackingID(ctx, payload, publishableSet)
		if err != ErrDocumentNotFound {
			t.Errorf("SA-27 FAIL: payload %q → error = %v, want ErrDocumentNotFound", payload, err)
		}
	}

	// All seeded rows must still exist.
	for _, id := range []string{"SA27-ROW-A", "SA27-ROW-B", "SA27-ROW-C"} {
		raw, _, _, err := db.GetByTrackingID(ctx, id, publishableSet)
		if err != nil {
			t.Errorf("SA-27 FAIL: row %s missing after SQLi attempts: %v (DB may be corrupted)", id, err)
		}
		if len(raw) == 0 {
			t.Errorf("SA-27 FAIL: row %s returned empty bytes after SQLi attempts", id)
		}
	}

	// The advisories table must still exist and contain our rows.
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM advisories WHERE publisher = $1`, publisher).Scan(&count); err != nil {
		t.Fatalf("SA-27: counting advisories after SQLi attempts: %v", err)
	}
	if count < 3 {
		t.Errorf("SA-27 FAIL: only %d advisories after SQLi attempts, want ≥3 (table may be corrupted)", count)
	}
}

// --- SA-34: deterministic resolution -----------------------------------------

// TestGetByTrackingID_DuplicateTrackingID_Deterministic confirms SA-34:
// when two advisories share a tracking_id (different publishers — the schema
// allows this), ORDER BY a.id LIMIT 1 selects the lower-id row every time.
func TestGetByTrackingID_DuplicateTrackingID_Deterministic(t *testing.T) {
	db, pool, ctx := migratedDB(t)

	const (
		sharedID = "SHARED-TID-SA34"
		pub1     = "Publisher One"
		pub2     = "Publisher Two"
	)

	doc1 := facetDoc(sharedID, pub1, "1.0.0", "2026-01-01T00:00:00Z", "WHITE", 1)
	doc2 := facetDoc(sharedID, pub2, "1.0.0", "2026-02-01T00:00:00Z", "WHITE", 1)
	seed(t, db, ctx, sharedID, pub1, doc1)
	seed(t, db, ctx, sharedID, pub2, doc2)

	// Determine which advisory.id is lower (that is the one ORDER BY a.id LIMIT 1
	// will return).
	var minID int64
	if err := pool.QueryRow(ctx,
		`SELECT min(id) FROM advisories WHERE tracking_id = $1`, sharedID).Scan(&minID); err != nil {
		t.Fatalf("finding min advisory id: %v", err)
	}

	// Call GetByTrackingID multiple times and confirm stable result.
	var firstRaw []byte
	for i := 0; i < 5; i++ {
		raw, _, _, err := db.GetByTrackingID(ctx, sharedID, publishableSet)
		if err != nil {
			t.Fatalf("SA-34: iteration %d: GetByTrackingID: %v", i, err)
		}
		if firstRaw == nil {
			firstRaw = raw
		} else if string(raw) != string(firstRaw) {
			t.Errorf("SA-34 FAIL: non-deterministic result on iteration %d", i)
		}
	}

	// Confirm it is the publisher with the lower advisory.id row.
	var gotPublisher string
	if err := pool.QueryRow(ctx,
		`SELECT a.publisher FROM advisories a
		 JOIN documents d ON d.advisories_id = a.id AND d.latest
		 WHERE a.tracking_id = $1
		 ORDER BY a.id LIMIT 1`, sharedID).Scan(&gotPublisher); err != nil {
		t.Fatalf("finding expected publisher: %v", err)
	}

	if !strings.Contains(string(firstRaw), gotPublisher) {
		t.Errorf("SA-34 FAIL: result does not contain expected publisher %q", gotPublisher)
	}
}
