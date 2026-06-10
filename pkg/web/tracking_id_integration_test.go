// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package web

// End-to-end integration tests for the
// GET /api/advisories/:publisher/:trackingid permalink endpoint
// (ADR-0016, plan tasks 41/46). These wire the real Gin handlers to a real
// postgres:16-alpine via the DinD harness, seeded with CSAF-shaped JSONB
// fixtures, and cover:
//
//   SA-39 — parameterized SQL / SQLi fixtures → 404 without corruption
//   SA-40 — non-publishable TLP → 404 identical to missing-id
//   SA-41 — 404 parity (missing, non-publishable, and withdrawn-non-publishable)
//   SA-51 — withdrawn publishable → 410 Gone; envelope omits document body
//   C-35  — envelope has exactly three keys (withdrawn, tracking_id, withdrawn_at)
//
// The DB-level query tests for GetByPublisherTrackingID (isolation) are in
// pkg/database/tracking_id_queries_integration_test.go.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/securityportal/securityportal-api/pkg/database"
)

// withdrawAdvisory tombstones an advisory so it becomes "withdrawn".
func (h *apiHarness) withdrawAdvisory(t *testing.T, keepIDs ...string) {
	t.Helper()
	present := make([]database.AdvisoryKey, len(keepIDs))
	for i, id := range keepIDs {
		present[i] = database.AdvisoryKey{TrackingID: id, Publisher: "Acme Security Team"}
	}
	if _, err := h.db.TombstoneAbsent(h.ctx, present); err != nil {
		t.Fatalf("TombstoneAbsent: %v", err)
	}
}

// advisoryPath returns the 2-segment permalink URL for the given publisher and
// tracking_id, percent-encoding only characters that would break URL parsing.
// For test simplicity the publisher is passed as a plain string (Gin will
// decode %XX in the path, so tests that need encoding use it explicitly).
func advisoryPath(publisher, trackingID string) string {
	return "/api/advisories/" + publisher + "/" + trackingID
}

// TestAPIPublisherTrackingIDPublishable_200Verbatim confirms a known publishable
// advisory (WHITE TLP, not withdrawn) returns HTTP 200 with the full CSAF JSON
// document and Content-Type: application/json.
func TestAPIPublisherTrackingIDPublishable_200Verbatim(t *testing.T) {
	h := newAPIHarness(t)
	const (
		trackingID = "IT-PERMALINK-WHITE-1"
		pub        = "Acme Security Team"
	)
	h.seedDoc(t, trackingID, pub, "1.0.0", "2026-03-01T00:00:00Z", "WHITE", 1)

	rec := h.get(t, advisoryPath("Acme%20Security%20Team", trackingID))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\n%s", rec.Code, rec.Body.String())
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "application/json; charset=utf-8" {
		t.Errorf("content-type = %q, want application/json; charset=utf-8", ct)
	}
	// The response must be valid JSON with a /document object.
	var parsed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if _, ok := parsed["document"]; !ok {
		t.Error("response missing /document key (expected verbatim CSAF JSON)")
	}
}

// TestAPIPublisherTrackingIDWithColon resolves an id containing a colon (like
// RHSA-2024:5101), which is percent-encoded as %3A in the URL (SA-43/C-19).
func TestAPIPublisherTrackingIDWithColon(t *testing.T) {
	h := newAPIHarness(t)
	const (
		trackingID = "RHSA-2024:5101"
		pub        = "Acme Security Team"
	)
	h.seedDoc(t, trackingID, pub, "1.0.0", "2026-03-01T00:00:00Z", "WHITE", 1)

	// The browser/client encodes ":" as "%3A".
	rec := h.get(t, advisoryPath("Acme%20Security%20Team", "RHSA-2024%3A5101"))
	if rec.Code != http.StatusOK {
		t.Fatalf("colon tracking_id: status = %d, want 200\n%s", rec.Code, rec.Body.String())
	}
	var parsed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("response not valid JSON: %v", err)
	}
	if _, ok := parsed["document"]; !ok {
		t.Error("response missing /document key")
	}
}

// TestAPIPublisherTrackingIDNotFound_404 checks that a random tracking_id that
// was never seeded returns a 404 with a JSON error body.
func TestAPIPublisherTrackingIDNotFound_404(t *testing.T) {
	h := newAPIHarness(t)

	rec := h.get(t, advisoryPath("Acme%20Security%20Team", "NO-SUCH-ID"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding 404 body: %v", err)
	}
	if _, ok := body["error"].(string); !ok {
		t.Errorf("404 body missing 'error' string key: %v", body)
	}
}

// TestAPIPublisherTrackingIDNonPublishableTLP_404_SameShapeAsMissing confirms
// SA-40/SA-41: an advisory with a restricted TLP (RED/AMBER/GREEN) returns a
// 404 with the same body shape as a genuinely missing id (no oracle for
// restricted docs).
func TestAPIPublisherTrackingIDNonPublishableTLP_404_SameShapeAsMissing(t *testing.T) {
	h := newAPIHarness(t)
	const pub = "Acme Security Team"

	for _, tlp := range []string{"RED", "AMBER", "GREEN"} {
		id := "RESTRICTED-" + tlp
		h.seedDoc(t, id, pub, "1.0.0", "2026-03-01T00:00:00Z", tlp, 1)

		rec := h.get(t, advisoryPath("Acme%20Security%20Team", id))
		if rec.Code != http.StatusNotFound {
			t.Errorf("SA-40 FAIL: TLP=%s → status %d, want 404", tlp, rec.Code)
			continue
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Errorf("SA-40 FAIL: TLP=%s 404 body not valid JSON: %v", tlp, err)
			continue
		}
		if _, ok := body["error"].(string); !ok {
			t.Errorf("SA-40 FAIL: TLP=%s 404 body missing 'error' key (oracle leak?): %v",
				tlp, body)
		}
	}
}

// TestAPIPublisherTrackingIDWithdrawn_410Envelope_SentinelAbsent confirms
// SA-51 and C-35 with a real database round-trip:
//   - SA-51: the advisory returns 410 Gone (not 200, not 404)
//   - SA-51: the document body is NOT in the response (sentinel absent)
//   - C-35:  envelope has exactly three keys (withdrawn, tracking_id, withdrawn_at)
func TestAPIPublisherTrackingIDWithdrawn_410Envelope_SentinelAbsent(t *testing.T) {
	h := newAPIHarness(t)
	const (
		trackingID = "IT-WITHDRAWN-SENTINEL"
		pub        = "Acme Security Team"
	)
	// The document title contains a unique sentinel that must NOT appear in the
	// withdrawn response (SA-51: handler must not read/emit document bytes).
	sentinel := "WITHDRAWN-SENTINEL-8f4e2a"

	doc := map[string]any{
		"document": map[string]any{
			"category": "csaf_security_advisory",
			"title":    sentinel,
			"lang":     "en",
			"publisher": map[string]any{
				"name":      pub,
				"namespace": "https://example.test",
			},
			"distribution": map[string]any{
				"tlp": map[string]any{"label": "WHITE"},
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
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshaling fixture: %v", err)
	}
	if _, err := h.db.StoreDocument(h.ctx, trackingID, pub, doc, b); err != nil {
		t.Fatalf("StoreDocument: %v", err)
	}

	// Withdraw by sweeping with an empty present set (all other advisories absent).
	h.withdrawAdvisory(t /* keep nothing from this advisory */)

	rec := h.get(t, advisoryPath("Acme%20Security%20Team", trackingID))

	// SA-51: withdrawn → 410 Gone, not 200 and not 404.
	if rec.Code != http.StatusGone {
		t.Fatalf("withdrawn advisory: status = %d, want 410 Gone\n%s",
			rec.Code, rec.Body.String())
	}

	body := rec.Body.String()

	// SA-51: document bytes must NOT appear.
	if strings.Contains(body, sentinel) {
		t.Errorf("SA-51 FAIL: sentinel %q appeared in withdrawn envelope response:\n%s",
			sentinel, body)
	}

	// C-35: exactly three keys.
	var env map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decoding envelope: %v", err)
	}
	if len(env) != 3 {
		t.Errorf("C-35 FAIL: envelope has %d keys, want exactly 3: %v", len(env), env)
	}
	for _, key := range []string{"withdrawn", "tracking_id", "withdrawn_at"} {
		if _, ok := env[key]; !ok {
			t.Errorf("C-35 FAIL: envelope missing key %q: %v", key, env)
		}
	}
	if w, _ := env["withdrawn"].(bool); !w {
		t.Errorf("C-35 FAIL: envelope['withdrawn'] = %v, want true", env["withdrawn"])
	}
}

// TestAPIPublisherTrackingIDSQLiFixtures_NoExtraRows_SA39 covers SA-39:
// SQL-injection payloads delivered as the tracking_id result in a 404 (not
// found) and do not corrupt or read extra rows. This uses a real DB so
// bound-parameter behaviour is genuinely exercised.
func TestAPIPublisherTrackingIDSQLiFixtures_NoExtraRows_SA39(t *testing.T) {
	h := newAPIHarness(t)

	// Seed a few publishable advisories so we can confirm no extra rows appear.
	const pub = "Acme Security Team"
	h.seedDoc(t, "REAL-ADV-1", pub, "1.0.0", "2026-01-01T00:00:00Z", "WHITE", 1)
	h.seedDoc(t, "REAL-ADV-2", pub, "1.0.0", "2026-02-01T00:00:00Z", "WHITE", 1)

	sqliPayloads := []string{
		"' OR 1=1 --",
		"x'; SELECT 1; --",
		`"; DROP TABLE advisories; --`,
		"' UNION SELECT 1,2,3,4,5 --",
	}

	for _, payload := range sqliPayloads {
		// URL-encode the payload for the path segment.
		encoded := urlEncodePathSegment(payload)
		rec := h.get(t, advisoryPath("Acme%20Security%20Team", encoded))

		// Every SQLi payload must yield 400 (if >256 bytes) or 404 (not found);
		// never 200 (which would mean a row was matched / injection succeeded).
		if rec.Code == http.StatusOK {
			t.Errorf("SA-39 FAIL: SQLi payload %q returned 200 — possible injection:\n%s",
				payload, rec.Body.String())
		}
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusBadRequest {
			t.Errorf("SA-39: payload %q returned unexpected status %d (want 404 or 400)",
				payload, rec.Code)
		}
	}

	// After all SQLi attempts the real rows must still exist and be queryable.
	listRec := h.get(t, "/api/advisories")
	if listRec.Code != http.StatusOK {
		t.Fatalf("list after SQLi attempts: status %d, want 200", listRec.Code)
	}
	listBody := decodeList(t, listRec)
	if listBody.Total < 2 {
		t.Errorf("SA-39 FAIL: only %d rows after SQLi attempts (DB may have been corrupted)",
			listBody.Total)
	}
}

// urlEncodePathSegment percent-encodes a string for use as a URL path segment.
// It encodes characters that are special in URL paths but preserves the leading
// character to avoid an empty segment.
func urlEncodePathSegment(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteByte(c)
		case c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			b.WriteString(percentEncode(c))
		}
	}
	return b.String()
}

func percentEncode(c byte) string {
	const hex = "0123456789ABCDEF"
	return "%" + string(hex[c>>4]) + string(hex[c&0xf])
}

// TestAPIPublisherTrackingIDCLEAR_PublishableAlias confirms that a CLEAR TLP
// advisory (the TLP 2.0 alias for WHITE) is also served (the publishable set
// includes both WHITE and CLEAR).
func TestAPIPublisherTrackingIDCLEAR_PublishableAlias(t *testing.T) {
	h := newAPIHarness(t)
	const (
		trackingID = "IT-CLEAR-TLP-1"
		pub        = "Acme Security Team"
	)
	h.seedDoc(t, trackingID, pub, "1.0.0", "2026-03-01T00:00:00Z", "CLEAR", 1)

	rec := h.get(t, advisoryPath("Acme%20Security%20Team", trackingID))
	if rec.Code != http.StatusOK {
		t.Fatalf("CLEAR TLP advisory: status = %d, want 200\n%s", rec.Code, rec.Body.String())
	}
}

// TestAPIPublisherTrackingIDWithdrawnAt_TimestampInEnvelope confirms that a
// withdrawn advisory's 410 envelope contains a non-null withdrawn_at when the
// advisory was tombstoned (the DB sets withdrawn_at = NOW() on tombstone).
func TestAPIPublisherTrackingIDWithdrawnAt_TimestampInEnvelope(t *testing.T) {
	h := newAPIHarness(t)
	const (
		trackingID = "IT-WITHDRAWN-TS"
		pub        = "Acme Security Team"
	)
	h.seedDoc(t, trackingID, pub, "1.0.0", "2026-03-01T00:00:00Z", "WHITE", 1)

	before := time.Now().UTC().Add(-time.Second)
	h.withdrawAdvisory(t /* keep nothing */)

	rec := h.get(t, advisoryPath("Acme%20Security%20Team", trackingID))
	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410\n%s", rec.Code, rec.Body.String())
	}

	var env map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decoding envelope: %v", err)
	}
	wdAt, ok := env["withdrawn_at"]
	if !ok {
		t.Fatal("envelope missing 'withdrawn_at' key")
	}
	if wdAt == nil {
		t.Fatal("withdrawn_at is null, want a timestamp (DB sets it on tombstone)")
	}
	// Parse the timestamp and confirm it is recent (set after we seeded).
	wdStr, _ := wdAt.(string)
	ts, err := time.Parse(time.RFC3339Nano, wdStr)
	if err != nil {
		ts, err = time.Parse(time.RFC3339, wdStr)
		if err != nil {
			t.Fatalf("withdrawn_at = %q is not a valid RFC3339 timestamp", wdStr)
		}
	}
	if ts.Before(before) {
		t.Errorf("withdrawn_at = %v is before the sweep time %v", ts, before)
	}
}

// TestAPIPublisherCollection_ReturnsListShape confirms that
// GET /api/advisories/:publisher returns a list-shaped body (total/limit/offset
// + advisories array), scoped to the given publisher.
func TestAPIPublisherCollection_ReturnsListShape(t *testing.T) {
	h := newAPIHarness(t)
	const (
		pubA = "Acme Security Team"
		pubB = "Beta CERT"
	)
	h.seedDoc(t, "PUB-A-1", pubA, "1.0.0", "2026-01-01T00:00:00Z", "WHITE", 1)
	h.seedDoc(t, "PUB-A-2", pubA, "1.0.0", "2026-02-01T00:00:00Z", "WHITE", 1)
	h.seedDoc(t, "PUB-B-1", pubB, "1.0.0", "2026-03-01T00:00:00Z", "WHITE", 1)

	rec := h.get(t, "/api/advisories/Acme%20Security%20Team")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\n%s", rec.Code, rec.Body.String())
	}
	body := decodeList(t, rec)

	if body.Total != 2 {
		t.Errorf("total = %d, want 2 (only Acme advisories)", body.Total)
	}
	ids := body.ids()
	if !contains(ids, "PUB-A-1") || !contains(ids, "PUB-A-2") {
		t.Errorf("ids = %v, want PUB-A-1 and PUB-A-2", ids)
	}
	if contains(ids, "PUB-B-1") {
		t.Error("Beta CERT advisory must not appear in Acme publisher collection")
	}
}

// TestAPIPublisherTrackingIDWrongPublisher_404 confirms that the correct
// (publisher, tracking_id) pair must match: using the right tracking_id but the
// wrong publisher yields 404 (not 200), since the UNIQUE key is (tracking_id,
// publisher).
func TestAPIPublisherTrackingIDWrongPublisher_404(t *testing.T) {
	h := newAPIHarness(t)
	const (
		trackingID = "CROSS-PUBLISHER"
		pub        = "Acme Security Team"
	)
	h.seedDoc(t, trackingID, pub, "1.0.0", "2026-01-01T00:00:00Z", "WHITE", 1)

	// Correct publisher → 200.
	if rec := h.get(t, advisoryPath("Acme%20Security%20Team", trackingID)); rec.Code != http.StatusOK {
		t.Errorf("correct publisher: status = %d, want 200", rec.Code)
	}
	// Wrong publisher → 404 (no oracle).
	rec := h.get(t, advisoryPath("Wrong%20Publisher", trackingID))
	if rec.Code != http.StatusNotFound {
		t.Errorf("wrong publisher: status = %d, want 404", rec.Code)
	}
}
