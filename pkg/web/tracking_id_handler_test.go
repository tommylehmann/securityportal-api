// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package web

// Unit tests for the getAdvisoryByPublisherTrackingID handler using the
// in-memory fakeQuerier (no database). These cover the response-code matrix and
// the security assumptions that can be proved at the HTTP / handler seam:
//
//   SA-40/SA-41 (TLP gate / 404 parity — no oracle for restricted or missing)
//   SA-51       (withdrawn → 410 Gone with exact 3-key envelope; doc bytes absent)
//   SA-43       (400 for empty / >256-byte segments; reject before any DB call)
//   SA-42       (arity routing: 1 segment = publisher collection, 2 = resource)
//   SA-33       (application/json + nosniff on all response branches)
//
// SA-39 (bound params / SQLi) and SA-40 (TLP gate with real data) require a
// real database; they live in tracking_id_integration_test.go.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/securityportal/securityportal-api/pkg/database"
)

// testPublisher is the publisher path segment used throughout these tests.
const testPublisher = "Acme+Security+Team"

// publisherPath returns a 2-segment advisory permalink for use in doRequest.
func publisherPath(publisher, trackingID string) string {
	return "/api/advisories/" + publisher + "/" + trackingID
}

// ---------------------------------------------------------------------------
// SA-40/SA-41 / Response-code matrix: 200 verbatim, 410 envelope, 404, 400
// ---------------------------------------------------------------------------

// TestGetAdvisoryByPublisherTrackingIDPublishable_200Verbatim exercises the
// happy path: a known publishable, non-withdrawn advisory returns 200 + verbatim
// CSAF JSON.
func TestGetAdvisoryByPublisherTrackingIDPublishable_200Verbatim(t *testing.T) {
	raw := []byte(`{"document":{"title":"openssl","tracking":{"id":"RHSA-2024:5101"}}}`)
	q := &fakeQuerier{trackingDoc: raw, trackingWithdrawn: false}

	rec := doRequest(t, q, http.MethodGet,
		publisherPath(testPublisher, "RHSA-2024%3A5101"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "application/json; charset=utf-8" {
		t.Errorf("content-type = %q, want application/json; charset=utf-8", ct)
	}
	if got := rec.Body.String(); got != string(raw) {
		t.Errorf("body = %q, want verbatim %q", got, raw)
	}
	// Gin URL-decodes the path segment before binding it, so the handler
	// receives "RHSA-2024:5101", not the encoded form.
	if q.gotTrackingID != "RHSA-2024:5101" {
		t.Errorf("handler received tracking_id = %q, want %q",
			q.gotTrackingID, "RHSA-2024:5101")
	}
}

// TestGetAdvisoryByPublisherTrackingIDWithdrawn_410Envelope checks that a
// withdrawn advisory returns HTTP 410 Gone with a JSON envelope of exactly three
// keys (withdrawn, tracking_id, withdrawn_at) and NOT the document body
// (SA-51 / C-35).
func TestGetAdvisoryByPublisherTrackingIDWithdrawn_410Envelope(t *testing.T) {
	sentinel := "UNIQUE-SENTINEL-MUST-NOT-APPEAR-8f4e2a"
	raw := []byte(`{"document":{"title":"` + sentinel + `"}}`)
	wdAt := time.Date(2026, 5, 10, 8, 0, 0, 0, time.UTC)
	q := &fakeQuerier{
		trackingDoc:         raw,
		trackingWithdrawn:   true,
		trackingWithdrawnAt: &wdAt,
	}

	rec := doRequest(t, q, http.MethodGet,
		publisherPath(testPublisher, "ADV-WITHDRAWN"))

	// SA-51: withdrawn → 410 Gone, not 200 and not 404.
	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410 (withdrawn → Gone, not 200)", rec.Code)
	}

	// SA-51: document bytes must NOT appear in the response.
	body := rec.Body.String()
	if strings.Contains(body, sentinel) {
		t.Errorf("SA-51 FAIL: document sentinel %q appeared in withdrawn response body: %s",
			sentinel, body)
	}

	// C-35/SA-51: envelope has exactly three keys.
	var env map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decoding envelope: %v", err)
	}
	if len(env) != 3 {
		t.Errorf("C-35 FAIL: envelope has %d keys, want exactly 3 "+
			"(withdrawn, tracking_id, withdrawn_at): %v", len(env), env)
	}
	for _, key := range []string{"withdrawn", "tracking_id", "withdrawn_at"} {
		if _, ok := env[key]; !ok {
			t.Errorf("C-35 FAIL: envelope missing key %q", key)
		}
	}
	if w, ok := env["withdrawn"].(bool); !ok || !w {
		t.Errorf("C-35 FAIL: envelope['withdrawn'] = %v, want true", env["withdrawn"])
	}
}

// TestGetAdvisoryByPublisherTrackingIDWithdrawnNullAt checks that a withdrawn
// advisory whose withdrawn_at is NULL still returns the 3-key envelope with null
// and HTTP 410.
func TestGetAdvisoryByPublisherTrackingIDWithdrawnNullAt(t *testing.T) {
	q := &fakeQuerier{
		trackingWithdrawn:   true,
		trackingWithdrawnAt: nil,
	}
	rec := doRequest(t, q, http.MethodGet,
		publisherPath(testPublisher, "ADV-WD-NO-TS"))

	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410", rec.Code)
	}
	var env map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decoding envelope: %v", err)
	}
	if len(env) != 3 {
		t.Errorf("envelope has %d keys, want 3", len(env))
	}
}

// TestGetAdvisoryByPublisherTrackingIDNotFound_404 checks that an unknown
// (publisher, tracking_id) returns 404 with the same generic error body shape
// as getDocument's 404 (no oracle, SA-41).
func TestGetAdvisoryByPublisherTrackingIDNotFound_404(t *testing.T) {
	q := &fakeQuerier{trackingErr: database.ErrDocumentNotFound}
	rec := doRequest(t, q, http.MethodGet,
		publisherPath(testPublisher, "DOES-NOT-EXIST"))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	// Must have the same {"error":"..."} shape as other 404 responses (no oracle).
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding 404 body: %v", err)
	}
	if _, ok := body["error"].(string); !ok {
		t.Errorf("404 body missing 'error' string key: %v", body)
	}
}

// ---------------------------------------------------------------------------
// SA-43 / C-27: 400 before any DB call for empty or overlong segments
// ---------------------------------------------------------------------------

// TestGetAdvisoryOverlongPublisher_400 checks that a publisher segment >256
// bytes returns 400 and the DB is NOT called (SA-43/C-27).
func TestGetAdvisoryOverlongPublisher_400(t *testing.T) {
	q := &fakeQuerier{}
	longPub := strings.Repeat("x", 300)
	rec := doRequest(t, q, http.MethodGet,
		"/api/advisories/"+longPub+"/SOME-ID")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("300-char publisher: status = %d, want 400", rec.Code)
	}
	if q.gotTrackingID != "" {
		t.Errorf("SA-43 FAIL: DB was called for an overlong publisher segment")
	}
}

// TestGetAdvisoryOverlongTrackingID_400 checks that a tracking_id segment >256
// bytes returns 400 and the DB is NOT called (SA-43/C-27).
func TestGetAdvisoryOverlongTrackingID_400(t *testing.T) {
	q := &fakeQuerier{}
	longID := strings.Repeat("x", 300)
	rec := doRequest(t, q, http.MethodGet,
		"/api/advisories/"+testPublisher+"/"+longID)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("300-char tracking_id: status = %d, want 400", rec.Code)
	}
	if q.gotTrackingID != "" {
		t.Errorf("SA-43 FAIL: DB was called for an overlong tracking_id segment")
	}
}

// TestGetAdvisoryExactly257BytesTrackingID_400 confirms the boundary: 257 bytes
// → 400.
func TestGetAdvisoryExactly257BytesTrackingID_400(t *testing.T) {
	q := &fakeQuerier{}
	id257 := strings.Repeat("a", 257)
	rec := doRequest(t, q, http.MethodGet,
		"/api/advisories/"+testPublisher+"/"+id257)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("257-byte tracking_id: status = %d, want 400", rec.Code)
	}
	if q.gotTrackingID != "" {
		t.Errorf("DB reached with 257-byte tracking_id; must be rejected before SQL")
	}
}

// TestGetAdvisoryExactly256BytesTrackingID_reachesDB confirms the boundary: 256
// bytes → reaches the DB (not rejected). The fake returns not-found → 404.
func TestGetAdvisoryExactly256BytesTrackingID_reachesDB(t *testing.T) {
	q := &fakeQuerier{trackingErr: database.ErrDocumentNotFound}
	id256 := strings.Repeat("b", 256)
	rec := doRequest(t, q, http.MethodGet,
		"/api/advisories/"+testPublisher+"/"+id256)

	// 256 bytes is at the limit — must reach the DB (404 from fake, not 400).
	if rec.Code != http.StatusNotFound {
		t.Fatalf("256-byte tracking_id: status = %d, want 404 (should reach DB)", rec.Code)
	}
	if q.gotTrackingID != id256 {
		t.Errorf("DB received %q, want the 256-byte id", q.gotTrackingID)
	}
}

// ---------------------------------------------------------------------------
// SA-42 / C-28: arity routing — 1 segment = publisher collection, 2 = resource
// ---------------------------------------------------------------------------

// TestRoutingOneSegmentIsPublisherCollection confirms that a single segment
// after /advisories/ resolves to the publisher-collection handler (200 with
// list shape), not the resource handler (SA-42/C-28).
func TestRoutingOneSegmentIsPublisherCollection(t *testing.T) {
	q := &fakeQuerier{list: database.AdvisoryList{}}
	rec := doRequest(t, q, http.MethodGet, "/api/advisories/SomePublisher")

	if rec.Code != http.StatusOK {
		t.Errorf("/api/advisories/SomePublisher → %d, want 200 (publisher collection)", rec.Code)
	}
	// The resource handler was NOT called (gotTrackingID stays empty).
	if q.gotTrackingID != "" {
		t.Errorf("resource handler was called for a 1-segment path; it must not be")
	}
}

// TestRoutingTwoSegmentsIsResource confirms that two segments resolve to the
// resource handler (SA-42/C-28).
func TestRoutingTwoSegmentsIsResource(t *testing.T) {
	raw := []byte(`{"document":{"title":"x"}}`)
	q := &fakeQuerier{trackingDoc: raw}
	rec := doRequest(t, q, http.MethodGet,
		"/api/advisories/"+testPublisher+"/SOME-ID")

	if rec.Code != http.StatusOK {
		t.Fatalf("/api/advisories/pub/id → %d, want 200", rec.Code)
	}
	if q.gotTrackingID != "SOME-ID" {
		t.Errorf("resource handler received tracking_id = %q, want %q",
			q.gotTrackingID, "SOME-ID")
	}
}

// TestRoutingColonEncodedIDReachesHandler checks that a colon-containing
// tracking_id encoded as %3A (RHSA-2024%3A5101) reaches the resource handler
// with the decoded value (RHSA-2024:5101). SA-42/C-19 URL-decode-once guarantee.
func TestRoutingColonEncodedIDReachesHandler(t *testing.T) {
	raw := []byte(`{"document":{"title":"rhel"}}`)
	q := &fakeQuerier{trackingDoc: raw}
	rec := doRequest(t, q, http.MethodGet,
		"/api/advisories/"+testPublisher+"/RHSA-2024%3A5101")

	if rec.Code != http.StatusOK {
		t.Fatalf("RHSA-2024%%3A5101 → %d, want 200", rec.Code)
	}
	if q.gotTrackingID != "RHSA-2024:5101" {
		t.Errorf("decoded tracking_id = %q, want %q",
			q.gotTrackingID, "RHSA-2024:5101")
	}
}

// TestRoutingSlashEncodedID_DoesNotTraverse checks that %2F in a tracking_id
// segment is decoded to "/" and remains within a single :trackingid parameter —
// it does not traverse to another handler (SA-42/C-28).
func TestRoutingSlashEncodedID_DoesNotTraverse(t *testing.T) {
	q := &fakeQuerier{trackingErr: database.ErrDocumentNotFound}
	rec := doRequest(t, q, http.MethodGet,
		"/api/advisories/"+testPublisher+"/a%2Fb")

	// Either 404 (handler called, id not found) or 400 (rejected for slash) —
	// but definitely not 200 from another handler (health, list, etc.).
	if rec.Code == http.StatusOK && q.gotTrackingID == "" {
		t.Errorf("SA-42 FAIL: %%2F traversed to a different handler (list/health returned 200)")
	}
}

// TestRoutingDotDotEncodedID_DoesNotTraverse checks that ..%2F..%2Fhealth does
// not reach the health handler (SA-42/C-28 path traversal guard).
func TestRoutingDotDotEncodedID_DoesNotTraverse(t *testing.T) {
	q := &fakeQuerier{trackingErr: database.ErrDocumentNotFound}
	rec := doRequest(t, q, http.MethodGet,
		"/api/advisories/"+testPublisher+"/..%2F..%2Fhealth")

	body := rec.Body.String()
	if rec.Code == http.StatusOK && strings.Contains(body, `"status"`) {
		t.Errorf("SA-42 FAIL: ..%%2F..%%2Fhealth traversed to health handler: %s", body)
	}
}

// ---------------------------------------------------------------------------
// SA-33: Content-Type application/json + nosniff on all response branches
// ---------------------------------------------------------------------------

// TestSecurityHeadersOnAdvisory200Verbatim checks SA-33 for the live-document
// 200 branch.
func TestSecurityHeadersOnAdvisory200Verbatim(t *testing.T) {
	raw := []byte(`{"document":{"title":"x"}}`)
	q := &fakeQuerier{trackingDoc: raw}
	rec := doRequest(t, q, http.MethodGet,
		publisherPath(testPublisher, "SOME-ID"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("SA-33 FAIL: X-Content-Type-Options = %q, want 'nosniff'", got)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("SA-33 FAIL: Content-Type = %q, want application/json prefix", ct)
	}
}

// TestSecurityHeadersOnAdvisory410Envelope checks SA-33 for the withdrawn 410
// branch.
func TestSecurityHeadersOnAdvisory410Envelope(t *testing.T) {
	wdAt := time.Date(2026, 5, 10, 0, 0, 0, 0, time.UTC)
	q := &fakeQuerier{trackingWithdrawn: true, trackingWithdrawnAt: &wdAt}
	rec := doRequest(t, q, http.MethodGet,
		publisherPath(testPublisher, "ADV-WD"))

	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410", rec.Code)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("SA-33 FAIL: X-Content-Type-Options = %q, want 'nosniff'", got)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("SA-33 FAIL: Content-Type = %q, want application/json prefix", ct)
	}
}

// TestSecurityHeadersOnAdvisory404 checks SA-33 for the 404 branch.
func TestSecurityHeadersOnAdvisory404(t *testing.T) {
	q := &fakeQuerier{trackingErr: database.ErrDocumentNotFound}
	rec := doRequest(t, q, http.MethodGet,
		publisherPath(testPublisher, "NO-SUCH"))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	nosniff := rec.Header().Get("X-Content-Type-Options")
	if nosniff != "nosniff" {
		t.Errorf("SA-33 FAIL: X-Content-Type-Options = %q on 404, want 'nosniff'", nosniff)
	}
}

// TestSecurityHeaderNosniffOnAdvisoryAllBranches is the SA-33 assertion for
// the 200-verbatim and 410-envelope branches using the standard doRequest helper.
func TestSecurityHeaderNosniffOnAdvisoryAllBranches(t *testing.T) {
	cases := []struct {
		name string
		q    *fakeQuerier
		want int
	}{
		{
			name: "live-document",
			q:    &fakeQuerier{trackingDoc: []byte(`{"document":{"title":"x"}}`)},
			want: http.StatusOK,
		},
		{
			name: "withdrawn-envelope",
			want: http.StatusGone,
			q: func() *fakeQuerier {
				ts := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
				return &fakeQuerier{trackingWithdrawn: true, trackingWithdrawnAt: &ts}
			}(),
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			rec := doRequest(t, tc.q, http.MethodGet,
				publisherPath(testPublisher, "TEST-ID"))
			if rec.Code != tc.want {
				t.Fatalf("%s: status = %d, want %d", tc.name, rec.Code, tc.want)
			}
			got := rec.Header().Get("X-Content-Type-Options")
			if got != "nosniff" {
				t.Errorf("%s: SA-33 FAIL: X-Content-Type-Options = %q, want 'nosniff'",
					tc.name, got)
			}
			ct := rec.Header().Get("Content-Type")
			if !strings.HasPrefix(ct, "application/json") {
				t.Errorf("%s: SA-33 FAIL: Content-Type = %q, want application/json prefix",
					tc.name, ct)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// C-35/SA-51: Envelope echoes the URL-decoded tracking_id
// ---------------------------------------------------------------------------

// TestWithdrawnEnvelopeEchoesDecodedTrackingID verifies that tracking_id in the
// 410 envelope is the URL-decoded value the handler received from Gin.
func TestWithdrawnEnvelopeEchoesDecodedTrackingID(t *testing.T) {
	wdAt := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	q := &fakeQuerier{
		trackingWithdrawn:   true,
		trackingWithdrawnAt: &wdAt,
	}
	rec := doRequest(t, q, http.MethodGet,
		publisherPath(testPublisher, "RHSA-2024%3A5101"))

	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410", rec.Code)
	}
	var env map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decoding envelope: %v", err)
	}
	// The handler echoes the decoded value it received from Gin (RHSA-2024:5101).
	if env["tracking_id"] != "RHSA-2024:5101" {
		t.Errorf("C-35 FAIL: envelope tracking_id = %q, want %q",
			env["tracking_id"], "RHSA-2024:5101")
	}
}
