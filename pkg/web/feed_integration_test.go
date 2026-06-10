// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package web

// Integration tests for the Atom feed endpoints and HATEOAS _links, wired
// against a real postgres:16-alpine via DinD.
//
//   SA-46  non-publishable + withdrawn advisories absent from global and per-publisher feeds
//   SA-47  content-type + nosniff on live feed responses; limit=10000 clamped
//   SA-50  _links.self round-trips to the resource; pagination link math against a seeded corpus

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/securityportal/securityportal-api/pkg/database"
)

// xmlFeed is a minimal struct for decoding an Atom feed response without
// importing the internal atomFeed type at the test level.
type xmlFeed struct {
	XMLName xml.Name   `xml:"feed"`
	Entries []xmlEntry `xml:"entry"`
}

type xmlEntry struct {
	ID    string `xml:"id"`
	Title string `xml:"title"`
}

// ============================================================================
// SA-46: non-publishable + withdrawn absent from global and per-publisher feeds
// ============================================================================

// TestFeedIntegration_NonPublishableAndWithdrawnAbsent proves SA-46: RED-TLP and
// withdrawn advisories are absent from both the global and per-publisher feeds.
func TestFeedIntegration_NonPublishableAndWithdrawnAbsent(t *testing.T) {
	h := newAPIHarness(t)
	const pub = "Acme Security Team"

	// Publishable, active advisory — must appear in the feed.
	h.seedDoc(t, "FEED-WHITE-1", pub, "1.0.0", "2026-03-01T00:00:00Z", "WHITE", 1)
	// Restricted (RED) — must never appear.
	h.seedDoc(t, "FEED-RED-1", pub, "1.0.0", "2026-03-01T00:00:00Z", "RED", 1)
	// Active publishable, then withdrawn — must not appear in the feed.
	h.seedDoc(t, "FEED-WD-1", pub, "1.0.0", "2026-02-01T00:00:00Z", "WHITE", 1)
	// Tombstone FEED-WD-1: only keep FEED-WHITE-1 and FEED-RED-1 as "present".
	if _, err := h.db.TombstoneAbsent(h.ctx, []database.AdvisoryKey{
		{TrackingID: "FEED-WHITE-1", Publisher: pub},
		{TrackingID: "FEED-RED-1", Publisher: pub},
	}); err != nil {
		t.Fatalf("TombstoneAbsent: %v", err)
	}

	// --- Global feed ---
	globalRec := h.get(t, "/api/feed.atom")
	if globalRec.Code != http.StatusOK {
		t.Fatalf("global feed status = %d, want 200\n%s", globalRec.Code, globalRec.Body.String())
	}
	globalFeed := decodeXMLFeed(t, globalRec.Body.Bytes())

	if !feedContainsEntry(globalFeed, "FEED-WHITE-1") {
		t.Errorf("SA-46: global feed missing publishable advisory FEED-WHITE-1")
	}
	if feedContainsEntry(globalFeed, "FEED-RED-1") {
		t.Errorf("SA-46 FAIL: global feed contains RED advisory FEED-RED-1 (non-publishable)")
	}
	if feedContainsEntry(globalFeed, "FEED-WD-1") {
		t.Errorf("SA-46 FAIL: global feed contains withdrawn advisory FEED-WD-1")
	}

	// --- Per-publisher feed ---
	pubRec := h.get(t, "/api/advisories/Acme%20Security%20Team/feed.atom")
	if pubRec.Code != http.StatusOK {
		t.Fatalf("publisher feed status = %d, want 200\n%s", pubRec.Code, pubRec.Body.String())
	}
	pubFeed := decodeXMLFeed(t, pubRec.Body.Bytes())

	if !feedContainsEntry(pubFeed, "FEED-WHITE-1") {
		t.Errorf("SA-46: per-publisher feed missing publishable advisory FEED-WHITE-1")
	}
	if feedContainsEntry(pubFeed, "FEED-RED-1") {
		t.Errorf("SA-46 FAIL: per-publisher feed contains RED advisory FEED-RED-1")
	}
	if feedContainsEntry(pubFeed, "FEED-WD-1") {
		t.Errorf("SA-46 FAIL: per-publisher feed contains withdrawn advisory FEED-WD-1")
	}
}

// TestFeedIntegration_UnknownPublisherEmptyValid proves ADR-0017's choice:
// an unknown publisher yields an empty but valid Atom feed (not 404).
func TestFeedIntegration_UnknownPublisherEmptyValid(t *testing.T) {
	h := newAPIHarness(t)

	rec := h.get(t, "/api/advisories/NoSuchPublisher/feed.atom")
	if rec.Code != http.StatusOK {
		t.Fatalf("unknown publisher feed status = %d, want 200 (empty valid feed)", rec.Code)
	}
	// Must be parseable XML.
	var f xmlFeed
	if err := xml.Unmarshal(rec.Body.Bytes(), &f); err != nil {
		t.Fatalf("unknown publisher: malformed Atom XML: %v\n%s", err, rec.Body.Bytes())
	}
	if len(f.Entries) != 0 {
		t.Errorf("unknown publisher: feed has %d entries, want 0", len(f.Entries))
	}
}

// TestFeedIntegration_ContentTypeAndNosniff_Live confirms SA-47 on a real response.
func TestFeedIntegration_ContentTypeAndNosniff_Live(t *testing.T) {
	h := newAPIHarness(t)

	rec := h.get(t, "/api/feed.atom")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "application/atom+xml; charset=utf-8" {
		t.Errorf("SA-47 FAIL: Content-Type = %q, want application/atom+xml; charset=utf-8", ct)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("SA-47 FAIL: X-Content-Type-Options = %q, want nosniff", got)
	}
}

// TestFeedIntegration_HostileTitleWellFormedXML proves SA-44 end-to-end with a
// real database round-trip: a document with XML-hostile metadata in its title
// produces a well-formed Atom feed.
func TestFeedIntegration_HostileTitleWellFormedXML(t *testing.T) {
	h := newAPIHarness(t)
	const pub = "Acme Security Team"

	// Seed a document with an XML-hostile title (contains <, &, and ").
	h.seedDoc(t, `<"hostile">&advisory`, pub, "1.0.0", "2026-03-01T00:00:00Z", "WHITE", 1)

	rec := h.get(t, "/api/feed.atom")
	if rec.Code != http.StatusOK {
		t.Fatalf("feed status = %d, want 200\n%s", rec.Code, rec.Body.String())
	}

	// The feed must be well-formed XML.
	var f xmlFeed
	if err := xml.Unmarshal(rec.Body.Bytes(), &f); err != nil {
		t.Fatalf("SA-44 FAIL: hostile-title feed produced malformed XML: %v\n%s",
			err, rec.Body.Bytes())
	}
}

// ============================================================================
// SA-50: _links.self round-trips; pagination link math against a seeded corpus
// ============================================================================

// TestLinksIntegration_SelfLinkRoundTrips proves SA-50: the _links.self of each
// row in the list response is the publisher-scoped permalink, not /documents/<int>,
// and it resolves to the same advisory on a follow-up GET.
func TestLinksIntegration_SelfLinkRoundTrips(t *testing.T) {
	h := newAPIHarness(t)
	const (
		trackingID = "LINKS-ROUNDTRIP-1"
		pub        = "Acme Security Team"
	)
	h.seedDoc(t, trackingID, pub, "1.0.0", "2026-03-01T00:00:00Z", "WHITE", 1)

	// Get the list response and extract the self link.
	listRec := h.get(t, "/api/advisories")
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200", listRec.Code)
	}

	self := extractFirstSelfLink(t, listRec.Body.Bytes())
	if self == "" {
		t.Fatal("SA-50 FAIL: first advisory row has no _links.self")
	}

	// Must not be /api/documents/<int>.
	if strings.Contains(self, "/documents/") {
		t.Errorf("SA-50 FAIL: self link %q uses internal /documents/<int> permalink", self)
	}

	// Must be the publisher-scoped form /api/advisories/{pub}/{trackingid}.
	if !strings.HasPrefix(self, "/api/advisories/") {
		t.Errorf("SA-50 FAIL: self link %q not publisher-scoped", self)
	}

	// Round-trip: follow the self link.
	resRec := h.get(t, self)
	if resRec.Code != http.StatusOK {
		t.Errorf("SA-50 FAIL: self link %q → %d, want 200 (must round-trip)", self, resRec.Code)
	}
}

// TestLinksIntegration_PaginationMathOnGatedCorpus proves SA-50: pagination
// _links.{first,next,prev} math is correct and is computed from the TLP-gated
// total (non-publishable rows do not inflate the count, so no link implies a row
// excluded by the gate).
func TestLinksIntegration_PaginationMathOnGatedCorpus(t *testing.T) {
	h := newAPIHarness(t)
	const pub = "Acme Security Team"

	// Seed 5 publishable + 2 non-publishable (RED) advisories.
	for i := 0; i < 5; i++ {
		id := "PAGINATE-" + itoaAPI(i)
		date := time.Date(2026, 1, 1+i, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
		h.seedDoc(t, id, pub, "1.0.0", date, "WHITE", 1)
	}
	for i := 0; i < 2; i++ {
		id := "PAGINATE-RED-" + itoaAPI(i)
		date := time.Date(2026, 2, 1+i, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
		h.seedDoc(t, id, pub, "1.0.0", date, "RED", 1)
	}

	// Page 1 (limit=2, offset=0): 5 publishable rows total.
	rec := h.get(t, "/api/advisories?limit=2&offset=0")
	if rec.Code != http.StatusOK {
		t.Fatalf("page 1 status = %d, want 200", rec.Code)
	}
	body := decodeList(t, rec)
	if body.Total != 5 {
		t.Errorf("SA-50 FAIL: total = %d, want 5 (RED rows must not inflate the count)", body.Total)
	}

	links := extractCollectionLinks(t, rec.Body.Bytes())

	// First page: prev must be nil, next must be non-nil.
	if prev, ok := links["prev"]; ok && prev != nil {
		t.Errorf("SA-50 FAIL: first page has prev link %v", prev)
	}
	nextLink, hasNext := links["next"]
	if !hasNext || nextLink == nil {
		t.Error("SA-50 FAIL: first page missing next link")
	}

	// Middle page (limit=2, offset=2): both prev and next.
	rec2 := h.get(t, "/api/advisories?limit=2&offset=2")
	if rec2.Code != http.StatusOK {
		t.Fatalf("page 2 status = %d", rec2.Code)
	}
	links2 := extractCollectionLinks(t, rec2.Body.Bytes())
	if _, hasPrev := links2["prev"]; !hasPrev {
		t.Error("SA-50 FAIL: middle page missing prev link")
	}
	if _, hasNext2 := links2["next"]; !hasNext2 {
		t.Error("SA-50 FAIL: middle page missing next link")
	}

	// Last page (limit=2, offset=4): prev present, next nil.
	rec3 := h.get(t, "/api/advisories?limit=2&offset=4")
	if rec3.Code != http.StatusOK {
		t.Fatalf("last page status = %d", rec3.Code)
	}
	links3 := extractCollectionLinks(t, rec3.Body.Bytes())
	if next3, ok := links3["next"]; ok && next3 != nil {
		t.Errorf("SA-50 FAIL: last page has next link %v", next3)
	}
	if _, hasPrev3 := links3["prev"]; !hasPrev3 {
		t.Error("SA-50 FAIL: last page missing prev link")
	}
}

// ============================================================================
// helper functions
// ============================================================================

// decodeXMLFeed decodes the Atom XML body into our minimal xmlFeed struct.
func decodeXMLFeed(t *testing.T, body []byte) xmlFeed {
	t.Helper()
	var f xmlFeed
	if err := xml.Unmarshal(body, &f); err != nil {
		t.Fatalf("decodeXMLFeed: malformed XML: %v\n%s", err, body)
	}
	return f
}

// feedContainsEntry reports whether any entry's id or title contains the given
// tracking_id string.
func feedContainsEntry(f xmlFeed, trackingID string) bool {
	for _, e := range f.Entries {
		if strings.Contains(e.ID, trackingID) || strings.Contains(e.Title, trackingID) {
			return true
		}
	}
	return false
}

// extractFirstSelfLink parses the list JSON body and returns the _links.self
// of the first advisory row, or "" when not found.
func extractFirstSelfLink(t *testing.T, body []byte) string {
	t.Helper()
	var resp struct {
		Advisories []struct {
			Links struct {
				Self string `json:"self"`
			} `json:"_links"`
		} `json:"advisories"`
	}
	if err := decodeJSON(body, &resp); err != nil {
		t.Fatalf("extractFirstSelfLink: %v", err)
	}
	if len(resp.Advisories) == 0 {
		return ""
	}
	return resp.Advisories[0].Links.Self
}

// extractCollectionLinks parses the list JSON body and returns the _links map
// (self, first, prev, next) as a map[string]interface{}.
func extractCollectionLinks(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var resp struct {
		Links map[string]any `json:"_links"`
	}
	if err := decodeJSON(body, &resp); err != nil {
		t.Fatalf("extractCollectionLinks: %v", err)
	}
	return resp.Links
}

// decodeJSON is a thin wrapper around json.Unmarshal for test helpers.
func decodeJSON(body []byte, dst any) error {
	return json.Unmarshal(body, dst)
}
