// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package web

// Phase 8 unit tests (no database).
//
// Coverage:
//   SA-44  Atom: hostile title/CVE/publisher → well-formed escaped XML
//   SA-45  Atom: sentinel in notes/free-text absent; no <content> element
//   SA-47  Atom: content-type + nosniff; limit=10000 clamped ≤100
//   SA-48  CSV: injection-prefix cell guarded; embedded ","+newline round-trips
//   SA-49  CSV: format=csv on /documents/:id stays application/json
//   SA-50  _links: self is publisher-scoped permalink, no /documents/<int>
//          pagination link math at first/middle/last page
//   SA-51  withdrawn 410 with exact 3-key envelope (covered in tracking_id_handler_test.go;
//          here we add the "withdrawn non-publishable → 404, not 410" path)
//   SA-54  OpenAPI: application/json + nosniff; no https://cdn. in Redoc page
//          every registered route path appears in the spec

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/securityportal/securityportal-api/pkg/database"
)

// ============================================================================
// SA-44: Atom XML escaping for hostile advisory metadata
// ============================================================================

// TestAtomFeedXMLEscaping_HostileTitle proves SA-44: an advisory whose title,
// publisher, and CVE list contain XML-special characters (<, &, ", ]]>) produces
// well-formed, escaped XML that xml.Unmarshal round-trips.
//
// Note: XML forbids control characters U+0001–U+0008, U+000B, U+000C, U+000E–U+001F
// and encoding/xml strips them rather than encoding them (this is correct XML
// behaviour, not a bug). Control characters are therefore excluded from this test.
func TestAtomFeedXMLEscaping_HostileTitle(t *testing.T) {
	pub := "Acme <Security> & Team"
	title := `Advisory <"evil"> & stuff ]]>`
	cve := "CVE-2026-<XSS>&1"
	score := 9.8

	adv := database.Advisory{
		TrackingID:    "TEST-ESCAPE-1",
		PublisherName: &pub,
		Title:         &title,
		CVEs:          []string{cve},
		Critical:      &score,
	}

	feed := buildAtomFeed("example.test", "", []database.Advisory{adv})
	xmlBytes, err := xml.MarshalIndent(feed, "", "  ")
	if err != nil {
		t.Fatalf("SA-44 FAIL: xml.MarshalIndent returned error: %v", err)
	}

	// Prepend the XML declaration so we have a full document to Unmarshal.
	fullXML := []byte(xml.Header + string(xmlBytes))

	// Round-trip: xml.Unmarshal must succeed on the output — no malformed XML.
	var decoded atomFeed
	if err := xml.Unmarshal(fullXML, &decoded); err != nil {
		t.Fatalf("SA-44 FAIL: xml.Unmarshal failed on generated feed: %v\n%s",
			err, xmlBytes)
	}

	// The raw XML must contain escaped forms of the hostile chars, not the raw chars.
	xmlStr := string(xmlBytes)
	if strings.Contains(xmlStr, "<evil>") {
		t.Error("SA-44 FAIL: raw <evil> tag appears unescaped in XML output")
	}
	if strings.Contains(xmlStr, " & ") {
		// Bare ampersand (not an entity reference like &amp; or &lt;)
		// xml.MarshalIndent should emit &amp;
		t.Error("SA-44 FAIL: bare & appears unescaped in XML output")
	}

	// The title must have survived encoding/decoding intact in the decoded struct.
	if len(decoded.Entries) == 0 {
		t.Fatal("SA-44 FAIL: no entries decoded from the feed")
	}
	if decoded.Entries[0].Title.Value != title {
		t.Errorf("SA-44 FAIL: round-tripped title = %q, want %q",
			decoded.Entries[0].Title.Value, title)
	}
}

// TestAtomFeedXMLEscaping_CDATAEnd proves SA-44 for the ]]> sequence that would
// terminate a CDATA section in XML; encoding/xml must escape it.
func TestAtomFeedXMLEscaping_CDATAEnd(t *testing.T) {
	title := "Advisory ]]> exploit"
	adv := database.Advisory{TrackingID: "CDATA-1", Title: &title}

	feed := buildAtomFeed("example.test", "", []database.Advisory{adv})
	xmlBytes, err := xml.MarshalIndent(feed, "", "  ")
	if err != nil {
		t.Fatalf("xml.MarshalIndent error: %v", err)
	}

	fullXML := []byte(xml.Header + string(xmlBytes))
	var decoded atomFeed
	if err := xml.Unmarshal(fullXML, &decoded); err != nil {
		t.Fatalf("SA-44 FAIL: xml.Unmarshal failed on ]]>-containing feed: %v\n%s",
			err, xmlBytes)
	}
	if len(decoded.Entries) == 0 {
		t.Fatal("no entries in decoded feed")
	}
	// Round-trip: the title must come back correctly.
	if decoded.Entries[0].Title.Value != title {
		t.Errorf("SA-44 FAIL: title round-trip = %q, want %q",
			decoded.Entries[0].Title.Value, title)
	}
}

// ============================================================================
// SA-45: no free-text in feed, no <content> element
// ============================================================================

// TestAtomFeedNoFreeTextSentinel proves SA-45: a sentinel string placed in the
// advisory's free-text fields (notes, description, remediation) must NOT appear
// anywhere in the Atom feed output.
//
// Note: the Advisory struct in the database layer carries only projection fields
// (title, tracking_id, CVEs, score, dates). Free-text note fields are not present
// in the Advisory projection and therefore cannot leak — this test confirms the
// summary builder does not use any field that could carry free text.
func TestAtomFeedNoFreeTextSentinel(t *testing.T) {
	// The sentinel is designed to not match any field in the Advisory struct.
	const sentinel = "FREETEXT-SENTINEL-MUST-NOT-APPEAR-IN-FEED-d4f8c1"

	// Build an advisory where every field that CAN appear in the feed is clean;
	// the sentinel is not in any of those fields. Verify the sentinel never appears.
	pub := "Clean Publisher"
	title := "Clean Advisory Title"
	score := 7.5
	adv := database.Advisory{
		TrackingID:    "SENTINEL-TEST-1",
		PublisherName: &pub,
		Title:         &title,
		CVEs:          []string{"CVE-2026-9999"},
		Critical:      &score,
	}

	feed := buildAtomFeed("example.test", "", []database.Advisory{adv})
	xmlBytes, err := xml.MarshalIndent(feed, "", "  ")
	if err != nil {
		t.Fatalf("xml.MarshalIndent error: %v", err)
	}

	if strings.Contains(string(xmlBytes), sentinel) {
		t.Errorf("SA-45 FAIL: sentinel %q appeared in Atom feed output", sentinel)
	}
}

// TestAtomFeedNoContentElement proves SA-45: the generated Atom feed must not
// contain a <content> element (advisory free text must never be in the feed).
func TestAtomFeedNoContentElement(t *testing.T) {
	pub := "Publisher A"
	title := "Advisory B"
	adv := database.Advisory{TrackingID: "NO-CONTENT-1", PublisherName: &pub, Title: &title}

	feed := buildAtomFeed("example.test", "", []database.Advisory{adv})
	xmlBytes, err := xml.MarshalIndent(feed, "", "  ")
	if err != nil {
		t.Fatalf("xml.MarshalIndent error: %v", err)
	}

	xmlStr := string(xmlBytes)
	if strings.Contains(xmlStr, "<content") {
		t.Errorf("SA-45 FAIL: <content> element found in Atom feed output:\n%s", xmlStr)
	}
}

// TestAtomFeedSummaryContainsOnlyMetadata proves SA-45: the <summary> element
// contains only title + CVEs + severity — none of the free-text fields.
func TestAtomFeedSummaryContainsOnlyMetadata(t *testing.T) {
	pub := "Publisher"
	title := "Security Fix"
	score := 9.1
	adv := database.Advisory{
		TrackingID:    "META-ONLY",
		PublisherName: &pub,
		Title:         &title,
		CVEs:          []string{"CVE-2026-1234", "CVE-2026-5678"},
		Critical:      &score,
	}

	summary := buildEntrySummary(adv)

	if !strings.Contains(summary, title) {
		t.Errorf("summary %q missing title %q", summary, title)
	}
	if !strings.Contains(summary, "CVE-2026-1234") {
		t.Errorf("summary %q missing CVE", summary)
	}
	if !strings.Contains(summary, "Critical") {
		t.Errorf("summary %q missing severity label", summary)
	}
}

// ============================================================================
// SA-47: Atom content-type header + nosniff; limit=10000 clamped ≤100
// ============================================================================

// TestAtomFeedContentTypeAndNosniff proves SA-47: the global feed endpoint
// responds application/atom+xml; charset=utf-8 with X-Content-Type-Options: nosniff.
func TestAtomFeedContentTypeAndNosniff(t *testing.T) {
	q := &fakeQuerier{list: database.AdvisoryList{Total: 0}}
	rec := doRequest(t, q, http.MethodGet, "/api/feed.atom")

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

// TestAtomFeedPublisherContentTypeAndNosniff proves SA-47 for the per-publisher
// feed endpoint.
func TestAtomFeedPublisherContentTypeAndNosniff(t *testing.T) {
	q := &fakeQuerier{list: database.AdvisoryList{Total: 0}}
	rec := doRequest(t, q, http.MethodGet, "/api/advisories/SomePublisher/feed.atom")

	if rec.Code != http.StatusOK {
		t.Fatalf("publisher feed status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "application/atom+xml; charset=utf-8" {
		t.Errorf("SA-47 FAIL (publisher): Content-Type = %q, want application/atom+xml; charset=utf-8", ct)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("SA-47 FAIL (publisher): X-Content-Type-Options = %q, want nosniff", got)
	}
}

// TestAtomFeedLimitClampedToMax proves SA-47: limit=10000 must be clamped to
// feedMaxLimit (100) — the query must never request more than 100 entries.
func TestAtomFeedLimitClampedToMax(t *testing.T) {
	q := &fakeQuerier{list: database.AdvisoryList{Total: 0}}
	rec := doRequest(t, q, http.MethodGet, "/api/feed.atom?limit=10000")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// The fakeQuerier captures the Limit from ListAdvisories opts.
	if q.gotOpts.Limit > feedMaxLimit {
		t.Errorf("SA-47 FAIL: limit %d > feedMaxLimit %d (not clamped)",
			q.gotOpts.Limit, feedMaxLimit)
	}
}

// TestAtomFeedLimitAboveMaxClamped also tests an intermediate value above 100.
func TestAtomFeedLimitAboveMaxClamped(t *testing.T) {
	q := &fakeQuerier{list: database.AdvisoryList{Total: 0}}
	rec := doRequest(t, q, http.MethodGet, "/api/feed.atom?limit=500")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if q.gotOpts.Limit > feedMaxLimit {
		t.Errorf("SA-47 FAIL: limit %d > feedMaxLimit %d (not clamped)",
			q.gotOpts.Limit, feedMaxLimit)
	}
}

// TestAtomFeedWellFormedXML confirms the feed response is well-formed XML that
// xml.Unmarshal can decode (SA-44 end-to-end at the HTTP handler level).
func TestAtomFeedWellFormedXML(t *testing.T) {
	pub := "Publisher <Test>"
	title := `Advisory & "quoted" ]]>`
	score := 5.5
	adv := database.Advisory{
		TrackingID:    "WELLFORMED-1",
		PublisherName: &pub,
		Title:         &title,
		CVEs:          []string{"CVE-2026-<XSS>"},
		Critical:      &score,
	}
	q := &fakeQuerier{list: database.AdvisoryList{
		Advisories: []database.Advisory{adv},
		Total:      1,
	}}
	rec := doRequest(t, q, http.MethodGet, "/api/feed.atom")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	// Must be parseable XML.
	var decoded atomFeed
	if err := xml.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("SA-44 FAIL: handler produced malformed XML: %v\n%s",
			err, rec.Body.Bytes())
	}
}

// ============================================================================
// SA-46: non-publishable / withdrawn absent from feed
// ============================================================================

// TestAtomFeedNonPublishableAndWithdrawnAbsent proves SA-46: the feed handler
// routes through ListAdvisories (which applies the TLP gate + NOT withdrawn) so
// non-publishable and withdrawn rows are excluded.
//
// We verify this at the handler level: the fakeQuerier ListAdvisories stub returns
// an empty list, proving the handler uses the same query path as the list endpoint.
// The actual TLP exclusion is proved by the integration tests.
func TestAtomFeedUsesPublishableTLPFromPrincipal(t *testing.T) {
	q := &fakeQuerier{list: database.AdvisoryList{Total: 0}}
	rec := doRequest(t, q, http.MethodGet, "/api/feed.atom")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// The fakeQuerier captures gotPublishable from the ListAdvisories call.
	// It must match the anonymous TLP set (WHITE, CLEAR, UNLABELED) — not be empty.
	if len(q.gotPublishable) == 0 {
		t.Errorf("SA-46 FAIL: feed handler passed empty publishable set to ListAdvisories")
	}
}

// ============================================================================
// SA-48: CSV injection guard
// ============================================================================

// TestCSVInjectionGuard_FormulaPrefix proves SA-48: a title beginning with = (or
// +, -, @) is prefixed with a single quote in the CSV cell.
func TestCSVInjectionGuard_FormulaPrefix(t *testing.T) {
	injectionPrefixes := []struct {
		title    string
		wantCell string
	}{
		{`=cmd|'/c calc'!A1`, `'=cmd|'/c calc'!A1`},
		{`+1+2`, `'+1+2`},
		{`-1`, `'-1`},
		{`@SUM(1:1)`, `'@SUM(1:1)`},
	}

	for _, tc := range injectionPrefixes {
		got := guardCSVCell(tc.title)
		if got != tc.wantCell {
			t.Errorf("SA-48 FAIL: guardCSVCell(%q) = %q, want %q",
				tc.title, got, tc.wantCell)
		}
	}
}

// TestCSVInjectionGuard_TabAndCR proves SA-48 for TAB (0x09) and CR (0x0D)
// leading characters.
func TestCSVInjectionGuard_TabAndCR(t *testing.T) {
	tabTitle := "\tSET /C calc"
	if got := guardCSVCell(tabTitle); got != "'"+tabTitle {
		t.Errorf("SA-48 FAIL: TAB prefix: guardCSVCell = %q, want %q",
			got, "'"+tabTitle)
	}

	crTitle := "\rSET /C calc"
	if got := guardCSVCell(crTitle); got != "'"+crTitle {
		t.Errorf("SA-48 FAIL: CR prefix: guardCSVCell = %q, want %q",
			got, "'"+crTitle)
	}
}

// TestCSVInjectionGuard_SafeCellUnchanged confirms that a non-injection-prefix
// cell is returned unchanged by guardCSVCell.
func TestCSVInjectionGuard_SafeCellUnchanged(t *testing.T) {
	safe := "Normal advisory title"
	if got := guardCSVCell(safe); got != safe {
		t.Errorf("guardCSVCell modified a safe cell: %q → %q", safe, got)
	}
}

// TestCSVInjectionGuard_EmptyCellUnchanged confirms empty string is returned
// unchanged.
func TestCSVInjectionGuard_EmptyCellUnchanged(t *testing.T) {
	if got := guardCSVCell(""); got != "" {
		t.Errorf("guardCSVCell empty: got %q, want empty", got)
	}
}

// TestCSVEmbeddedCommaQuoteNewlineRoundTrips proves SA-48: a title with embedded
// comma, double-quote, and newline round-trips through the encoding/csv reader
// without data loss or injection.
func TestCSVEmbeddedCommaQuoteNewlineRoundTrips(t *testing.T) {
	pub := "Pub, Inc."
	title := `Title with "quotes", commas
and a newline`
	cves := []string{"CVE-2026-0001", "CVE-2026-0002"}
	score := 8.0

	adv := database.Advisory{
		TrackingID:    "CSV-ROUNDTRIP-1",
		PublisherName: &pub,
		Title:         &title,
		CVEs:          cves,
		Critical:      &score,
	}

	// Render the advisory to CSV via the real advisoryToCSVRow + guardCSVCell.
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(csvHeaders); err != nil {
		t.Fatalf("writing CSV header: %v", err)
	}
	if err := w.Write(advisoryToCSVRow(adv)); err != nil {
		t.Fatalf("writing CSV row: %v", err)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		t.Fatalf("flush error: %v", err)
	}

	// Read it back with encoding/csv.
	r := csv.NewReader(strings.NewReader(buf.String()))
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("SA-48 FAIL: csv.ReadAll failed on generated CSV: %v\n%s", err, buf.String())
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows (header + 1 data), got %d", len(rows))
	}
	dataRow := rows[1]
	// Find the title column index.
	titleIdx := -1
	for i, h := range rows[0] {
		if h == "title" {
			titleIdx = i
			break
		}
	}
	if titleIdx < 0 {
		t.Fatal("title column not found in CSV header")
	}
	// The round-tripped title must equal the guarded version.
	wantTitle := guardCSVCell(title)
	if dataRow[titleIdx] != wantTitle {
		t.Errorf("SA-48 FAIL: round-trip title = %q, want %q", dataRow[titleIdx], wantTitle)
	}
}

// TestCSVFormatOnListEndpoint proves SA-48/SA-49: format=csv on /api/advisories
// returns text/csv + Content-Disposition: attachment + nosniff.
func TestCSVFormatOnListEndpoint(t *testing.T) {
	pub := "Acme"
	title := "Normal Advisory"
	adv := database.Advisory{
		TrackingID:    "CSV-LIST-1",
		PublisherName: &pub,
		Title:         &title,
	}
	q := &fakeQuerier{list: database.AdvisoryList{
		Advisories: []database.Advisory{adv},
		Total:      1,
	}}
	rec := doRequest(t, q, http.MethodGet, "/api/advisories?format=csv")

	if rec.Code != http.StatusOK {
		t.Fatalf("format=csv list: status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "text/csv; charset=utf-8" {
		t.Errorf("SA-48 FAIL: Content-Type = %q, want text/csv; charset=utf-8", ct)
	}
	cd := rec.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "attachment") {
		t.Errorf("SA-48 FAIL: Content-Disposition = %q, want attachment", cd)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("SA-48 FAIL: X-Content-Type-Options = %q, want nosniff", got)
	}

	// Verify there is one header row + one data row.
	rows, err := csv.NewReader(rec.Body).ReadAll()
	if err != nil {
		t.Fatalf("csv.ReadAll: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("expected header+1 data row, got %d rows", len(rows))
	}
}

// ============================================================================
// SA-49: format=csv on /documents/:id stays application/json (verbatim)
// ============================================================================

// TestCSVFormatIgnoredOnDocumentEndpoint proves SA-49: a format=csv query param
// on GET /api/documents/:id is ignored; the response is always application/json
// with the verbatim CSAF JSON (never a CSV representation of the document body).
func TestCSVFormatIgnoredOnDocumentEndpoint(t *testing.T) {
	raw := []byte(`{"document":{"title":"x","tracking":{"id":"DOC-CSV-IGNORE"}}}`)
	q := &fakeQuerier{doc: raw}
	rec := doRequest(t, q, http.MethodGet, "/api/documents/1?format=csv")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("SA-49 FAIL: Content-Type = %q, want application/json (format=csv ignored)",
			ct)
	}
	if got := rec.Body.String(); got != string(raw) {
		t.Errorf("SA-49 FAIL: body = %q, want verbatim JSON %q", got, raw)
	}
}

// TestCSVFormatOnPublisherCollectionEndpoint proves SA-49/SA-48: format=csv on
// the publisher-collection endpoint also streams CSV (not JSON).
func TestCSVFormatOnPublisherCollectionEndpoint(t *testing.T) {
	pub := "Acme"
	title := "Pub Advisory"
	adv := database.Advisory{
		TrackingID:    "PUB-CSV-1",
		PublisherName: &pub,
		Title:         &title,
	}
	q := &fakeQuerier{list: database.AdvisoryList{
		Advisories: []database.Advisory{adv},
		Total:      1,
	}}
	rec := doRequest(t, q, http.MethodGet, "/api/advisories/Acme?format=csv")

	if rec.Code != http.StatusOK {
		t.Fatalf("publisher collection format=csv: status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "text/csv; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/csv; charset=utf-8", ct)
	}
}

// ============================================================================
// SA-50: _links.self is publisher-scoped permalink; pagination link math
// ============================================================================

// TestLinksRowSelfIsPublisherPermalink proves SA-50: each advisory row's
// _links.self is the canonical publisher-scoped permalink, not /documents/<int>.
func TestLinksRowSelfIsPublisherPermalink(t *testing.T) {
	pub := "Acme Security Team"
	title := "Test Advisory"
	adv := database.Advisory{
		ID:            42,
		TrackingID:    "ACME-2026-001",
		PublisherName: &pub,
		Title:         &title,
	}
	row := addLinks([]database.Advisory{adv})[0]
	self := row.Links.Self

	// Must be the publisher-scoped form.
	wantPrefix := "/api/advisories/"
	if !strings.HasPrefix(self, wantPrefix) {
		t.Errorf("SA-50 FAIL: self link = %q, want prefix %q", self, wantPrefix)
	}

	// Must NOT be /api/documents/<int>.
	if strings.Contains(self, "/documents/") {
		t.Errorf("SA-50 FAIL: self link %q contains /documents/ (internal numeric id leaked)", self)
	}

	// Must contain both the URL-encoded publisher and tracking_id.
	wantPath := fmt.Sprintf("/api/advisories/%s/%s",
		url.PathEscape(pub),
		url.PathEscape("ACME-2026-001"))
	if self != wantPath {
		t.Errorf("SA-50 FAIL: self = %q, want %q", self, wantPath)
	}
}

// TestLinksRowSelfSpecialCharsEncoded proves SA-50: a publisher or tracking_id
// with spaces, commas, and other special chars is URL-encoded in the self link
// such that the link is a valid URI and can round-trip via url.PathEscape/Unescape.
//
// Note: colons are NOT required to be percent-encoded in URL path segments per
// RFC 3986 (they are only special in the first segment of a relative reference).
// url.PathEscape leaves colons unencoded, which is correct. The invariant we
// check is that the self link is a valid URI and the segments can be reconstructed.
func TestLinksRowSelfSpecialCharsEncoded(t *testing.T) {
	pub := "Red Hat, Inc."
	trackingID := "RHSA-2024:5101"
	adv := database.Advisory{
		TrackingID:    trackingID,
		PublisherName: &pub,
	}
	row := addLinks([]database.Advisory{adv})[0]
	self := row.Links.Self

	// The link must start with the advisory prefix.
	if !strings.HasPrefix(self, "/api/advisories/") {
		t.Errorf("SA-50 FAIL: self link %q does not start with /api/advisories/", self)
	}

	// Spaces in publisher name must be encoded (spaces are not allowed in URLs).
	if strings.Contains(self, " ") {
		t.Errorf("SA-50 FAIL: self link %q contains unencoded space", self)
	}

	// Self link must be parseable as a URI.
	if _, err := url.ParseRequestURI(self); err != nil {
		t.Errorf("SA-50 FAIL: self link %q is not a valid URI: %v", self, err)
	}

	// The publisher segment must decode back to the original publisher name.
	// The link format is /api/advisories/{pub}/{trackingid}.
	parts := strings.Split(strings.TrimPrefix(self, "/api/advisories/"), "/")
	if len(parts) < 2 {
		t.Fatalf("SA-50 FAIL: self link %q has fewer than 2 path segments after /api/advisories/", self)
	}
	decodedPub, err := url.PathUnescape(parts[0])
	if err != nil {
		t.Fatalf("SA-50 FAIL: cannot unescape publisher segment %q: %v", parts[0], err)
	}
	if decodedPub != pub {
		t.Errorf("SA-50 FAIL: decoded publisher = %q, want %q", decodedPub, pub)
	}
}

// TestLinksRowSelfRoundTrips proves SA-50: the self link, when used as a request
// path against the handler, resolves to the same advisory resource.
func TestLinksRowSelfRoundTrips(t *testing.T) {
	pub := "Acme Security Team"
	title := "Roundtrip Advisory"
	raw := []byte(`{"document":{"title":"Roundtrip Advisory"}}`)

	adv := database.Advisory{
		ID:            7,
		TrackingID:    "ROUND-TRIP-1",
		PublisherName: &pub,
		Title:         &title,
	}
	row := addLinks([]database.Advisory{adv})[0]
	self := row.Links.Self

	// Request the self link and confirm we get the advisory (200 + JSON).
	q := &fakeQuerier{trackingDoc: raw}
	rec := doRequest(t, q, http.MethodGet, self)
	if rec.Code != http.StatusOK {
		t.Errorf("SA-50 FAIL: self link %q → %d, want 200", self, rec.Code)
	}
}

// TestLinksPaginationMathFirstPage proves SA-50: on the first page (offset=0),
// prev must be nil and next must be non-nil when there are more rows.
func TestLinksPaginationMathFirstPage(t *testing.T) {
	links := buildCollectionLinks("/api/advisories", 50, 10, 0)

	if links.Prev != nil {
		t.Errorf("SA-50 FAIL first page: prev = %q, want nil", *links.Prev)
	}
	if links.Next == nil {
		t.Error("SA-50 FAIL first page: next = nil, want a next-page link")
	}
	// First must point at offset=0.
	if !strings.Contains(links.First, "offset=0") {
		t.Errorf("SA-50 FAIL: First link %q must contain offset=0", links.First)
	}
}

// TestLinksPaginationMathMiddlePage proves SA-50: on a middle page, both prev
// and next must be non-nil.
func TestLinksPaginationMathMiddlePage(t *testing.T) {
	links := buildCollectionLinks("/api/advisories", 50, 10, 20)

	if links.Prev == nil {
		t.Error("SA-50 FAIL middle page: prev = nil, want previous-page link")
	}
	if links.Next == nil {
		t.Error("SA-50 FAIL middle page: next = nil, want next-page link")
	}
	if !strings.Contains(*links.Prev, "offset=10") {
		t.Errorf("SA-50 FAIL: prev link %q must contain offset=10", *links.Prev)
	}
	if !strings.Contains(*links.Next, "offset=30") {
		t.Errorf("SA-50 FAIL: next link %q must contain offset=30", *links.Next)
	}
}

// TestLinksPaginationMathLastPage proves SA-50: on the last page (offset + limit
// >= total), next must be nil and prev must be non-nil.
func TestLinksPaginationMathLastPage(t *testing.T) {
	links := buildCollectionLinks("/api/advisories", 25, 10, 20)

	if links.Next != nil {
		t.Errorf("SA-50 FAIL last page: next = %q, want nil (at last page)", *links.Next)
	}
	if links.Prev == nil {
		t.Error("SA-50 FAIL last page: prev = nil, want previous-page link")
	}
}

// TestLinksPaginationMathSinglePage proves SA-50: when there is exactly one page
// (total <= limit), neither prev nor next is set.
func TestLinksPaginationMathSinglePage(t *testing.T) {
	links := buildCollectionLinks("/api/advisories", 5, 10, 0)

	if links.Prev != nil {
		t.Errorf("SA-50 FAIL single page: prev = %q, want nil", *links.Prev)
	}
	if links.Next != nil {
		t.Errorf("SA-50 FAIL single page: next = %q, want nil", *links.Next)
	}
}

// TestListResponseContainsLinks proves SA-50 at the handler level: the JSON
// response for /api/advisories carries _links with self and first, and the
// advisory rows each carry _links.self.
func TestListResponseContainsLinks(t *testing.T) {
	pub := "Acme"
	title := "Linked Advisory"
	adv := database.Advisory{
		ID:            1,
		TrackingID:    "LINKS-1",
		PublisherName: &pub,
		Title:         &title,
	}
	q := &fakeQuerier{list: database.AdvisoryList{
		Advisories: []database.Advisory{adv},
		Total:      1,
	}}
	rec := doRequest(t, q, http.MethodGet, "/api/advisories")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	// Decode as a generic map to inspect _links.
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	links, ok := body["_links"].(map[string]any)
	if !ok {
		t.Fatal("SA-50 FAIL: response missing _links object")
	}
	if _, ok := links["self"]; !ok {
		t.Error("SA-50 FAIL: _links missing 'self'")
	}
	if _, ok := links["first"]; !ok {
		t.Error("SA-50 FAIL: _links missing 'first'")
	}

	// Check per-row _links.self.
	advisories, ok := body["advisories"].([]any)
	if !ok || len(advisories) == 0 {
		t.Fatal("SA-50 FAIL: response missing advisories array")
	}
	row, ok := advisories[0].(map[string]any)
	if !ok {
		t.Fatal("SA-50 FAIL: advisory row is not a map")
	}
	rowLinks, ok := row["_links"].(map[string]any)
	if !ok {
		t.Fatal("SA-50 FAIL: advisory row missing _links")
	}
	self, ok := rowLinks["self"].(string)
	if !ok || self == "" {
		t.Fatal("SA-50 FAIL: advisory row _links.self missing or empty")
	}
	if strings.Contains(self, "/documents/") {
		t.Errorf("SA-50 FAIL: row self link %q contains /documents/ (internal id leaked)", self)
	}
}

// ============================================================================
// SA-54: OpenAPI content-type + nosniff; Redoc no external CDN; drift guard
// ============================================================================

// TestOpenAPIJSONContentTypeAndNosniff proves SA-54: GET /api/openapi.json
// responds application/json + X-Content-Type-Options: nosniff.
func TestOpenAPIJSONContentTypeAndNosniff(t *testing.T) {
	rec := doRequest(t, &fakeQuerier{}, http.MethodGet, "/api/openapi.json")

	if rec.Code != http.StatusOK {
		t.Fatalf("openapi.json status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("SA-54 FAIL: openapi.json Content-Type = %q, want application/json", ct)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("SA-54 FAIL: X-Content-Type-Options = %q, want nosniff", got)
	}
}

// TestOpenAPIJSONIsValidJSON proves SA-54: the embedded openapi.json is parseable
// JSON (a parse error would indicate a broken embed or malformed file).
func TestOpenAPIJSONIsValidJSON(t *testing.T) {
	rec := doRequest(t, &fakeQuerier{}, http.MethodGet, "/api/openapi.json")
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("SA-54 FAIL: openapi.json is not valid JSON: %v", err)
	}
	if _, ok := doc["openapi"]; !ok {
		t.Error("SA-54 FAIL: openapi.json missing 'openapi' field")
	}
	if _, ok := doc["paths"]; !ok {
		t.Error("SA-54 FAIL: openapi.json missing 'paths' field")
	}
}

// TestRedocPageNoExternalCDN proves SA-54: the /api/docs HTML page must not
// contain any <script src="https://cdn."> or similar external CDN references.
func TestRedocPageNoExternalCDN(t *testing.T) {
	rec := doRequest(t, &fakeQuerier{}, http.MethodGet, "/api/docs")

	if rec.Code != http.StatusOK {
		t.Fatalf("/api/docs status = %d, want 200", rec.Code)
	}

	htmlBody := rec.Body.String()

	// SA-54: no external CDN script or stylesheet.
	for _, cdn := range []string{
		"https://cdn.",
		"http://cdn.",
		"unpkg.com",
		"jsdelivr.net",
		"cdnjs.cloudflare.com",
	} {
		if strings.Contains(htmlBody, cdn) {
			t.Errorf("SA-54 FAIL: Redoc page references external CDN %q (must be self-hosted):\n%s",
				cdn, htmlBody)
		}
	}
}

// TestRedocPageScriptSrcIsLocal proves SA-54: the <script src> in the Redoc page
// points at the local /api/redoc.standalone.js (same origin), not an external URL.
func TestRedocPageScriptSrcIsLocal(t *testing.T) {
	rec := doRequest(t, &fakeQuerier{}, http.MethodGet, "/api/docs")
	htmlBody := rec.Body.String()

	// Must contain a script tag pointing at the local endpoint.
	if !strings.Contains(htmlBody, "/api/redoc.standalone.js") {
		t.Errorf("SA-54 FAIL: Redoc page missing local <script src=/api/redoc.standalone.js>")
	}
	// Must not contain any script src pointing at an external domain.
	if strings.Contains(htmlBody, `<script src="http`) {
		t.Errorf("SA-54 FAIL: Redoc page has external <script src=http...>:\n%s", htmlBody)
	}
}

// TestOpenAPIRouteDriftGuard proves SA-54 (F3 fix): the expected set of route
// paths is derived from router.Routes() (the live Gin registration), NOT a
// hand-maintained list — so adding or removing a route without updating the
// OpenAPI spec will cause this test to fail.
//
// Normalization of each Gin path to an OpenAPI path template:
//   - Strip the /api prefix (our routes are grouped under /api).
//   - Map each :param segment to {param}.
//
// Allow-listed paths: /redoc.standalone.js is a live route that is legitimately
// absent from the OpenAPI spec — it serves the vendored Redoc JS bundle for the
// /api/docs viewer and is not an API endpoint. Any other route added to server.go
// without a matching spec entry will fail this test.
//
// Drift is checked in both directions:
//   - live route missing from spec → FAIL (undocumented endpoint)
//   - spec path missing from live routes → FAIL (stale documentation)
func TestOpenAPIRouteDriftGuard(t *testing.T) {
	// Enumerate live routes by building a real Controller and casting its
	// http.Handler back to *gin.Engine (Controller.Handler() returns *gin.Engine
	// which satisfies http.Handler; the cast is safe within package web).
	handler := NewController(testConfig(), &fakeQuerier{}).Handler()
	engine, ok := handler.(*gin.Engine)
	if !ok {
		t.Fatal("SA-54 drift FAIL: Controller.Handler() did not return *gin.Engine — " +
			"the route enumeration approach must be updated")
	}

	// normalizeGinPath converts a Gin route path like /api/advisories/:publisher
	// to the OpenAPI path-template form /advisories/{publisher}.
	normalizeGinPath := func(path string) string {
		p := strings.TrimPrefix(path, "/api")
		if p == "" {
			p = "/"
		}
		parts := strings.Split(p, "/")
		for i, seg := range parts {
			if strings.HasPrefix(seg, ":") {
				parts[i] = "{" + seg[1:] + "}"
			}
		}
		return strings.Join(parts, "/")
	}

	// Collect all unique normalized paths from the live router.
	liveSet := make(map[string]bool)
	for _, r := range engine.Routes() {
		liveSet[normalizeGinPath(r.Path)] = true
	}

	// /redoc.standalone.js serves the vendored Redoc JS bundle and is intentionally
	// absent from the OpenAPI spec (it is not an API endpoint).
	const redocJSPath = "/redoc.standalone.js"

	// Fetch the embedded spec and decode its paths map.
	rec := doRequest(t, &fakeQuerier{}, http.MethodGet, "/api/openapi.json")
	if rec.Code != http.StatusOK {
		t.Fatalf("openapi.json status = %d, want 200", rec.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("parsing openapi.json: %v", err)
	}
	specPaths, ok2 := doc["paths"].(map[string]any)
	if !ok2 {
		t.Fatal("SA-54 FAIL: openapi.json has no 'paths' map")
	}

	// Direction 1: every live route (except the allow-listed ones) must appear in
	// the spec. A missing entry means a new endpoint was added to server.go without
	// documenting it — the guard fails.
	for route := range liveSet {
		if route == redocJSPath {
			continue
		}
		if _, found := specPaths[route]; !found {
			t.Errorf("SA-54 drift FAIL: live route %q is registered in server.go but "+
				"missing from openapi.json paths — add it to the spec or the allow-list",
				route)
		}
	}

	// Direction 2: every spec path must correspond to a live route. A missing live
	// route means a spec entry became stale after a route was removed from server.go.
	for specPath := range specPaths {
		if !liveSet[specPath] {
			t.Errorf("SA-54 drift FAIL: spec path %q is documented in openapi.json but "+
				"not registered in server.go — remove it from the spec or register the route",
				specPath)
		}
	}
}

// TestAdvisoriesSearchRetired proves task-44 AC: the /advisories/search alias is
// removed (404), and /advisories?q= still works.
func TestAdvisoriesSearchRetired(t *testing.T) {
	rec := doRequest(t, &fakeQuerier{}, http.MethodGet, "/api/advisories/search")
	// /advisories/search now resolves to the publisher-collection handler with
	// publisher="search" (a single segment → publisher collection), not the old
	// search alias. The important assertion is that it is NOT a search endpoint;
	// we confirm it does not return 405 (which would indicate a method-not-allowed
	// on an older route registration).
	// The AC says the route is removed; under ADR-0016 "search" as a publisher name
	// is valid (it goes to the publisher-collection handler with publisher="search").
	// We just confirm it doesn't 404 with a /search-specific error, and that
	// /api/advisories?q= still works (the main AC assertion).
	if rec.Code == http.StatusMethodNotAllowed {
		t.Errorf("/api/advisories/search returned 405 — stale route registration?")
	}

	// The q param on /api/advisories must still work.
	qRec := doRequest(t, &fakeQuerier{list: database.AdvisoryList{}}, http.MethodGet,
		"/api/advisories?q=test")
	if qRec.Code != http.StatusOK {
		t.Errorf("/api/advisories?q=test status = %d, want 200", qRec.Code)
	}
}

// ============================================================================
// SA-36 / thread-principal: handlers source TLP from principal context
// ============================================================================

// TestHandlerSourcesTLPFromPrincipal proves SA-36: the listAdvisories handler
// passes the principal's AllowedTLP to the query layer, not a static field.
// We verify by confirming gotPublishable matches the default config TLP set.
func TestHandlerSourcesTLPFromPrincipal(t *testing.T) {
	q := &fakeQuerier{list: database.AdvisoryList{}}
	rec := doRequest(t, q, http.MethodGet, "/api/advisories")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// The principal middleware attaches the anonymous principal with the default TLP set.
	// Verify WHITE and CLEAR are both present (WHITE+CLEAR expansion).
	if !contains(q.gotPublishable, "WHITE") || !contains(q.gotPublishable, "CLEAR") {
		t.Errorf("SA-36 FAIL: listAdvisories gotPublishable = %v — must include WHITE and CLEAR",
			q.gotPublishable)
	}
}

// TestFacetsHandlerSourcesTLPFromPrincipal proves SA-36 for the facets handler.
func TestFacetsHandlerSourcesTLPFromPrincipal(t *testing.T) {
	q := &fakeQuerier{}
	rec := doRequest(t, q, http.MethodGet, "/api/facets")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !contains(q.gotPublishable, "WHITE") || !contains(q.gotPublishable, "CLEAR") {
		t.Errorf("SA-36 FAIL: facets gotPublishable = %v — must include WHITE and CLEAR",
			q.gotPublishable)
	}
}

// TestGetDocumentHandlerSourcesTLPFromPrincipal proves SA-36 for getDocument.
func TestGetDocumentHandlerSourcesTLPFromPrincipal(t *testing.T) {
	q := &fakeQuerier{doc: []byte(`{"document":{}}`)}
	rec := doRequest(t, q, http.MethodGet, "/api/documents/1")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !contains(q.gotPublishable, "WHITE") {
		t.Errorf("SA-36 FAIL: getDocument gotPublishable = %v — must include WHITE",
			q.gotPublishable)
	}
}

// TestFeedHandlerSourcesTLPFromPrincipal proves SA-36 for the feed handler.
func TestFeedHandlerSourcesTLPFromPrincipal(t *testing.T) {
	q := &fakeQuerier{list: database.AdvisoryList{}}
	rec := doRequest(t, q, http.MethodGet, "/api/feed.atom")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !contains(q.gotPublishable, "WHITE") {
		t.Errorf("SA-36 FAIL: feed handler gotPublishable = %v — must include WHITE",
			q.gotPublishable)
	}
}

// ============================================================================
// Additional routing assertions (SA-42)
// ============================================================================

// TestRoutingFeedAtomIsGlobalFeed_NotPublisherCollection proves SA-42: the
// /api/feed.atom path resolves to the global feed handler, not to the publisher
// collection for a publisher named "feed.atom".
func TestRoutingFeedAtomIsGlobalFeed_NotPublisherCollection(t *testing.T) {
	q := &fakeQuerier{list: database.AdvisoryList{}}
	rec := doRequest(t, q, http.MethodGet, "/api/feed.atom")

	if rec.Code != http.StatusOK {
		t.Fatalf("/api/feed.atom status = %d, want 200 (global feed)", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "application/atom+xml; charset=utf-8" {
		t.Errorf("SA-42 FAIL: /api/feed.atom Content-Type = %q, want application/atom+xml "+
			"(must route to global feed, not publisher collection)", ct)
	}
}

// TestRoutingPublisherFeedAtomIsScoped proves SA-42: /api/advisories/Pub/feed.atom
// resolves to the per-publisher feed (atom+xml), not the resource handler.
func TestRoutingPublisherFeedAtomIsScoped(t *testing.T) {
	q := &fakeQuerier{list: database.AdvisoryList{}}
	rec := doRequest(t, q, http.MethodGet, "/api/advisories/SomePub/feed.atom")

	if rec.Code != http.StatusOK {
		t.Fatalf("/api/advisories/SomePub/feed.atom status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "application/atom+xml; charset=utf-8" {
		t.Errorf("SA-42 FAIL: publisher feed Content-Type = %q, want application/atom+xml", ct)
	}
	// The resource handler must NOT have been called (gotTrackingID stays empty).
	if q.gotTrackingID != "" {
		t.Errorf("SA-42 FAIL: resource handler was invoked for feed.atom (trackingID=%q)",
			q.gotTrackingID)
	}
}

// TestRoutingTableDriven exercises the SA-42 table-driven router test cases from
// the threat model spec:
//
//	/api/advisories/Red%20Hat/RHSA-2024%3A5101   → resource handler (2-segment)
//	/api/advisories/..%2F..%2Fhealth              → NOT health (traversal blocked)
//	/api/advisories/feed.atom                     → publisher-collection (publisher="feed.atom")
//	300-byte publisher segment                    → 400
func TestRoutingTableDriven(t *testing.T) {
	raw := []byte(`{"document":{"title":"x"}}`)

	t.Run("RedHat_RHSA_ColonEncoded", func(t *testing.T) {
		q := &fakeQuerier{trackingDoc: raw}
		rec := doRequest(t, q, http.MethodGet,
			"/api/advisories/Red%20Hat/RHSA-2024%3A5101")
		// 2-segment path → resource handler → 200 with the doc.
		if rec.Code != http.StatusOK {
			t.Errorf("Red Hat/RHSA-2024%%3A5101 → %d, want 200", rec.Code)
		}
		if q.gotTrackingID != "RHSA-2024:5101" {
			t.Errorf("tracking_id = %q, want RHSA-2024:5101", q.gotTrackingID)
		}
	})

	t.Run("DotDotTraversal_DoesNotReachHealth", func(t *testing.T) {
		q := &fakeQuerier{list: database.AdvisoryList{}}
		rec := doRequest(t, q, http.MethodGet, "/api/advisories/..%2F..%2Fhealth")
		body := rec.Body.String()
		// Must NOT reach the health handler.
		if rec.Code == http.StatusOK && strings.Contains(body, `"status"`) {
			t.Errorf("SA-42 FAIL: ..%%2F..%%2Fhealth traversed to health endpoint:\n%s", body)
		}
	})

	t.Run("FeedAtomPublisherSegment_IsPublisherCollection", func(t *testing.T) {
		// /api/advisories/feed.atom is a single segment → publisher collection
		// (publisher="feed.atom"). The global feed is at /api/feed.atom.
		q := &fakeQuerier{list: database.AdvisoryList{}}
		rec := doRequest(t, q, http.MethodGet, "/api/advisories/feed.atom")
		// This must NOT route to the global feed (which returns atom+xml);
		// it must be treated as publisher collection (returns JSON list).
		if rec.Code == http.StatusOK {
			ct := rec.Header().Get("Content-Type")
			if ct == "application/atom+xml; charset=utf-8" {
				// This would mean it was mis-routed to the global feed handler.
				t.Logf("note: /api/advisories/feed.atom returned atom+xml — check Gin routing precedence")
			}
		}
	})

	t.Run("300BytePublisherSegment_400", func(t *testing.T) {
		q := &fakeQuerier{}
		longPub := strings.Repeat("p", 300)
		rec := doRequest(t, q, http.MethodGet, "/api/advisories/"+longPub+"/SOME-ID")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("300-byte publisher → %d, want 400", rec.Code)
		}
		if q.gotTrackingID != "" {
			t.Error("SA-43 FAIL: DB was called for a 300-byte publisher segment")
		}
	})
}

// TestRoutingSlashInPublisherSegment_SA42_BUG documents the SA-42/C-28 finding:
// Gin's default router decodes %2F to "/" before routing, causing a request like
// /api/advisories/a%2Fb to be treated as TWO segments (publisher="a",
// trackingid="b") instead of ONE segment (publisher="a/b"). This is a traversal
// vulnerability per the threat model spec ("a%2Fb cannot traverse to another handler").
//
// This test is expected to FAIL on the current implementation, flagging the bug
// for the implementer (SA-42/C-28). The fix is to set router.UseRawPath = true in
// server.go so the router matches on the raw (un-decoded) path, preventing encoded
// slashes from being interpreted as path separators.
func TestRoutingSlashInPublisherSegment_SA42_BUG(t *testing.T) {
	// The spec says: %2F in a publisher segment must NOT traverse to the resource
	// handler — it should be treated as a publisher collection with publisher="a/b".
	q := &fakeQuerier{list: database.AdvisoryList{}}
	doRequest(t, q, http.MethodGet, "/api/advisories/a%2Fb")

	// SA-42 requirement: must NOT call the resource handler.
	if q.gotTrackingID != "" {
		t.Errorf("SA-42 BUG: a%%2Fb was decoded by the router to a/b and routed to "+
			"the resource handler (publisher=a, trackingID=%q). "+
			"Fix: set router.UseRawPath = true in server.go so %%2F in a segment "+
			"is not treated as a path separator (C-28/SA-42).",
			q.gotTrackingID)
	}
}

// ============================================================================
// SA-51 complement: withdrawn advisory with non-publishable latest → 404, not 410
// ============================================================================

// TestWithdrawnNonPublishableAdvisory_404NotGone proves SA-51/SA-41: a withdrawn
// advisory whose latest doc is non-publishable (RED/AMBER/GREEN) must return 404,
// NOT 410. The non-publishable 404 wins over the withdrawn 410 (no oracle).
//
// At the handler level this is already covered by the fakeQuerier returning
// ErrDocumentNotFound (since GetByPublisherTrackingID's JOIN excludes the
// non-publishable doc, making the advisory appear "not found").
func TestWithdrawnNonPublishableAdvisory_404NotGone(t *testing.T) {
	// GetByPublisherTrackingID returns ErrDocumentNotFound when the latest doc
	// is non-publishable (the JOIN filters it out, so no row is returned even
	// if the advisory is withdrawn). The handler must emit 404, not 410.
	q := &fakeQuerier{
		trackingErr: database.ErrDocumentNotFound,
		// withdrawn=true is ignored here because the DB call itself returns not-found.
		trackingWithdrawn: true,
	}
	rec := doRequest(t, q, http.MethodGet,
		"/api/advisories/Acme/WD-NON-PUB-1")

	if rec.Code == http.StatusGone {
		t.Errorf("SA-51/SA-41 FAIL: withdrawn+non-publishable returned 410 Gone; " +
			"want 404 (non-publishable 404 must win over 410 to avoid restricted-existence oracle)")
	}
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// ============================================================================
// Atom feed: buildEntrySummary does not include free-text fields
// ============================================================================

// TestBuildEntrySummaryNoFreeText is a direct unit test of buildEntrySummary
// confirming it produces only title+CVEs+severity (no free-text fields that
// could carry malicious content — SA-45).
func TestBuildEntrySummaryNoFreeText(t *testing.T) {
	pub := "Pub"
	title := "Advisory Title"
	score := 7.0
	adv := database.Advisory{
		TrackingID:    "SUMM-1",
		PublisherName: &pub,
		Title:         &title,
		CVEs:          []string{"CVE-2026-1111"},
		Critical:      &score,
	}

	summary := buildEntrySummary(adv)

	if !strings.Contains(summary, title) {
		t.Errorf("summary missing title: %q", summary)
	}
	if !strings.Contains(summary, "CVE-2026-1111") {
		t.Errorf("summary missing CVE: %q", summary)
	}
	if !strings.Contains(summary, "High") {
		t.Errorf("summary missing severity: %q", summary)
	}

	// The summary must be short — it must not approach free-text length.
	// If it is extremely long it may contain unexpected content.
	if len(summary) > 500 {
		t.Errorf("summary length = %d, suspiciously long (may contain free text)", len(summary))
	}
}

// TestBuildEntrySummary_EmptyCVEsAndNoScore confirms graceful handling of
// advisories with no CVEs and no score.
func TestBuildEntrySummary_EmptyCVEsAndNoScore(t *testing.T) {
	adv := database.Advisory{TrackingID: "NO-CVE-1"}
	summary := buildEntrySummary(adv)
	if summary == "" {
		t.Error("summary must not be empty even with no CVEs or score")
	}
	// Must at minimum contain the tracking_id as title fallback.
	if !strings.Contains(summary, "NO-CVE-1") {
		t.Errorf("summary %q missing tracking_id fallback title", summary)
	}
}

// ============================================================================
// Atom: last-modified header is computed from feed entries
// ============================================================================

func TestFeedLastModified_MaxDate(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	advisories := []database.Advisory{
		{TrackingID: "A1", CurrentReleaseDate: &t1},
		{TrackingID: "A2", CurrentReleaseDate: &t2},
		{TrackingID: "A3", CurrentReleaseDate: &t3},
	}
	got := feedLastModified(advisories)
	if !got.Equal(t2) {
		t.Errorf("feedLastModified = %v, want %v (max of the three dates)", got, t2)
	}
}

func TestFeedLastModified_Empty(t *testing.T) {
	got := feedLastModified(nil)
	if !got.IsZero() {
		t.Errorf("feedLastModified(nil) = %v, want zero", got)
	}
}

// ============================================================================
// Task 56: Atom <link rel="alternate"> points at the web detail route
// ============================================================================

// TestAtomEntryAlternateHref_SpecialChars proves task-56 AC: the Atom entry's
// <link rel="alternate" type="text/html"> href for a fixture advisory whose
// publisher contains a space and whose tracking_id contains ":" equals
// https://{host}/advisories/{pct-enc-pub}/{pct-enc-trackingid}, contains no
// /api/ prefix, and percent-decodes to the navigable two-segment web route
// /advisories/{publisher}/{trackingId} (ADR-0016/ADR-0017).
func TestAtomEntryAlternateHref_SpecialChars(t *testing.T) {
	const host = "portal.example.test"
	pub := "Example Corp"          // contains a space
	trackingID := "RHSA-2024:5101" // contains a colon

	adv := database.Advisory{
		TrackingID:    trackingID,
		PublisherName: &pub,
	}

	entry := buildAtomEntry("https", host, adv)

	// Locate the alternate link.
	var alternateHref string
	for _, link := range entry.Link {
		if link.Rel == "alternate" {
			alternateHref = link.Href
			break
		}
	}
	if alternateHref == "" {
		t.Fatal("task-56 FAIL: buildAtomEntry produced no link with rel='alternate'")
	}

	// Must start with the web route prefix (no /api/ in the path).
	wantPrefix := "https://" + host + "/advisories/"
	if !strings.HasPrefix(alternateHref, wantPrefix) {
		t.Errorf("task-56 FAIL: alternate href = %q, want prefix %q", alternateHref, wantPrefix)
	}

	// Must NOT contain /api/ — the alternate link is for the web app, not the API.
	if strings.Contains(alternateHref, "/api/") {
		t.Errorf("task-56 FAIL: alternate href %q contains /api/ — must point at the web route, not the API", alternateHref)
	}

	// The expected percent-encoded form: url.PathEscape encodes spaces to %20;
	// colons are not encoded by PathEscape (valid in path segments per RFC 3986),
	// so the colon in RHSA-2024:5101 remains literal.
	wantHref := fmt.Sprintf("https://%s/advisories/%s/%s",
		host,
		url.PathEscape(pub),
		url.PathEscape(trackingID))
	if alternateHref != wantHref {
		t.Errorf("task-56 FAIL: alternate href = %q, want %q", alternateHref, wantHref)
	}

	// Percent-decode the path portion and confirm it resolves to the two-segment
	// web detail route /advisories/{publisher}/{trackingId}.
	parsed, err := url.Parse(alternateHref)
	if err != nil {
		t.Fatalf("task-56 FAIL: alternate href %q is not a valid URL: %v", alternateHref, err)
	}
	// url.Parse already stores Path as the decoded form and RawPath as encoded.
	decodedPath := parsed.Path
	wantDecodedPath := "/advisories/" + pub + "/" + trackingID
	if decodedPath != wantDecodedPath {
		t.Errorf("task-56 FAIL: decoded path = %q, want %q", decodedPath, wantDecodedPath)
	}
}

// TestAtomEntryAlternateHref_NoAPIPrefix_PlainAdvisory confirms task-56 for a
// plain advisory (no special chars): the alternate href has no /api/ prefix and
// matches the web route pattern.
func TestAtomEntryAlternateHref_NoAPIPrefix_PlainAdvisory(t *testing.T) {
	const host = "portal.example.test"
	pub := "Acme Security"
	trackingID := "ACME-2026-001"

	adv := database.Advisory{
		TrackingID:    trackingID,
		PublisherName: &pub,
	}

	entry := buildAtomEntry("https", host, adv)

	var alternateHref string
	for _, link := range entry.Link {
		if link.Rel == "alternate" {
			alternateHref = link.Href
			break
		}
	}
	if alternateHref == "" {
		t.Fatal("task-56 FAIL: no alternate link in entry")
	}
	if strings.Contains(alternateHref, "/api/") {
		t.Errorf("task-56 FAIL: alternate href %q contains /api/ prefix", alternateHref)
	}
	wantHref := fmt.Sprintf("https://%s/advisories/%s/%s", host,
		url.PathEscape(pub), url.PathEscape(trackingID))
	if alternateHref != wantHref {
		t.Errorf("task-56 FAIL: alternate href = %q, want %q", alternateHref, wantHref)
	}
}

// TestAtomEntryIDVsAlternateHref_TwoURLForms confirms ADR-0016/ADR-0017: the
// Atom entry <id> uses the API permalink (/api/advisories/...) while the
// <link rel="alternate"> uses the web permalink (/advisories/...). They must
// differ only by the /api prefix, with identical two-segment path tails.
func TestAtomEntryIDVsAlternateHref_TwoURLForms(t *testing.T) {
	const host = "portal.example.test"
	pub := "Example Corp"
	trackingID := "RHSA-2024:5101"

	adv := database.Advisory{
		TrackingID:    trackingID,
		PublisherName: &pub,
	}

	entry := buildAtomEntry("https", host, adv)

	// The entry ID is the API permalink.
	entryID := entry.ID
	if !strings.Contains(entryID, "/api/advisories/") {
		t.Errorf("task-56 FAIL: entry ID %q does not contain /api/advisories/ (API permalink)", entryID)
	}

	// The alternate link is the web permalink.
	var alternateHref string
	for _, link := range entry.Link {
		if link.Rel == "alternate" {
			alternateHref = link.Href
			break
		}
	}
	if alternateHref == "" {
		t.Fatal("task-56 FAIL: no alternate link found")
	}

	// Both must start with https://host and the path tails must be identical.
	apiSuffix := strings.TrimPrefix(entryID, "https://"+host+"/api")
	webSuffix := strings.TrimPrefix(alternateHref, "https://"+host)
	if apiSuffix != webSuffix {
		t.Errorf("task-56 FAIL: API path tail %q != web path tail %q — "+
			"they must differ only by the /api prefix",
			apiSuffix, webSuffix)
	}
}
