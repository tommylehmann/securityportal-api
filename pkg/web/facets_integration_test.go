// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package web

import (
	"encoding/json"
	"net/http"
	"testing"
)

// These tests cover the NEW task-17/18 surface at the HTTP seam: filter-param
// validation (malformed values are 400, not 500), the /api/facets endpoint, the
// /api/advisories/search alias, and the TLP non-leak invariant on both list and
// facets. The fast cases use the fake Querier (no docker); the wired cases use
// the live apiHarness and skip cleanly without docker.

// --- 7. validation: malformed filter params are 400 (fake Querier, fast) -----

// TestParseFiltersRejectsMalformedParams pins that a bad severity / score / date
// is rejected at the handler with a 400 rather than reaching the query layer and
// surfacing as a 500. It checks both the list endpoint and the facets endpoint,
// which share parseFilters.
func TestParseFiltersRejectsMalformedParams(t *testing.T) {
	bad := []string{
		"severity=catastrophic",
		"severity=high,bogus", // one good, one bad -> still 400
		"score_min=high",
		"score_max=NaNN",
		"from=2026-13-40",
		"from=yesterday",
		"to=01-01-2026", // wrong layout
	}
	for _, query := range bad {
		for _, path := range []string{"/api/advisories?", "/api/facets?", "/api/advisories/search?"} {
			target := path + query
			rec := doRequest(t, &fakeQuerier{}, http.MethodGet, target)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want 400", target, rec.Code)
			}
		}
	}
}

// TestParseFiltersAcceptsValidParams confirms the validated, accepted values
// flow through to the query layer as the parsed Filters (and that both a comma
// list and a repeated param yield the same severity set).
func TestParseFiltersAcceptsValidParams(t *testing.T) {
	q := &fakeQuerier{}
	target := "/api/advisories?q=spectre&cve=CVE-2026-1&severity=high,critical" +
		"&score_min=4.0&score_max=9.5&from=2026-01-01&to=2026-12-31" +
		"&product=Gateway&vendor=Acme&publisher=Acme+Security+Team" +
		"&category=csaf_security_advisory&lang=en-US&tlp=WHITE"
	rec := doRequest(t, q, http.MethodGet, target)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\n%s", rec.Code, rec.Body.String())
	}

	f := q.gotOpts.Filters
	if f.Query != "spectre" || f.CVE != "CVE-2026-1" {
		t.Errorf("q/cve not parsed: %+v", f)
	}
	if len(f.Severity) != 2 || f.Severity[0] != "high" || f.Severity[1] != "critical" {
		t.Errorf("severity = %v, want [high critical]", f.Severity)
	}
	if f.ScoreMin == nil || *f.ScoreMin != 4.0 || f.ScoreMax == nil || *f.ScoreMax != 9.5 {
		t.Errorf("score range = %v..%v, want 4.0..9.5", f.ScoreMin, f.ScoreMax)
	}
	if f.From.IsZero() || f.To.IsZero() {
		t.Errorf("date range not parsed: from=%v to=%v", f.From, f.To)
	}
	if f.Product != "Gateway" || f.Vendor != "Acme" || f.Publisher != "Acme Security Team" {
		t.Errorf("product/vendor/publisher not parsed: %+v", f)
	}
	if f.Category != "csaf_security_advisory" || f.Lang != "en-US" {
		t.Errorf("category/lang not parsed: %+v", f)
	}
	if len(f.TLP) != 1 || f.TLP[0] != "WHITE" {
		t.Errorf("tlp = %v, want [WHITE]", f.TLP)
	}
}

// --- live /api/facets + /api/advisories/search (apiHarness, docker) ----------

// facetsResponse mirrors the JSON shape of GET /api/facets.
type facetsResponse struct {
	Publisher facetGroupJSON `json:"publisher"`
	Vendor    facetGroupJSON `json:"vendor"`
	Product   facetGroupJSON `json:"product"`
	Category  facetGroupJSON `json:"category"`
	TLP       facetGroupJSON `json:"tlp"`
	Lang      facetGroupJSON `json:"lang"`
	Severity  facetGroupJSON `json:"severity"`
}

type facetGroupJSON struct {
	Values []struct {
		Value string `json:"value"`
		Count int64  `json:"count"`
	} `json:"values"`
	Capped bool `json:"capped"`
}

func (g facetGroupJSON) count(value string) int64 {
	for _, fc := range g.Values {
		if fc.Value == value {
			return fc.Count
		}
	}
	return 0
}

func decodeFacets(t *testing.T, body []byte) facetsResponse {
	t.Helper()
	var f facetsResponse
	if err := json.Unmarshal(body, &f); err != nil {
		t.Fatalf("decoding facets body: %v\n%s", err, body)
	}
	return f
}

// seedFacetDoc stores one revision carrying a product tree and a CVE so the
// vendor/product/cve facets are populated.
func (h *apiHarness) seedFacetDoc(t *testing.T, trackingID, publisher, tlp, vendor, product string) {
	t.Helper()
	doc := map[string]any{
		"document": map[string]any{
			"category": "csaf_security_advisory",
			"title":    "Advisory " + trackingID,
			"lang":     "en-US",
			"publisher": map[string]any{
				"name":      publisher,
				"namespace": "https://example.test",
			},
			"distribution": map[string]any{"tlp": map[string]any{"label": tlp}},
			"tracking": map[string]any{
				"id":                   trackingID,
				"version":              "1.0.0",
				"status":               "final",
				"current_release_date": "2026-03-01T00:00:00Z",
				"initial_release_date": "2026-01-01T00:00:00Z",
				"revision_history":     []any{map[string]any{"number": "1"}},
			},
		},
		"vulnerabilities": []any{
			map[string]any{
				"cve":    "CVE-2026-" + trackingID,
				"scores": []any{map[string]any{"cvss_v3": map[string]any{"baseScore": 9.8}}},
			},
		},
		"product_tree": map[string]any{
			"branches": []any{
				map[string]any{
					"category": "vendor",
					"name":     vendor,
					"branches": []any{map[string]any{"category": "product_name", "name": product}},
				},
			},
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshaling fixture: %v", err)
	}
	if _, err := h.db.StoreDocument(h.ctx, trackingID, publisher, doc, b); err != nil {
		t.Fatalf("StoreDocument %s: %v", trackingID, err)
	}
}

// TestAPIFacetsEndpoint drives GET /api/facets end-to-end against a live
// database: the dimensions are present and correct, restricted TLP never leaks,
// and a drill-down filter narrows the counts.
func TestAPIFacetsEndpoint(t *testing.T) {
	h := newAPIHarness(t)

	h.seedFacetDoc(t, "FCT-WHITE-A", "Acme Security Team", "WHITE", "Acme", "Gateway")
	h.seedFacetDoc(t, "FCT-WHITE-B", "Beta CERT", "WHITE", "Beta", "Portal")
	h.seedFacetDoc(t, "FCT-UNLABELED", "Beta CERT", "UNLABELED", "Beta", "Dashboard")
	h.seedFacetDoc(t, "FCT-AMBER", "Acme Security Team", "AMBER", "Acme", "Gateway")
	h.seedFacetDoc(t, "FCT-RED", "Acme Security Team", "RED", "Acme", "Gateway")

	rec := h.get(t, "/api/facets")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\n%s", rec.Code, rec.Body.String())
	}
	f := decodeFacets(t, rec.Body.Bytes())

	// Publisher: Acme=1 (only the WHITE doc), Beta=2.
	if got := f.Publisher.count("Acme Security Team"); got != 1 {
		t.Errorf("publisher Acme count = %d, want 1 (AMBER/RED excluded)", got)
	}
	if got := f.Publisher.count("Beta CERT"); got != 2 {
		t.Errorf("publisher Beta count = %d, want 2", got)
	}
	// TLP must list only publishable labels.
	for _, label := range []string{"AMBER", "RED"} {
		if f.TLP.count(label) != 0 {
			t.Errorf("TLP facet leaked restricted label %s", label)
		}
	}
	if f.TLP.count("WHITE") != 2 || f.TLP.count("UNLABELED") != 1 {
		t.Errorf("TLP facet = %+v, want WHITE=2 UNLABELED=1", f.TLP.Values)
	}
	// Vendor: Acme=1 publishable, Beta=2.
	if f.Vendor.count("Acme") != 1 || f.Vendor.count("Beta") != 2 {
		t.Errorf("vendor facet = %+v, want Acme=1 Beta=2", f.Vendor.Values)
	}
	// Severity always emits all five bands.
	if len(f.Severity.Values) != 5 {
		t.Errorf("severity facet emitted %d bands, want 5", len(f.Severity.Values))
	}

	// Drill-down: publisher=Beta CERT narrows every dimension to the 2 Beta docs.
	rec = h.get(t, "/api/facets?publisher=Beta+CERT")
	drill := decodeFacets(t, rec.Body.Bytes())
	if drill.Publisher.count("Beta CERT") != 2 || drill.Publisher.count("Acme Security Team") != 0 {
		t.Errorf("drill-down publisher facet = %+v, want only Beta CERT=2", drill.Publisher.Values)
	}
	if drill.Vendor.count("Acme") != 0 {
		t.Error("drill-down to Beta CERT must drop Acme from the vendor facet")
	}
}

// TestAPIFacetsTLPRedYieldsNoCounts proves the TLP non-leak invariant on the
// facets endpoint: an explicit tlp=RED param yields zero counts across every
// dimension (the param is intersected with the publishable set, never a bypass).
func TestAPIFacetsTLPRedYieldsNoCounts(t *testing.T) {
	h := newAPIHarness(t)
	h.seedFacetDoc(t, "FCT-RED-ONLY", "Acme Security Team", "RED", "Acme", "Gateway")
	h.seedFacetDoc(t, "FCT-WHITE-ONLY", "Acme Security Team", "WHITE", "Acme", "Gateway")

	rec := h.get(t, "/api/facets?tlp=RED")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\n%s", rec.Code, rec.Body.String())
	}
	f := decodeFacets(t, rec.Body.Bytes())

	for name, g := range map[string]facetGroupJSON{
		"publisher": f.Publisher, "vendor": f.Vendor, "product": f.Product,
		"category": f.Category, "tlp": f.TLP, "lang": f.Lang,
	} {
		if len(g.Values) != 0 {
			t.Errorf("tlp=RED %s facet = %+v, want no counts (no leak)", name, g.Values)
		}
	}
	// Severity still emits its five bands, but all at zero.
	for _, fc := range f.Severity.Values {
		if fc.Count != 0 {
			t.Errorf("tlp=RED severity band %s = %d, want 0", fc.Value, fc.Count)
		}
	}
}

// TestAPISearchAliasHonoursFilters confirms /api/advisories/search is a true
// alias of the list endpoint and applies the search/facet params, with the TLP
// non-leak invariant holding (an explicit tlp=RED returns nothing).
func TestAPISearchAliasHonoursFilters(t *testing.T) {
	h := newAPIHarness(t)
	h.seedFacetDoc(t, "SRCH-ACME", "Acme Security Team", "WHITE", "Acme", "Gateway")
	h.seedFacetDoc(t, "SRCH-BETA", "Beta CERT", "WHITE", "Beta", "Portal")
	h.seedFacetDoc(t, "SRCH-RED", "Acme Security Team", "RED", "Acme", "Gateway")

	// vendor=Acme via the alias -> only the publishable Acme advisory.
	rec := h.get(t, "/api/advisories/search?vendor=Acme")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\n%s", rec.Code, rec.Body.String())
	}
	body := decodeList(t, rec)
	if body.Total != 1 || !contains(body.ids(), "SRCH-ACME") {
		t.Errorf("search vendor=Acme = %v (total %d), want only SRCH-ACME", body.ids(), body.Total)
	}
	if contains(body.ids(), "SRCH-RED") {
		t.Error("restricted RED advisory must never surface through the search alias")
	}

	// tlp=RED via the alias -> nothing.
	rec = h.get(t, "/api/advisories/search?tlp=RED")
	if got := decodeList(t, rec).Total; got != 0 {
		t.Errorf("search tlp=RED total = %d, want 0 (no leak)", got)
	}
}
