// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package database

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"
)

// These tests drive the NEW task-17/18 search/filter and facet-count behaviour
// (filters.go, facets.go, the rewritten ListAdvisories) against a live
// postgres:16-alpine seeded — through the real StoreDocument path, so the CVE /
// product / tsvector extraction triggers all fire — with one varied corpus.
// They skip cleanly when docker is absent (via the shared dbtest fixture).
//
// They focus on the new filter/facet surface only; the existing
// queries_integration_test.go already covers latest-per-advisory, pagination,
// sort, the always-on publishable-TLP gate and withdrawn exclusion, so those are
// not re-proven here.

// --- corpus -----------------------------------------------------------------

// corpusDoc is one seedable document: its facet knobs plus the CSAF-shaped body
// the generated columns and extraction triggers consume.
type corpusDoc struct {
	trackingID  string
	publisher   string
	tlp         string
	lang        string
	category    string
	releaseDate string
	score       float64 // CVSS v3 base score; <0 means "no vulnerabilities / no score"
	cves        []string
	vendor      string
	products    []string
	title       string
	notes       []string
}

// build assembles the CSAF JSON map StoreDocument persists.
func (c corpusDoc) build() map[string]any {
	document := map[string]any{
		"category": c.category,
		"title":    c.title,
		"lang":     c.lang,
		"publisher": map[string]any{
			"name":      c.publisher,
			"namespace": "https://example.test",
		},
		"distribution": map[string]any{
			"tlp": map[string]any{"label": c.tlp},
		},
		"tracking": map[string]any{
			"id":                   c.trackingID,
			"version":              "1.0.0",
			"status":               "final",
			"current_release_date": c.releaseDate,
			"initial_release_date": "2026-01-01T00:00:00Z",
			"revision_history":     []any{map[string]any{"number": "1"}},
		},
	}
	if len(c.notes) > 0 {
		notes := make([]any, 0, len(c.notes))
		for _, n := range c.notes {
			notes = append(notes, map[string]any{"category": "general", "text": n})
		}
		document["notes"] = notes
	}

	doc := map[string]any{"document": document}

	// One vulnerability entry carrying the CVSS score and CVE ids. A score < 0
	// means the document has no CVSS data at all (severity band "none").
	if c.score >= 0 || len(c.cves) > 0 {
		vuln := map[string]any{}
		if c.score >= 0 {
			vuln["scores"] = []any{
				map[string]any{"cvss_v3": map[string]any{"baseScore": c.score}},
			}
		}
		vulns := make([]any, 0, len(c.cves)+1)
		if len(c.cves) == 0 {
			vulns = append(vulns, vuln)
		} else {
			for i, cve := range c.cves {
				v := map[string]any{"cve": cve}
				if i == 0 { // attach the score to the first entry
					for k, val := range vuln {
						v[k] = val
					}
				}
				vulns = append(vulns, v)
			}
		}
		doc["vulnerabilities"] = vulns
	}

	if c.vendor != "" || len(c.products) > 0 {
		branches := []any{}
		productBranches := make([]any, 0, len(c.products))
		for _, p := range c.products {
			productBranches = append(productBranches,
				map[string]any{"category": "product_name", "name": p})
		}
		branches = append(branches, map[string]any{
			"category": "vendor",
			"name":     c.vendor,
			"branches": productBranches,
		})
		doc["product_tree"] = map[string]any{"branches": branches}
	}

	return doc
}

// seedCorpus stores a varied corpus spanning severities (none -> critical),
// publishers, vendors/products, categories, languages (DE + EN), dates, CVEs,
// and the restricted TLP labels (AMBER, RED) the public portal must never leak.
// Returns the set keyed by tracking id for per-test reference.
func seedCorpus(t *testing.T, db *DB, ctx context.Context) map[string]corpusDoc {
	t.Helper()

	corpus := []corpusDoc{
		{
			trackingID:  "PORTAL-EN-CRIT",
			publisher:   "Acme Security Team",
			tlp:         "WHITE",
			lang:        "en-US",
			category:    "csaf_security_advisory",
			releaseDate: "2026-05-01T00:00:00Z",
			score:       9.8,
			cves:        []string{"CVE-2026-20001", "CVE-2026-20002", "CVE-2026-20003"},
			vendor:      "Acme",
			products:    []string{"Gateway", "Router", "Switch"},
			title:       "Critical remote code execution vulnerability in Gateway",
			notes:       []string{"A remote attacker can execute arbitrary code."},
		},
		{
			trackingID:  "PORTAL-DE-HIGH",
			publisher:   "Beta CERT",
			tlp:         "WHITE",
			lang:        "de-DE",
			category:    "csaf_security_advisory",
			releaseDate: "2026-04-10T00:00:00Z",
			score:       7.5,
			cves:        []string{"CVE-2026-30001"},
			vendor:      "Beta",
			products:    []string{"Portal"},
			title:       "Schwerwiegende Schwachstelle im Portal",
			notes:       []string{"Ein Angreifer kann die Schwachstelle aus der Ferne ausnutzen."},
		},
		{
			trackingID:  "PORTAL-EN-MED",
			publisher:   "Beta CERT",
			tlp:         "UNLABELED",
			lang:        "en-US",
			category:    "csaf_informational_advisory",
			releaseDate: "2026-03-01T00:00:00Z",
			score:       5.5,
			cves:        []string{"CVE-2026-30002"},
			vendor:      "Beta",
			products:    []string{"Portal", "Dashboard"},
			title:       "Medium severity information disclosure",
			notes:       []string{"Sensitive data may be exposed under rare conditions."},
		},
		{
			trackingID:  "PORTAL-EN-LOW",
			publisher:   "Acme Security Team",
			tlp:         "WHITE",
			lang:        "en-US",
			category:    "csaf_security_advisory",
			releaseDate: "2026-02-01T00:00:00Z",
			score:       3.1,
			cves:        []string{"CVE-2026-40001"},
			vendor:      "Acme",
			products:    []string{"Switch"},
			title:       "Low severity denial of service",
		},
		{
			trackingID:  "PORTAL-EN-NONE",
			publisher:   "Gamma Labs",
			tlp:         "WHITE",
			lang:        "en-US",
			category:    "csaf_security_advisory",
			releaseDate: "2026-01-05T00:00:00Z",
			score:       -1, // no CVSS score at all -> severity band "none"
			vendor:      "Gamma",
			products:    []string{"Analyzer"},
			title:       "Informational note with no scored vulnerability",
		},
		{
			trackingID:  "PORTAL-AMBER",
			publisher:   "Acme Security Team",
			tlp:         "AMBER",
			lang:        "en-US",
			category:    "csaf_security_advisory",
			releaseDate: "2026-05-20T00:00:00Z",
			score:       9.1,
			cves:        []string{"CVE-2026-50001"},
			vendor:      "Acme",
			products:    []string{"Gateway"},
			title:       "Restricted AMBER advisory must never surface",
		},
		{
			trackingID:  "PORTAL-RED",
			publisher:   "Acme Security Team",
			tlp:         "RED",
			lang:        "en-US",
			category:    "csaf_security_advisory",
			releaseDate: "2026-05-21T00:00:00Z",
			score:       10.0,
			cves:        []string{"CVE-2026-60001"},
			vendor:      "Acme",
			products:    []string{"Gateway"},
			title:       "Restricted RED advisory must never surface",
		},
	}

	by := make(map[string]corpusDoc, len(corpus))
	for _, c := range corpus {
		doc := c.build()
		if _, err := db.StoreDocument(ctx, c.trackingID, c.publisher, doc, rawJSON(t, doc)); err != nil {
			t.Fatalf("seeding %s: %v", c.trackingID, err)
		}
		by[c.trackingID] = c
	}
	return by
}

// listWith runs ListAdvisories with the given filters and the default
// publishable-TLP policy, returning the page (Limit 100, newest first).
func listWith(t *testing.T, db *DB, ctx context.Context, f Filters) AdvisoryList {
	t.Helper()
	list, err := db.ListAdvisories(ctx, ListOptions{
		Filters:    f,
		Limit:      100,
		Sort:       SortCurrentReleaseDate,
		Descending: true,
	}, publishableSet)
	if err != nil {
		t.Fatalf("ListAdvisories(%+v): %v", f, err)
	}
	return list
}

// idSet returns the tracking ids of a list as a set for membership assertions.
func idSet(list AdvisoryList) map[string]bool {
	got := map[string]bool{}
	for _, a := range list.Advisories {
		got[a.TrackingID] = true
	}
	return got
}

// assertIDs fails unless the list's tracking ids are exactly want (order-free)
// and the reported total matches the row count.
func assertIDs(t *testing.T, list AdvisoryList, want ...string) {
	t.Helper()
	got := idSet(list)
	if len(got) != len(want) {
		t.Fatalf("result ids = %v, want exactly %v", trackingIDs(list), want)
	}
	for _, id := range want {
		if !got[id] {
			t.Fatalf("result ids = %v, want %v (missing %s)", trackingIDs(list), want, id)
		}
	}
	if list.Total != int64(len(want)) {
		t.Errorf("total = %d, want %d (must equal the matching set)", list.Total, len(want))
	}
}

// --- 1. each filter individually --------------------------------------------

func TestFilterSeverityBands(t *testing.T) {
	db, _, ctx := migratedDB(t)
	seedCorpus(t, db, ctx)

	cases := []struct {
		band string
		want []string
	}{
		{"critical", []string{"PORTAL-EN-CRIT"}}, // 9.8
		{"high", []string{"PORTAL-DE-HIGH"}},     // 7.5
		{"medium", []string{"PORTAL-EN-MED"}},    // 5.5
		{"low", []string{"PORTAL-EN-LOW"}},       // 3.1
		{"none", []string{"PORTAL-EN-NONE"}},     // NULL score
	}
	for _, c := range cases {
		t.Run(c.band, func(t *testing.T) {
			assertIDs(t, listWith(t, db, ctx, Filters{Severity: []string{c.band}}), c.want...)
		})
	}

	// Multiple bands OR together.
	assertIDs(t, listWith(t, db, ctx, Filters{Severity: []string{"high", "critical"}}),
		"PORTAL-EN-CRIT", "PORTAL-DE-HIGH")
}

func TestFilterScoreRange(t *testing.T) {
	db, _, ctx := migratedDB(t)
	seedCorpus(t, db, ctx)

	min7 := 7.0
	assertIDs(t, listWith(t, db, ctx, Filters{ScoreMin: &min7}),
		"PORTAL-EN-CRIT", "PORTAL-DE-HIGH") // 9.8 and 7.5

	max4 := 4.0
	// NULL critical (PORTAL-EN-NONE) does NOT satisfy "critical <= 4.0".
	assertIDs(t, listWith(t, db, ctx, Filters{ScoreMax: &max4}), "PORTAL-EN-LOW") // 3.1

	lo, hi := 4.0, 6.9
	assertIDs(t, listWith(t, db, ctx, Filters{ScoreMin: &lo, ScoreMax: &hi}),
		"PORTAL-EN-MED") // 5.5
}

func TestFilterDateRange(t *testing.T) {
	db, _, ctx := migratedDB(t)
	seedCorpus(t, db, ctx)

	// from: on/after 2026-04-01 -> the April and May docs (restricted ones excluded).
	assertIDs(t, listWith(t, db, ctx, Filters{From: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)}),
		"PORTAL-EN-CRIT", "PORTAL-DE-HIGH")

	// to: on/before 2026-02-01 -> the Feb and Jan docs.
	assertIDs(t, listWith(t, db, ctx, Filters{To: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)}),
		"PORTAL-EN-LOW", "PORTAL-EN-NONE")

	// range: 2026-02-15 .. 2026-04-15 -> March and April docs.
	assertIDs(t, listWith(t, db, ctx, Filters{
		From: time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC),
	}), "PORTAL-EN-MED", "PORTAL-DE-HIGH")
}

func TestFilterCVEExactAndPrefix(t *testing.T) {
	db, _, ctx := migratedDB(t)
	seedCorpus(t, db, ctx)

	// Exact CVE id -> the single advisory carrying it.
	assertIDs(t, listWith(t, db, ctx, Filters{CVE: "CVE-2026-20002"}), "PORTAL-EN-CRIT")

	// Prefix -> all CVEs beginning CVE-2026-3 (two distinct advisories).
	assertIDs(t, listWith(t, db, ctx, Filters{CVE: "CVE-2026-3"}),
		"PORTAL-DE-HIGH", "PORTAL-EN-MED")

	// Case-insensitive.
	assertIDs(t, listWith(t, db, ctx, Filters{CVE: "cve-2026-20001"}), "PORTAL-EN-CRIT")

	// A restricted advisory's CVE must not leak through the CVE filter.
	assertIDs(t, listWith(t, db, ctx, Filters{CVE: "CVE-2026-60001"}))
}

func TestFilterProductAndVendor(t *testing.T) {
	db, _, ctx := migratedDB(t)
	seedCorpus(t, db, ctx)

	// vendor=Acme -> the publishable Acme advisories (crit + low); AMBER/RED excluded.
	assertIDs(t, listWith(t, db, ctx, Filters{Vendor: "Acme"}),
		"PORTAL-EN-CRIT", "PORTAL-EN-LOW")

	// Case-insensitive vendor.
	assertIDs(t, listWith(t, db, ctx, Filters{Vendor: "acme"}),
		"PORTAL-EN-CRIT", "PORTAL-EN-LOW")

	// product=Portal -> the two Beta advisories carrying that product.
	assertIDs(t, listWith(t, db, ctx, Filters{Product: "Portal"}),
		"PORTAL-DE-HIGH", "PORTAL-EN-MED")

	// product=Gateway among publishable docs is only the EN-CRIT advisory (the
	// AMBER/RED Gateway docs are gated out).
	assertIDs(t, listWith(t, db, ctx, Filters{Product: "Gateway"}), "PORTAL-EN-CRIT")
}

func TestFilterPublisherCategoryLang(t *testing.T) {
	db, _, ctx := migratedDB(t)
	seedCorpus(t, db, ctx)

	// publisher.
	assertIDs(t, listWith(t, db, ctx, Filters{Publisher: "Beta CERT"}),
		"PORTAL-DE-HIGH", "PORTAL-EN-MED")

	// category: only the informational advisory.
	assertIDs(t, listWith(t, db, ctx, Filters{Category: "csaf_informational_advisory"}),
		"PORTAL-EN-MED")

	// lang: only the German document.
	assertIDs(t, listWith(t, db, ctx, Filters{Lang: "de-DE"}), "PORTAL-DE-HIGH")
}

func TestFilterTLPNarrowsWithinPublishable(t *testing.T) {
	db, _, ctx := migratedDB(t)
	seedCorpus(t, db, ctx)

	// tlp=WHITE narrows to the WHITE docs (the UNLABELED one drops out).
	assertIDs(t, listWith(t, db, ctx, Filters{TLP: []string{"WHITE"}}),
		"PORTAL-EN-CRIT", "PORTAL-DE-HIGH", "PORTAL-EN-LOW", "PORTAL-EN-NONE")

	// tlp=UNLABELED narrows to the single UNLABELED doc.
	assertIDs(t, listWith(t, db, ctx, Filters{TLP: []string{"UNLABELED"}}), "PORTAL-EN-MED")
}

// --- 2. combined filters AND together ----------------------------------------

func TestFiltersCombineWithAnd(t *testing.T) {
	db, _, ctx := migratedDB(t)
	seedCorpus(t, db, ctx)

	// publisher=Acme AND severity=critical AND lang=en-US -> only PORTAL-EN-CRIT.
	assertIDs(t, listWith(t, db, ctx, Filters{
		Publisher: "Acme Security Team",
		Severity:  []string{"critical"},
		Lang:      "en-US",
	}), "PORTAL-EN-CRIT")

	// vendor=Beta AND category=csaf_security_advisory -> only the German high doc
	// (the medium Beta doc is informational, so the category narrows it out).
	assertIDs(t, listWith(t, db, ctx, Filters{
		Vendor:   "Beta",
		Category: "csaf_security_advisory",
	}), "PORTAL-DE-HIGH")

	// A contradictory combination yields an empty (but valid) result set.
	assertIDs(t, listWith(t, db, ctx, Filters{
		Publisher: "Gamma Labs",
		Severity:  []string{"critical"},
	}))
}

// --- 3. FTS cross-language + ranking -----------------------------------------

func TestFTSFindsBothLanguagesFromOneQueryBox(t *testing.T) {
	db, _, ctx := migratedDB(t)
	seedCorpus(t, db, ctx)

	// A German term finds the German doc (the OR-across-configs OQ-2 mitigation).
	assertIDs(t, listWith(t, db, ctx, Filters{Query: "Schwachstelle"}), "PORTAL-DE-HIGH")

	// An English term finds the English docs whose text mentions it.
	deg := listWith(t, db, ctx, Filters{Query: "vulnerability"})
	if !idSet(deg)["PORTAL-EN-CRIT"] {
		t.Errorf("english query should match the EN critical doc; got %v", trackingIDs(deg))
	}
	if idSet(deg)["PORTAL-DE-HIGH"] {
		t.Errorf("english 'vulnerability' must not match the German doc; got %v", trackingIDs(deg))
	}
}

func TestFTSBlankQueryIsNoFilter(t *testing.T) {
	db, _, ctx := migratedDB(t)
	seedCorpus(t, db, ctx)

	// Whitespace-only q must behave exactly like no q at all: the full publishable
	// set (4 docs), not an empty or error result.
	whitespace := listWith(t, db, ctx, Filters{Query: "   "})
	none := listWith(t, db, ctx, Filters{})
	if whitespace.Total != none.Total || whitespace.Total != 5 {
		t.Errorf("whitespace q total = %d, no-filter total = %d, want both 5",
			whitespace.Total, none.Total)
	}
}

func TestFTSRanksTitleHitAboveNotesHit(t *testing.T) {
	db, _, ctx := migratedDB(t)

	// Two EN docs: one with the term in the title (weight A), one only in notes.
	titleDoc := corpusDoc{
		trackingID: "PORTAL-RANK-TITLE", publisher: "Acme Security Team", tlp: "WHITE",
		lang: "en-US", category: "csaf_security_advisory", releaseDate: "2026-02-01T00:00:00Z",
		score: 5.0, title: "Spectre side-channel advisory",
		notes: []string{"An unrelated mitigation is discussed here."},
	}
	notesDoc := corpusDoc{
		trackingID: "PORTAL-RANK-NOTES", publisher: "Acme Security Team", tlp: "WHITE",
		lang: "en-US", category: "csaf_security_advisory", releaseDate: "2026-03-01T00:00:00Z",
		score: 5.0, title: "Generic advisory",
		notes: []string{"The component is affected by Spectre."},
	}
	for _, c := range []corpusDoc{titleDoc, notesDoc} {
		doc := c.build()
		if _, err := db.StoreDocument(ctx, c.trackingID, c.publisher, doc, rawJSON(t, doc)); err != nil {
			t.Fatalf("seeding %s: %v", c.trackingID, err)
		}
	}

	// The default sort is newest-first (which would put the notes doc first), so a
	// correct relevance ordering must override it and put the title hit first.
	list := listWith(t, db, ctx, Filters{Query: "Spectre"})
	if len(list.Advisories) != 2 {
		t.Fatalf("expected both Spectre docs, got %v", trackingIDs(list))
	}
	if list.Advisories[0].TrackingID != "PORTAL-RANK-TITLE" {
		t.Errorf("ranking order = %v, want the title hit first (above the notes-only hit)",
			trackingIDs(list))
	}
}

// --- 4. no row duplication ---------------------------------------------------

func TestNoRowDuplicationForManyProductsAndCVEs(t *testing.T) {
	db, _, ctx := migratedDB(t)
	seedCorpus(t, db, ctx)

	// PORTAL-EN-CRIT has 3 products and 3 CVEs. A vendor filter that joins the
	// product side table must still yield it exactly once, with an honest total.
	list := listWith(t, db, ctx, Filters{Vendor: "Acme", Product: "Gateway"})
	count := 0
	var hit Advisory
	for _, a := range list.Advisories {
		if a.TrackingID == "PORTAL-EN-CRIT" {
			count++
			hit = a
		}
	}
	if count != 1 {
		t.Fatalf("PORTAL-EN-CRIT appeared %d times, want exactly 1 (no fan-out)", count)
	}
	if list.Total != 1 {
		t.Errorf("total = %d, want 1 (count must not be inflated by the product join)", list.Total)
	}

	// The cves array must list ALL of its CVEs, sorted, exactly once each.
	want := []string{"CVE-2026-20001", "CVE-2026-20002", "CVE-2026-20003"}
	got := append([]string(nil), hit.CVEs...)
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("cves = %v, want %v", hit.CVEs, want)
	}
}

// --- 5. TLP non-leak (security) ----------------------------------------------

func TestRestrictedTLPNeverLeaksRegardlessOfParams(t *testing.T) {
	db, _, ctx := migratedDB(t)
	seedCorpus(t, db, ctx)

	// An explicit tlp=RED / tlp=AMBER request returns nothing — the param is
	// intersected with the publishable set, never substituted for it.
	if got := listWith(t, db, ctx, Filters{TLP: []string{"RED"}}); got.Total != 0 {
		t.Errorf("tlp=RED total = %d, want 0 (no leak); got %v", got.Total, trackingIDs(got))
	}
	if got := listWith(t, db, ctx, Filters{TLP: []string{"AMBER"}}); got.Total != 0 {
		t.Errorf("tlp=AMBER total = %d, want 0 (no leak); got %v", got.Total, trackingIDs(got))
	}
	if got := listWith(t, db, ctx, Filters{TLP: []string{"RED", "AMBER", "WHITE"}}); !idSet(got)["PORTAL-EN-CRIT"] || idSet(got)["PORTAL-RED"] || idSet(got)["PORTAL-AMBER"] {
		t.Errorf("mixed tlp request leaked a restricted doc; got %v", trackingIDs(got))
	}

	// No combination of other filters can surface a restricted advisory. Each of
	// these would match the AMBER/RED docs if the publishable gate were bypassed.
	for _, f := range []Filters{
		{Severity: []string{"critical"}, Vendor: "Acme"},     // RED is critical Acme
		{ScoreMin: ptr(9.0)},                                 // AMBER 9.1, RED 10.0
		{CVE: "CVE-2026-5"},                                  // AMBER CVE prefix
		{CVE: "CVE-2026-6"},                                  // RED CVE prefix
		{From: time.Date(2026, 5, 19, 0, 0, 0, 0, time.UTC)}, // AMBER/RED release window
		{Publisher: "Acme Security Team"},
	} {
		list := listWith(t, db, ctx, f)
		if idSet(list)["PORTAL-AMBER"] || idSet(list)["PORTAL-RED"] {
			t.Errorf("filter %+v leaked a restricted advisory: %v", f, trackingIDs(list))
		}
	}
}

func TestFacetsNeverLeakRestrictedTLP(t *testing.T) {
	db, _, ctx := migratedDB(t)
	seedCorpus(t, db, ctx)

	facets, err := db.ComputeFacets(ctx, Filters{}, publishableSet)
	if err != nil {
		t.Fatalf("ComputeFacets: %v", err)
	}

	// No facet dimension may surface AMBER/RED — not as a TLP value, and the
	// restricted docs' publisher/vendor contributions must only reflect their
	// publishable siblings.
	for _, fc := range facets.TLP.Values {
		if fc.Value == "AMBER" || fc.Value == "RED" {
			t.Errorf("TLP facet leaked restricted label %q", fc.Value)
		}
	}
	// The Acme publisher count must equal only its publishable docs (crit + low),
	// not the AMBER/RED ones.
	if got := facetCount(facets.Publisher, "Acme Security Team"); got != 2 {
		t.Errorf("Acme publisher facet count = %d, want 2 (restricted docs excluded)", got)
	}
}

// --- 6. facets: dimensions, drill-down consistency, caps ---------------------

func TestFacetsCoverAllDimensionsUnfiltered(t *testing.T) {
	db, _, ctx := migratedDB(t)
	seedCorpus(t, db, ctx)

	facets, err := db.ComputeFacets(ctx, Filters{}, publishableSet)
	if err != nil {
		t.Fatalf("ComputeFacets: %v", err)
	}

	// Publisher: Acme=2, Beta CERT=2, Gamma Labs=1.
	assertFacet(t, facets.Publisher, map[string]int64{
		"Acme Security Team": 2, "Beta CERT": 2, "Gamma Labs": 1,
	})
	// Vendor: Acme=2, Beta=2, Gamma=1 (restricted Acme docs excluded).
	assertFacet(t, facets.Vendor, map[string]int64{"Acme": 2, "Beta": 2, "Gamma": 1})
	// Category.
	assertFacet(t, facets.Category, map[string]int64{
		"csaf_security_advisory": 4, "csaf_informational_advisory": 1,
	})
	// TLP: WHITE=4, UNLABELED=1, no restricted labels.
	assertFacet(t, facets.TLP, map[string]int64{"WHITE": 4, "UNLABELED": 1})
	// Lang.
	assertFacet(t, facets.Lang, map[string]int64{"en-US": 4, "de-DE": 1})

	// Severity: all 5 bands always emitted; counts sum to the publishable total.
	severity := map[string]int64{}
	for _, fc := range facets.Severity.Values {
		severity[fc.Value] = fc.Count
	}
	if len(facets.Severity.Values) != 5 {
		t.Errorf("severity facet emitted %d bands, want all 5", len(facets.Severity.Values))
	}
	want := map[string]int64{"none": 1, "low": 1, "medium": 1, "high": 1, "critical": 1}
	for band, n := range want {
		if severity[band] != n {
			t.Errorf("severity[%s] = %d, want %d", band, severity[band], n)
		}
	}
	var sum int64
	for _, n := range severity {
		sum += n
	}
	if sum != 5 {
		t.Errorf("severity bands sum to %d, want 5 (the publishable total)", sum)
	}
}

// TestFacetCountsMatchListTotalUnderDrillDown is the core facet-consistency
// proof: for the same filter state, every facet count equals the list total for
// that same filtered set (standard drill-down, the counted facet is not
// self-excluded).
func TestFacetCountsMatchListTotalUnderDrillDown(t *testing.T) {
	db, _, ctx := migratedDB(t)
	seedCorpus(t, db, ctx)

	filterStates := []Filters{
		{},
		{Publisher: "Beta CERT"},
		{Vendor: "Acme"},
		{Severity: []string{"high", "critical"}},
		{Lang: "en-US", Category: "csaf_security_advisory"},
		{Query: "vulnerability"},
	}
	for _, f := range filterStates {
		list := listWith(t, db, ctx, f)
		facets, err := db.ComputeFacets(ctx, f, publishableSet)
		if err != nil {
			t.Fatalf("ComputeFacets(%+v): %v", f, err)
		}

		// The publisher, category, tlp and lang facets each cover every row exactly
		// once, so their counts must sum to the list total. (Vendor/product can
		// over- or under-count when a doc has several or no products, so they are
		// not summed here.)
		for name, g := range map[string]FacetGroup{
			"publisher": facets.Publisher,
			"category":  facets.Category,
			"tlp":       facets.TLP,
			"lang":      facets.Lang,
		} {
			var sum int64
			for _, fc := range g.Values {
				sum += fc.Count
			}
			if sum != list.Total {
				t.Errorf("filter %+v: %s facet counts sum to %d, want list total %d",
					f, name, sum, list.Total)
			}
		}

		// Severity bands always sum to the list total (every row classifies into one).
		var sevSum int64
		for _, fc := range facets.Severity.Values {
			sevSum += fc.Count
		}
		if sevSum != list.Total {
			t.Errorf("filter %+v: severity facet sums to %d, want list total %d",
				f, sevSum, list.Total)
		}
	}
}

// TestFacetCapAppliedAndFlagged proves the publisher/vendor/product caps: with
// more than FacetCap distinct publishers the group is truncated to FacetCap
// values and Capped is set; an uncapped corpus leaves Capped false.
func TestFacetCapAppliedAndFlagged(t *testing.T) {
	db, _, ctx := migratedDB(t)

	// Seed FacetCap+5 advisories, each with a distinct publisher so the publisher
	// facet exceeds the cap.
	for i := 0; i < FacetCap+5; i++ {
		c := corpusDoc{
			trackingID:  "PORTAL-CAP-" + itoa(i),
			publisher:   "Publisher-" + itoa(i),
			tlp:         "WHITE",
			lang:        "en-US",
			category:    "csaf_security_advisory",
			releaseDate: "2026-02-01T00:00:00Z",
			score:       5.0,
			title:       "Capped advisory " + itoa(i),
		}
		doc := c.build()
		if _, err := db.StoreDocument(ctx, c.trackingID, c.publisher, doc, rawJSON(t, doc)); err != nil {
			t.Fatalf("seeding %s: %v", c.trackingID, err)
		}
	}

	facets, err := db.ComputeFacets(ctx, Filters{}, publishableSet)
	if err != nil {
		t.Fatalf("ComputeFacets: %v", err)
	}
	if !facets.Publisher.Capped {
		t.Errorf("publisher facet Capped = false, want true (>%d distinct publishers)", FacetCap)
	}
	if len(facets.Publisher.Values) != FacetCap {
		t.Errorf("publisher facet returned %d values, want exactly the cap %d",
			len(facets.Publisher.Values), FacetCap)
	}
	// Lang has a single value, well under the cap, so it must not be flagged.
	if facets.Lang.Capped {
		t.Error("lang facet Capped = true, want false (one distinct value)")
	}
}

// --- helpers -----------------------------------------------------------------

func ptr(f float64) *float64 { return &f }

func facetCount(g FacetGroup, value string) int64 {
	for _, fc := range g.Values {
		if fc.Value == value {
			return fc.Count
		}
	}
	return 0
}

// assertFacet checks a facet group lists exactly the expected value->count map.
func assertFacet(t *testing.T, g FacetGroup, want map[string]int64) {
	t.Helper()
	got := map[string]int64{}
	for _, fc := range g.Values {
		got[fc.Value] = fc.Count
	}
	if len(got) != len(want) {
		t.Errorf("facet values = %v, want %v", got, want)
		return
	}
	for value, n := range want {
		if got[value] != n {
			t.Errorf("facet[%q] = %d, want %d (full group %v)", value, got[value], n, got)
		}
	}
}
