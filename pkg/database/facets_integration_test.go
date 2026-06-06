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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/securityportal/securityportal-api/internal/dbtest"
)

// These tests exercise the task-15/16 facet extraction (CVEs, product/vendor)
// and the language-aware full-text search added by migration 002 (folded into
// the consolidated 000 setup for fresh installs). They run against a real
// postgres:16-alpine container via docker-in-docker and skip cleanly when docker
// is unavailable, so `go test ./...` still passes without a docker daemon.
//
// They drive the schema through the public surface only: plain INSERT/UPDATE/
// DELETE on documents (which fire the extraction triggers) and SQL queries
// against the resulting facet tables and tsvector column. No private function is
// called directly.

// facetCSAF builds a CSAF-shaped document as a JSON string. Sensible defaults are
// provided for every field the extraction relies on; opts mutate the top-level
// map (e.g. to drop vulnerabilities or supply a custom product_tree).
func facetCSAF(trackingID, lang string, opts ...func(map[string]any)) string {
	doc := map[string]any{
		"document": map[string]any{
			"category": "csaf_security_advisory",
			"title":    "Test advisory " + trackingID,
			"lang":     lang,
			"publisher": map[string]any{
				"name":      "SecurityPortal Test Publisher",
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
		"vulnerabilities": []any{
			map[string]any{
				"cve": "CVE-2026-00001",
				"scores": []any{
					map[string]any{
						"cvss_v3": map[string]any{"baseScore": 9.8},
					},
				},
			},
		},
	}
	for _, opt := range opts {
		opt(doc)
	}
	return mustJSON(doc)
}

// withCVEs replaces the vulnerabilities array with one entry per CVE id.
func withCVEs(cves ...string) func(map[string]any) {
	return func(doc map[string]any) {
		vulns := make([]any, 0, len(cves))
		for _, cve := range cves {
			vulns = append(vulns, map[string]any{"cve": cve})
		}
		doc["vulnerabilities"] = vulns
	}
}

// withoutVulnerabilities drops the vulnerabilities array entirely.
func withoutVulnerabilities() func(map[string]any) {
	return func(doc map[string]any) {
		delete(doc, "vulnerabilities")
	}
}

// withProductTree sets the document's product_tree.
func withProductTree(tree map[string]any) func(map[string]any) {
	return func(doc map[string]any) {
		doc["product_tree"] = tree
	}
}

// withTitle overrides the document title (used for FTS tests).
func withTitle(title string) func(map[string]any) {
	return func(doc map[string]any) {
		doc["document"].(map[string]any)["title"] = title
	}
}

// withNotes sets the document-level notes array from the given text strings.
func withNotes(texts ...string) func(map[string]any) {
	return func(doc map[string]any) {
		notes := make([]any, 0, len(texts))
		for _, txt := range texts {
			notes = append(notes, map[string]any{"category": "general", "text": txt})
		}
		doc["document"].(map[string]any)["notes"] = notes
	}
}

// facetDB starts a throwaway postgres and applies the embedded migrations.
func facetDB(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	pool, _, ctx := dbtest.StartPostgres(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return pool, ctx
}

// insertDoc inserts a document under a fresh advisory and returns the document id.
func insertDoc(t *testing.T, ctx context.Context, pool *pgxpool.Pool, trackingID, doc string) int {
	t.Helper()
	advID := newAdvisory(t, ctx, pool, trackingID, "SecurityPortal Test Publisher")
	return insertRevision(t, ctx, pool, advID, doc)
}

// cvesFor returns the sorted CVE ids extracted for the given document.
func cvesFor(t *testing.T, ctx context.Context, pool *pgxpool.Pool, docID int) []string {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT u.cve
		FROM documents_cves dc
		JOIN unique_cves u ON u.id = dc.cve_id
		WHERE dc.documents_id = $1
		ORDER BY u.cve`, docID)
	if err != nil {
		t.Fatalf("reading documents_cves: %v", err)
	}
	defer rows.Close()
	var cves []string
	for rows.Next() {
		var cve string
		if err := rows.Scan(&cve); err != nil {
			t.Fatalf("scanning cve: %v", err)
		}
		cves = append(cves, cve)
	}
	return cves
}

// pair is a (vendor, product) extraction result, using "" for SQL NULL so it
// can be compared and printed without nil juggling.
type pair struct {
	vendor  string
	product string
}

func (p pair) String() string {
	return "(" + p.vendor + ", " + p.product + ")"
}

// productsFor returns the sorted (vendor, product) pairs extracted for a document.
func productsFor(t *testing.T, ctx context.Context, pool *pgxpool.Pool, docID int) []pair {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT coalesce(vendor, ''), coalesce(product, '')
		FROM documents_products
		WHERE documents_id = $1`, docID)
	if err != nil {
		t.Fatalf("reading documents_products: %v", err)
	}
	defer rows.Close()
	var pairs []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.vendor, &p.product); err != nil {
			t.Fatalf("scanning product pair: %v", err)
		}
		pairs = append(pairs, p)
	}
	sortPairs(pairs)
	return pairs
}

func sortPairs(pairs []pair) {
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].vendor != pairs[j].vendor {
			return pairs[i].vendor < pairs[j].vendor
		}
		return pairs[i].product < pairs[j].product
	})
}

// assertPairs fails the test unless the extracted pairs equal want exactly.
func assertPairs(t *testing.T, got, want []pair) {
	t.Helper()
	sortPairs(want)
	if len(got) != len(want) {
		t.Fatalf("got %d product pairs %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("product pairs = %v, want %v", got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// 1. CVE extraction
// ---------------------------------------------------------------------------

func TestCVEExtractionMultipleCVEs(t *testing.T) {
	pool, ctx := facetDB(t)

	docID := insertDoc(t, ctx, pool, "PORTAL-CVE-MULTI",
		facetCSAF("PORTAL-CVE-MULTI", "en",
			withCVEs("CVE-2026-11111", "CVE-2026-22222", "CVE-2026-33333")))

	got := cvesFor(t, ctx, pool, docID)
	want := []string{"CVE-2026-11111", "CVE-2026-22222", "CVE-2026-33333"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("documents_cves = %v, want %v", got, want)
	}

	// Every extracted CVE must also exist in the shared unique_cves dictionary.
	for _, cve := range want {
		var exists bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM unique_cves WHERE cve = $1)`, cve).Scan(&exists); err != nil {
			t.Fatalf("checking unique_cves for %s: %v", cve, err)
		}
		if !exists {
			t.Errorf("expected %s in unique_cves", cve)
		}
	}
}

func TestCVEExtractionNoCVEYieldsNoRows(t *testing.T) {
	pool, ctx := facetDB(t)

	docID := insertDoc(t, ctx, pool, "PORTAL-CVE-NONE",
		facetCSAF("PORTAL-CVE-NONE", "en", withoutVulnerabilities()))

	if got := cvesFor(t, ctx, pool, docID); len(got) != 0 {
		t.Errorf("expected no CVE rows for a doc without vulnerabilities, got %v", got)
	}
}

// TestCVEDeduplicatedPerDocument pins the implementer's UNION/DISTINCT choice:
// a document that repeats the same CVE across two vulnerability entries yields a
// single documents_cves row (the unique key would otherwise reject the second).
func TestCVEDeduplicatedPerDocument(t *testing.T) {
	pool, ctx := facetDB(t)

	docID := insertDoc(t, ctx, pool, "PORTAL-CVE-DUP",
		facetCSAF("PORTAL-CVE-DUP", "en",
			withCVEs("CVE-2026-44444", "CVE-2026-44444")))

	got := cvesFor(t, ctx, pool, docID)
	if len(got) != 1 || got[0] != "CVE-2026-44444" {
		t.Errorf("expected one deduplicated CVE row, got %v", got)
	}
}

// TestCVESharedDictionaryAcrossDocuments verifies unique_cves is a shared
// dictionary: two documents referencing the same CVE point at one unique_cves row.
func TestCVESharedDictionaryAcrossDocuments(t *testing.T) {
	pool, ctx := facetDB(t)

	doc1 := insertDoc(t, ctx, pool, "PORTAL-CVE-SHARE-1",
		facetCSAF("PORTAL-CVE-SHARE-1", "en", withCVEs("CVE-2026-55555")))
	doc2 := insertDoc(t, ctx, pool, "PORTAL-CVE-SHARE-2",
		facetCSAF("PORTAL-CVE-SHARE-2", "en", withCVEs("CVE-2026-55555")))

	var dictCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM unique_cves WHERE cve = $1`, "CVE-2026-55555").Scan(&dictCount); err != nil {
		t.Fatalf("counting unique_cves: %v", err)
	}
	if dictCount != 1 {
		t.Errorf("expected exactly one unique_cves row for the shared CVE, got %d", dictCount)
	}

	for _, id := range []int{doc1, doc2} {
		if got := cvesFor(t, ctx, pool, id); len(got) != 1 || got[0] != "CVE-2026-55555" {
			t.Errorf("doc %d cves = %v, want [CVE-2026-55555]", id, got)
		}
	}
}

func TestCVEExtractionCascadesOnDelete(t *testing.T) {
	pool, ctx := facetDB(t)

	docID := insertDoc(t, ctx, pool, "PORTAL-CVE-DEL",
		facetCSAF("PORTAL-CVE-DEL", "en", withCVEs("CVE-2026-66666")))
	if got := cvesFor(t, ctx, pool, docID); len(got) != 1 {
		t.Fatalf("setup: expected one CVE row, got %v", got)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM documents WHERE id = $1`, docID); err != nil {
		t.Fatalf("deleting document: %v", err)
	}

	var remaining int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM documents_cves WHERE documents_id = $1`, docID).Scan(&remaining); err != nil {
		t.Fatalf("counting documents_cves after delete: %v", err)
	}
	if remaining != 0 {
		t.Errorf("expected documents_cves to cascade away, %d rows remain", remaining)
	}
}

// TestCVEExtractionReExtractsOnUpdate pins the AFTER UPDATE trigger: changing the
// document's vulnerabilities rebuilds the CVE links (old gone, new present).
func TestCVEExtractionReExtractsOnUpdate(t *testing.T) {
	pool, ctx := facetDB(t)

	docID := insertDoc(t, ctx, pool, "PORTAL-CVE-UPD",
		facetCSAF("PORTAL-CVE-UPD", "en", withCVEs("CVE-2026-77777")))
	if got := cvesFor(t, ctx, pool, docID); len(got) != 1 || got[0] != "CVE-2026-77777" {
		t.Fatalf("setup: cves = %v, want [CVE-2026-77777]", got)
	}

	updated := facetCSAF("PORTAL-CVE-UPD", "en", withCVEs("CVE-2026-88888", "CVE-2026-99999"))
	if _, err := pool.Exec(ctx,
		`UPDATE documents SET document = $1::jsonb WHERE id = $2`, updated, docID); err != nil {
		t.Fatalf("updating document: %v", err)
	}

	got := cvesFor(t, ctx, pool, docID)
	want := []string{"CVE-2026-88888", "CVE-2026-99999"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("after update cves = %v, want %v (old CVE must be gone)", got, want)
	}
}

// ---------------------------------------------------------------------------
// 2. Product / vendor extraction
// ---------------------------------------------------------------------------

// TestProductExtractionNestedTreeAndFullProductNames is the core extraction
// test: a nested product_tree (vendor -> product_name + product_family branches)
// plus a flat full_product_names array. It asserts the exact (vendor, product)
// pairs, including the (vendor, NULL) facet row for a bare vendor and the
// (NULL, product) rows from full_product_names.
func TestProductExtractionNestedTreeAndFullProductNames(t *testing.T) {
	pool, ctx := facetDB(t)

	tree := map[string]any{
		"branches": []any{
			map[string]any{
				"category": "vendor",
				"name":     "Example AG",
				"branches": []any{
					map[string]any{"category": "product_name", "name": "ExampleApp"},
					map[string]any{"category": "product_family", "name": "ExampleSuite"},
				},
			},
		},
		"full_product_names": []any{
			map[string]any{"name": "ExampleApp 1.0", "product_id": "CSAFPID-0001"},
			map[string]any{"name": "ExampleApp 2.0", "product_id": "CSAFPID-0002"},
		},
	}
	docID := insertDoc(t, ctx, pool, "PORTAL-PROD-NESTED",
		facetCSAF("PORTAL-PROD-NESTED", "en", withProductTree(tree)))

	got := productsFor(t, ctx, pool, docID)
	want := []pair{
		{"Example AG", ""},             // bare vendor facet row
		{"Example AG", "ExampleApp"},   // product_name under vendor
		{"Example AG", "ExampleSuite"}, // product_family under vendor
		{"", "ExampleApp 1.0"},         // full_product_names (no vendor context)
		{"", "ExampleApp 2.0"},
	}
	assertPairs(t, got, want)
}

// TestProductExtractionVendorWithoutProducts covers the edge case of a vendor
// branch with no product children: it must still surface as a (vendor, NULL)
// facet row so the vendor is filterable.
func TestProductExtractionVendorWithoutProducts(t *testing.T) {
	pool, ctx := facetDB(t)

	tree := map[string]any{
		"branches": []any{
			map[string]any{"category": "vendor", "name": "Lonely Vendor"},
		},
	}
	docID := insertDoc(t, ctx, pool, "PORTAL-PROD-BAREVENDOR",
		facetCSAF("PORTAL-PROD-BAREVENDOR", "en", withProductTree(tree)))

	assertPairs(t, productsFor(t, ctx, pool, docID), []pair{
		{"Lonely Vendor", ""},
	})
}

// TestProductExtractionDeeplyNestedTree covers a deeply nested tree where the
// vendor sits several non-vendor branch levels above the product leaves; the
// nearest-ancestor vendor must be threaded all the way down.
func TestProductExtractionDeeplyNestedTree(t *testing.T) {
	pool, ctx := facetDB(t)

	tree := map[string]any{
		"branches": []any{
			map[string]any{
				"category": "vendor",
				"name":     "DeepVendor",
				"branches": []any{
					map[string]any{
						"category": "product_family",
						"name":     "FamilyA",
						"branches": []any{
							map[string]any{
								"category": "product_family",
								"name":     "SubFamily",
								"branches": []any{
									map[string]any{"category": "product_name", "name": "DeepProduct"},
								},
							},
						},
					},
				},
			},
		},
	}
	docID := insertDoc(t, ctx, pool, "PORTAL-PROD-DEEP",
		facetCSAF("PORTAL-PROD-DEEP", "en", withProductTree(tree)))

	// DeepVendor is the nearest-ancestor vendor for every product/family leaf,
	// regardless of how many family levels sit between it and the leaf.
	assertPairs(t, productsFor(t, ctx, pool, docID), []pair{
		{"DeepVendor", ""},
		{"DeepVendor", "DeepProduct"},
		{"DeepVendor", "FamilyA"},
		{"DeepVendor", "SubFamily"},
	})
}

// TestProductExtractionMultipleVendors covers two vendor subtrees under the root:
// each product must be attributed to its own vendor, not bleed across siblings.
func TestProductExtractionMultipleVendors(t *testing.T) {
	pool, ctx := facetDB(t)

	tree := map[string]any{
		"branches": []any{
			map[string]any{
				"category": "vendor",
				"name":     "VendorOne",
				"branches": []any{
					map[string]any{"category": "product_name", "name": "ProductOne"},
				},
			},
			map[string]any{
				"category": "vendor",
				"name":     "VendorTwo",
				"branches": []any{
					map[string]any{"category": "product_name", "name": "ProductTwo"},
				},
			},
		},
	}
	docID := insertDoc(t, ctx, pool, "PORTAL-PROD-MULTI",
		facetCSAF("PORTAL-PROD-MULTI", "en", withProductTree(tree)))

	assertPairs(t, productsFor(t, ctx, pool, docID), []pair{
		{"VendorOne", ""},
		{"VendorOne", "ProductOne"},
		{"VendorTwo", ""},
		{"VendorTwo", "ProductTwo"},
	})
}

// TestProductExtractionDeduplicates covers a tree that names the same product
// twice (e.g. once in a branch, once in full_product_names with the same string)
// collapsing to a single row per distinct (vendor, product). The same product
// string under a vendor branch and as a vendor-less full name are distinct pairs.
func TestProductExtractionDeduplicates(t *testing.T) {
	pool, ctx := facetDB(t)

	tree := map[string]any{
		"branches": []any{
			map[string]any{
				"category": "vendor",
				"name":     "DupVendor",
				"branches": []any{
					map[string]any{"category": "product_name", "name": "DupProduct"},
					map[string]any{"category": "product_name", "name": "DupProduct"},
				},
			},
		},
		"full_product_names": []any{
			map[string]any{"name": "DupProduct"},
			map[string]any{"name": "DupProduct"},
		},
	}
	docID := insertDoc(t, ctx, pool, "PORTAL-PROD-DEDUP",
		facetCSAF("PORTAL-PROD-DEDUP", "en", withProductTree(tree)))

	// (DupVendor, DupProduct) collapses to one despite two branch entries;
	// (NULL, DupProduct) collapses to one despite two full_product_names; the
	// bare-vendor row is the third distinct pair.
	assertPairs(t, productsFor(t, ctx, pool, docID), []pair{
		{"DupVendor", ""},
		{"DupVendor", "DupProduct"},
		{"", "DupProduct"},
	})
}

func TestProductExtractionNoProductTreeYieldsNoRows(t *testing.T) {
	pool, ctx := facetDB(t)

	docID := insertDoc(t, ctx, pool, "PORTAL-PROD-NONE",
		facetCSAF("PORTAL-PROD-NONE", "en"))

	if got := productsFor(t, ctx, pool, docID); len(got) != 0 {
		t.Errorf("expected no product rows without a product_tree, got %v", got)
	}
}

func TestProductExtractionCascadesOnDelete(t *testing.T) {
	pool, ctx := facetDB(t)

	tree := map[string]any{
		"branches": []any{
			map[string]any{
				"category": "vendor",
				"name":     "CascadeVendor",
				"branches": []any{
					map[string]any{"category": "product_name", "name": "CascadeProduct"},
				},
			},
		},
	}
	docID := insertDoc(t, ctx, pool, "PORTAL-PROD-DEL",
		facetCSAF("PORTAL-PROD-DEL", "en", withProductTree(tree)))
	if got := productsFor(t, ctx, pool, docID); len(got) == 0 {
		t.Fatalf("setup: expected product rows, got none")
	}

	if _, err := pool.Exec(ctx, `DELETE FROM documents WHERE id = $1`, docID); err != nil {
		t.Fatalf("deleting document: %v", err)
	}

	var remaining int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM documents_products WHERE documents_id = $1`, docID).Scan(&remaining); err != nil {
		t.Fatalf("counting documents_products after delete: %v", err)
	}
	if remaining != 0 {
		t.Errorf("expected documents_products to cascade away, %d rows remain", remaining)
	}
}

func TestProductExtractionReExtractsOnUpdate(t *testing.T) {
	pool, ctx := facetDB(t)

	before := map[string]any{
		"branches": []any{
			map[string]any{
				"category": "vendor",
				"name":     "OldVendor",
				"branches": []any{
					map[string]any{"category": "product_name", "name": "OldProduct"},
				},
			},
		},
	}
	docID := insertDoc(t, ctx, pool, "PORTAL-PROD-UPD",
		facetCSAF("PORTAL-PROD-UPD", "en", withProductTree(before)))

	after := map[string]any{
		"branches": []any{
			map[string]any{
				"category": "vendor",
				"name":     "NewVendor",
				"branches": []any{
					map[string]any{"category": "product_name", "name": "NewProduct"},
				},
			},
		},
	}
	updated := facetCSAF("PORTAL-PROD-UPD", "en", withProductTree(after))
	if _, err := pool.Exec(ctx,
		`UPDATE documents SET document = $1::jsonb WHERE id = $2`, updated, docID); err != nil {
		t.Fatalf("updating document: %v", err)
	}

	assertPairs(t, productsFor(t, ctx, pool, docID), []pair{
		{"NewVendor", ""},
		{"NewVendor", "NewProduct"},
	})
}

// ---------------------------------------------------------------------------
// 3. Full-text search: language config
// ---------------------------------------------------------------------------

// matchesQuery reports whether the document's stored tsvector matches the query
// built with plainto_tsquery under the given config. This is the exact predicate
// a search handler would issue, and it is GIN-backed by documents_tsv_idx.
func matchesQuery(t *testing.T, ctx context.Context, pool *pgxpool.Pool, docID int, cfg, query string) bool {
	t.Helper()
	var matched bool
	if err := pool.QueryRow(ctx, `
		SELECT tsv @@ plainto_tsquery($1::regconfig, $2)
		FROM documents WHERE id = $3`, cfg, query, docID).Scan(&matched); err != nil {
		t.Fatalf("evaluating tsv match (cfg=%s, q=%q): %v", cfg, query, err)
	}
	return matched
}

// TestFTSGermanStemming: a de-DE document is stored with the german config, so a
// stem variant of a title word matches via plainto_tsquery('german', ...).
// "Schwachstellen" in the title stems to schwachstell; the query "Schwachstelle"
// stems to the same token under german.
func TestFTSGermanStemming(t *testing.T) {
	pool, ctx := facetDB(t)

	docID := insertDoc(t, ctx, pool, "PORTAL-FTS-DE",
		facetCSAF("PORTAL-FTS-DE", "de-DE", withTitle("Mehrere Schwachstellen in ExampleApp")))

	// Configuration was picked from lang: the row must be searchable as german.
	var lang string
	if err := pool.QueryRow(ctx, `SELECT lang FROM documents WHERE id = $1`, docID).Scan(&lang); err != nil {
		t.Fatalf("reading lang: %v", err)
	}
	if lang != "de-DE" {
		t.Fatalf("setup: lang = %q, want de-DE", lang)
	}

	if !matchesQuery(t, ctx, pool, docID, "german", "Schwachstelle") {
		t.Error("german query for a stem variant of a de-DE title word should match")
	}
}

// TestFTSEnglishStemming: an en-US document is stored with the english config;
// "vulnerabilities" in the title stems to vulner, matched by the query
// "vulnerability".
func TestFTSEnglishStemming(t *testing.T) {
	pool, ctx := facetDB(t)

	docID := insertDoc(t, ctx, pool, "PORTAL-FTS-EN",
		facetCSAF("PORTAL-FTS-EN", "en-US", withTitle("Multiple vulnerabilities in ExampleApp")))

	if !matchesQuery(t, ctx, pool, docID, "english", "vulnerability") {
		t.Error("english query for a stem variant of an en-US title word should match")
	}
}

// TestFTSGINIndexIsUsed confirms the FTS predicate is served by the GIN index on
// tsv, not a sequential scan, so the facet is actually indexed (ADR-0005). It
// forces an index scan and inspects the plan.
func TestFTSGINIndexIsUsed(t *testing.T) {
	pool, ctx := facetDB(t)

	// Populate enough rows that the planner would consider an index at all, and
	// disable seqscan so a usable index is preferred deterministically.
	for i := 0; i < 20; i++ {
		insertDoc(t, ctx, pool, "PORTAL-FTS-IDX-"+string(rune('a'+i)),
			facetCSAF("PORTAL-FTS-IDX-"+string(rune('a'+i)), "en-US",
				withTitle("Multiple vulnerabilities in ExampleApp")))
	}
	if _, err := pool.Exec(ctx, `SET enable_seqscan = off`); err != nil {
		t.Fatalf("disabling seqscan: %v", err)
	}

	rows, err := pool.Query(ctx, `
		EXPLAIN SELECT id FROM documents
		WHERE tsv @@ plainto_tsquery('english', 'vulnerability')`)
	if err != nil {
		t.Fatalf("EXPLAIN: %v", err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatalf("scanning plan line: %v", err)
		}
		plan.WriteString(line)
		plan.WriteString("\n")
	}
	if !strings.Contains(plan.String(), "documents_tsv_idx") {
		t.Errorf("expected the tsv GIN index to be used; plan was:\n%s", plan.String())
	}
}

// ---------------------------------------------------------------------------
// 4. FTS weighting
// ---------------------------------------------------------------------------

// TestFTSWeightingTitleRanksAboveNotes: the same term ranks higher when it
// appears in the title (weight A) than when it appears only in the notes (weight
// C). Two documents are scored for the same query and ordered by ts_rank.
func TestFTSWeightingTitleRanksAboveNotes(t *testing.T) {
	pool, ctx := facetDB(t)

	// "Spectre" only in the title (weight A).
	titleDoc := insertDoc(t, ctx, pool, "PORTAL-FTS-RANK-TITLE",
		facetCSAF("PORTAL-FTS-RANK-TITLE", "en-US",
			withTitle("Spectre advisory for ExampleApp"),
			withNotes("This document discusses an unrelated mitigation.")))

	// "Spectre" only in the notes (weight C); title is unrelated.
	notesDoc := insertDoc(t, ctx, pool, "PORTAL-FTS-RANK-NOTES",
		facetCSAF("PORTAL-FTS-RANK-NOTES", "en-US",
			withTitle("Generic advisory for ExampleApp"),
			withNotes("The affected component is impacted by Spectre.")))

	type ranked struct {
		id   int
		rank float64
	}
	rows, err := pool.Query(ctx, `
		SELECT id, ts_rank(tsv, plainto_tsquery('english', 'Spectre')) AS rank
		FROM documents
		WHERE tsv @@ plainto_tsquery('english', 'Spectre')
		ORDER BY rank DESC, id`)
	if err != nil {
		t.Fatalf("ranking query: %v", err)
	}
	defer rows.Close()
	var got []ranked
	for rows.Next() {
		var r ranked
		if err := rows.Scan(&r.id, &r.rank); err != nil {
			t.Fatalf("scanning ranked row: %v", err)
		}
		got = append(got, r)
	}

	if len(got) != 2 {
		t.Fatalf("expected both Spectre documents to match, got %d", len(got))
	}
	if got[0].id != titleDoc {
		t.Errorf("title-weighted doc %d should rank first, got order %v", titleDoc, got)
	}
	if got[1].id != notesDoc {
		t.Errorf("notes-weighted doc %d should rank second, got order %v", notesDoc, got)
	}
	if !(got[0].rank > got[1].rank) {
		t.Errorf("title rank %.4f should exceed notes rank %.4f", got[0].rank, got[1].rank)
	}
}

// ---------------------------------------------------------------------------
// 5. OQ-2 cross-language stemming limitation (characterize, do not fail)
// ---------------------------------------------------------------------------

// TestFTSCrossLanguageStemmingIsCurrentlyLimited encodes the known OQ-2
// limitation of the single-config-per-row tsvector design (ADR-0005): a query
// run under one language config does NOT stem-match a document stored under the
// other language config when the term only stems in the document's language.
//
// This is a CHARACTERIZATION test, not a bug: it documents present behaviour so
// that if a future pg_trgm (or dual-config) addition flips it, this test will
// fail loudly and force a conscious update. See the build-log "OQ-2 observation".
func TestFTSCrossLanguageStemmingIsCurrentlyLimited(t *testing.T) {
	pool, ctx := facetDB(t)

	// A de-DE document whose notes contain a German word that only the german
	// stemmer reduces: "Bedrohungen" -> bedroh.
	deDoc := insertDoc(t, ctx, pool, "PORTAL-FTS-XLANG-DE",
		facetCSAF("PORTAL-FTS-XLANG-DE", "de-DE",
			withTitle("Sicherheitshinweis"),
			withNotes("Es wurden mehrere Bedrohungen erkannt.")))

	// An en-US document whose title contains an English word that only the
	// english stemmer reduces: "vulnerabilities" -> vulner.
	enDoc := insertDoc(t, ctx, pool, "PORTAL-FTS-XLANG-EN",
		facetCSAF("PORTAL-FTS-XLANG-EN", "en-US",
			withTitle("Multiple vulnerabilities in ExampleApp")))

	// Same-config baselines: each document IS found under its own language.
	if !matchesQuery(t, ctx, pool, deDoc, "german", "Bedrohung") {
		t.Fatal("baseline: german query should match the de-DE document")
	}
	if !matchesQuery(t, ctx, pool, enDoc, "english", "vulnerability") {
		t.Fatal("baseline: english query should match the en-US document")
	}

	// The limitation: cross-language queries miss. If either of these starts
	// matching, the FTS model gained cross-language reach and this test (and the
	// OQ-2 note) must be revisited.
	if matchesQuery(t, ctx, pool, deDoc, "english", "Bedrohung") {
		t.Error("OQ-2 changed: english query now stem-matches the de-DE document " +
			"(german-stemmed term) — revisit the cross-language limitation")
	}
	if matchesQuery(t, ctx, pool, enDoc, "german", "vulnerability") {
		t.Error("OQ-2 changed: german query now stem-matches the en-US document " +
			"(english-stemmed term) — revisit the cross-language limitation")
	}
}
