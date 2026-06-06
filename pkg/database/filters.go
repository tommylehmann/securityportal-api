// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package database

import (
	"fmt"
	"strings"
	"time"
)

// Filters is the combinable facet/search filter set for the advisory list and
// the facet-count endpoint (spec §8, §13). Every field is optional; an unset
// field contributes no predicate. The same struct drives both ListAdvisories
// and Facets so the two always agree on what "the current result set" is.
//
// All values are applied as bound query parameters — none is ever concatenated
// into SQL text — so the filter surface carries no SQL-injection risk (the only
// interpolated SQL remains the whitelisted ORDER BY in ListOptions.orderClause).
type Filters struct {
	// Query is the free-text search term matched against documents.tsv. Empty or
	// whitespace-only is treated as no filter.
	Query string
	// CVE is a case-insensitive CVE id prefix matched via documents_cves.
	CVE string
	// Severity restricts to one or more CVSS v3 severity bands (none/low/medium/
	// high/critical), evaluated against the critical column.
	Severity []string
	// ScoreMin / ScoreMax bound the critical (effective CVSS) score. A nil pointer
	// leaves that side of the range open.
	ScoreMin *float64
	ScoreMax *float64
	// From / To bound current_release_date (inclusive). A zero time leaves that
	// side open.
	From time.Time
	To   time.Time
	// Product / Vendor match a product or vendor name via documents_products,
	// using an EXISTS subquery so a document with many products is not duplicated
	// in the result set.
	Product string
	Vendor  string
	// Publisher matches publisher_name exactly.
	Publisher string
	// TLP restricts to one or more TLP labels. It is always intersected with the
	// publishable set in SQL, so a tlp=RED parameter can never surface a
	// restricted document.
	TLP []string
	// Category matches the CSAF document category exactly.
	Category string
	// Lang matches the document language exactly.
	Lang string
}

// severityRange maps a severity band name to its inclusive CVSS v3 base-score
// bounds (per the CVSS v3 specification): none = 0.0, low 0.1–3.9, medium
// 4.0–6.9, high 7.0–8.9, critical 9.0–10.0.
type severityRange struct {
	min float64
	max float64
}

var severityBands = map[string]severityRange{
	"none":     {0.0, 0.0},
	"low":      {0.1, 3.9},
	"medium":   {4.0, 6.9},
	"high":     {7.0, 8.9},
	"critical": {9.0, 10.0},
}

// SeverityBandNames returns the recognised severity band names. The web layer
// validates incoming severity params against this set so a malformed band is a
// 400 rather than silently matching nothing.
func SeverityBandNames() []string {
	return []string{"none", "low", "medium", "high", "critical"}
}

// IsSeverityBand reports whether name is a recognised severity band.
func IsSeverityBand(name string) bool {
	_, ok := severityBands[strings.ToLower(name)]
	return ok
}

// queryBuilder accumulates parameterised WHERE conditions and their bound
// arguments. Placeholders are numbered ($1, $2, ...) in the order parameters are
// bound, so the args slice it returns lines up with the generated SQL. It never
// embeds caller-supplied values into the SQL text — values flow only through
// bound parameters, which is the project's SQL-injection guarantee.
type queryBuilder struct {
	conditions []string
	args       []any
	// ftsParamIndex is the 1-based placeholder index of the bound free-text query
	// string, or 0 when no free-text query is active. ListAdvisories reuses it to
	// build the matching ts_rank ordering expression without rebinding the term.
	ftsParamIndex int
}

// bind records value as the next positional parameter and returns its 1-based
// placeholder index (e.g. 3 for "$3"). The caller formats the condition text
// around the returned index, so a condition may reference one or several bound
// parameters.
func (b *queryBuilder) bind(value any) int {
	b.args = append(b.args, value)
	return len(b.args)
}

// addf binds value as the next parameter and appends a condition formatted with
// its placeholder index. The template must contain exactly one %d.
func (b *queryBuilder) addf(template string, value any) {
	b.conditions = append(b.conditions, fmt.Sprintf(template, b.bind(value)))
}

// addCond appends an already-formed condition (its placeholders obtained via
// bind) without binding a further parameter.
func (b *queryBuilder) addCond(condition string) {
	b.conditions = append(b.conditions, condition)
}

// where returns the assembled WHERE body (without the leading WHERE keyword),
// AND-joined, plus the positional arguments in placeholder order.
func (b *queryBuilder) where() (string, []any) {
	return strings.Join(b.conditions, "\n  AND "), b.args
}

// newFilteredWhere builds the shared WHERE body for the advisory result set:
// the invariants (latest revision only, never withdrawn, publishable TLP only)
// plus every active facet filter from f, all as bound parameters. The returned
// builder's args are positional starting at $1; the caller appends any further
// parameters (limit/offset) after them.
//
// The invariants are added first and unconditionally so a filter change can
// never drop them. The publishable-TLP gate is intersected with any tlp filter
// rather than replaced by it, which is why a tlp=RED parameter cannot leak a
// restricted document (see the TLP handling below).
func newFilteredWhere(f Filters, publishableTLP []string) *queryBuilder {
	b := &queryBuilder{}

	// --- Invariants (spec §8): always applied, never overridable by a filter. ---
	b.addCond("d.latest")
	b.addCond("NOT a.withdrawn")
	b.addf("upper(d.tlp) = ANY($%d::text[])", publishableTLP)

	// --- Optional facet filters. ---

	// Free-text search across all relevant text-search configs (OQ-2 mitigation,
	// see ftsCondition). A blank/whitespace query is treated as no filter.
	if cond := ftsCondition(b, f.Query); cond != "" {
		b.addCond(cond)
	}

	// CVE: case-insensitive prefix match via the extracted CVE links. EXISTS keeps
	// a document with several CVEs from being duplicated in the result set.
	if cve := strings.TrimSpace(f.CVE); cve != "" {
		idx := b.bind(strings.ToUpper(cve) + "%")
		b.addCond(fmt.Sprintf(`EXISTS (
			SELECT 1 FROM documents_cves dc
			JOIN unique_cves uc ON uc.id = dc.cve_id
			WHERE dc.documents_id = d.id AND upper(uc.cve) LIKE $%d)`, idx))
	}

	// Severity bands: each band is a (min,max) range on critical; multiple bands
	// are OR-ed together. NULL critical (no CVSS score) only matches the explicit
	// "none" band via a separate clause below.
	if cond := severityCondition(b, f.Severity); cond != "" {
		b.addCond(cond)
	}

	// Numeric CVSS range on the effective score.
	if f.ScoreMin != nil {
		b.addf("d.critical >= $%d", *f.ScoreMin)
	}
	if f.ScoreMax != nil {
		b.addf("d.critical <= $%d", *f.ScoreMax)
	}

	// Date range on the current release date (inclusive bounds).
	if !f.From.IsZero() {
		b.addf("d.current_release_date >= $%d", f.From)
	}
	if !f.To.IsZero() {
		b.addf("d.current_release_date <= $%d", f.To)
	}

	// Product / vendor: EXISTS subqueries (no JOIN) so multi-product documents are
	// not duplicated. Case-insensitive exact match on the extracted facet value.
	if product := strings.TrimSpace(f.Product); product != "" {
		idx := b.bind(product)
		b.addCond(fmt.Sprintf(`EXISTS (
			SELECT 1 FROM documents_products dp
			WHERE dp.documents_id = d.id AND lower(dp.product) = lower($%d))`, idx))
	}
	if vendor := strings.TrimSpace(f.Vendor); vendor != "" {
		idx := b.bind(vendor)
		b.addCond(fmt.Sprintf(`EXISTS (
			SELECT 1 FROM documents_products dp
			WHERE dp.documents_id = d.id AND lower(dp.vendor) = lower($%d))`, idx))
	}

	if publisher := strings.TrimSpace(f.Publisher); publisher != "" {
		b.addf("d.publisher_name = $%d", publisher)
	}

	// TLP filter: intersected with — never substituted for — the publishable set.
	// The publishable-TLP invariant above already constrains rows to publishable
	// labels; this only narrows further to the requested labels, so a request for
	// a restricted label simply matches nothing rather than leaking it.
	if len(f.TLP) > 0 {
		b.addf("upper(d.tlp) = ANY($%d::text[])", upperAll(f.TLP))
	}

	if category := strings.TrimSpace(f.Category); category != "" {
		b.addf("d.category = $%d", category)
	}
	if lang := strings.TrimSpace(f.Lang); lang != "" {
		b.addf("d.lang = $%d", lang)
	}

	return b
}

// ftsCondition adds the free-text parameter (when present) and returns the FTS
// match condition, or "" when the query is blank.
//
// OQ-2 mitigation (v1): each document's tsv is built with a single text-search
// config chosen from its language (german / english / simple, see ADR-0005), so
// a query parsed under one config would miss documents indexed under another. To
// find both German and English documents from one query box we OR the query
// across all three configs:
//
//	tsv @@ (websearch_to_tsquery('german', $q)
//	     || websearch_to_tsquery('english', $q)
//	     || websearch_to_tsquery('simple', $q))
//
// websearch_to_tsquery is the user-friendly parser (handles quoted phrases and
// bare words without raising on punctuation). The single bound $q parameter is
// reused by all three calls. This is the v1 cross-language workaround for the
// single-config-per-row limitation; a future pg_trgm index could supersede it.
func ftsCondition(b *queryBuilder, query string) string {
	q := strings.TrimSpace(query)
	if q == "" {
		return ""
	}
	idx := b.bind(q)
	b.ftsParamIndex = idx
	return fmt.Sprintf(`d.tsv @@ (
		websearch_to_tsquery('german',  $%[1]d) ||
		websearch_to_tsquery('english', $%[1]d) ||
		websearch_to_tsquery('simple',  $%[1]d))`, idx)
}

// ftsRankExpr is the relevance score used to order results when a free-text
// query is active. It mirrors the multi-config match in ftsCondition so the rank
// reflects whichever config produced the hit. paramIdx is the placeholder index
// of the already-bound query string.
func ftsRankExpr(paramIdx int) string {
	return fmt.Sprintf(`ts_rank(d.tsv,
		websearch_to_tsquery('german',  $%[1]d) ||
		websearch_to_tsquery('english', $%[1]d) ||
		websearch_to_tsquery('simple',  $%[1]d))`, paramIdx)
}

// severityCondition adds the score-band parameters (when any) and returns an
// OR-ed band predicate, or "" when no band is requested. Bands other than "none"
// are inclusive numeric ranges on critical; "none" matches a zero score AND a
// missing score (NULL critical), since a document without any CVSS score has no
// severity. Unknown band names are skipped (the web layer rejects them with 400
// before they get here).
func severityCondition(b *queryBuilder, bands []string) string {
	clauses := make([]string, 0, len(bands))
	for _, band := range bands {
		r, ok := severityBands[strings.ToLower(strings.TrimSpace(band))]
		if !ok {
			continue
		}
		if r.min == 0.0 && r.max == 0.0 {
			// "none": no/zero severity. A NULL critical (document carries no CVSS
			// score) belongs here, alongside an explicit 0.0.
			lo := b.bind(r.min)
			clauses = append(clauses,
				fmt.Sprintf("(d.critical IS NULL OR d.critical = $%d)", lo))
			continue
		}
		lo := b.bind(r.min)
		hi := b.bind(r.max)
		clauses = append(clauses,
			fmt.Sprintf("(d.critical >= $%d AND d.critical <= $%d)", lo, hi))
	}
	if len(clauses) == 0 {
		return ""
	}
	return "(" + strings.Join(clauses, " OR ") + ")"
}

// upperAll upper-cases every element of in, returning a new slice. Used to
// normalise TLP labels before the ANY comparison against upper(d.tlp).
func upperAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToUpper(strings.TrimSpace(s))
	}
	return out
}
