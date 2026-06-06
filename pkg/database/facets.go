// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package database

import (
	"context"
	"fmt"
)

// FacetCap bounds the number of values returned for an otherwise unbounded
// facet (publishers, vendors, products, ...). The most frequent values are
// returned and the rest are dropped; the response flags whether a facet was
// truncated so the UI can say "showing top N". The cap keeps a pathological
// corpus (thousands of distinct vendors) from producing an enormous sidebar
// payload.
const FacetCap = 50

// FacetCount is one facet value and how many advisories in the current filtered
// set carry it.
type FacetCount struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

// FacetGroup is the counted values for one facet dimension. Capped is true when
// the dimension had more distinct values than FacetCap and the list was
// truncated to the most frequent ones.
type FacetGroup struct {
	Values []FacetCount `json:"values"`
	Capped bool         `json:"capped"`
}

// Facets is the full set of facet counts for the sidebar. Each dimension is
// counted over the SAME filtered set the result list shows (standard drill-down:
// every active filter — including the one being counted — applies). Severity is
// bucketed into the CVSS v3 bands.
type Facets struct {
	Publisher FacetGroup `json:"publisher"`
	Vendor    FacetGroup `json:"vendor"`
	Product   FacetGroup `json:"product"`
	Category  FacetGroup `json:"category"`
	TLP       FacetGroup `json:"tlp"`
	Lang      FacetGroup `json:"lang"`
	Severity  FacetGroup `json:"severity"`
}

// ComputeFacets returns the facet values and counts for the currently filtered
// advisory set (spec §8/§13). It applies the identical WHERE body as
// ListAdvisories — the invariants (latest revision, not withdrawn, publishable
// TLP) plus every active filter in f — so the counts describe exactly the set
// the list shows.
//
// Drill-down semantics: this uses the standard "all active filters apply"
// model — the facet being counted is NOT self-excluded. Selecting a publisher
// therefore shrinks every other facet's counts (including the publisher facet,
// which then shows just the selected publisher). This is the simplest
// consistent behaviour and matches the result list one-to-one.
//
// Unbounded facets (publisher, vendor, product) are capped at FacetCap most
// frequent values; the group's Capped flag and a log note record any truncation.
// All inputs are bound parameters (newFilteredWhere); no user value is
// interpolated into SQL.
func (db *DB) ComputeFacets(
	ctx context.Context,
	f Filters,
	publishableTLP []string,
) (Facets, error) {
	var facets Facets

	// Column-backed facets on documents: one grouped count each.
	var err error
	if facets.Publisher, err = db.facetColumn(ctx, f, publishableTLP, "d.publisher_name", true); err != nil {
		return Facets{}, fmt.Errorf("publisher facet: %w", err)
	}
	if facets.Category, err = db.facetColumn(ctx, f, publishableTLP, "d.category", false); err != nil {
		return Facets{}, fmt.Errorf("category facet: %w", err)
	}
	if facets.TLP, err = db.facetColumn(ctx, f, publishableTLP, "upper(d.tlp)", false); err != nil {
		return Facets{}, fmt.Errorf("tlp facet: %w", err)
	}
	if facets.Lang, err = db.facetColumn(ctx, f, publishableTLP, "d.lang", false); err != nil {
		return Facets{}, fmt.Errorf("lang facet: %w", err)
	}

	// Product / vendor live in the documents_products side table; count distinct
	// documents per value so a multi-product document is counted once per value.
	if facets.Vendor, err = db.facetProduct(ctx, f, publishableTLP, "dp.vendor"); err != nil {
		return Facets{}, fmt.Errorf("vendor facet: %w", err)
	}
	if facets.Product, err = db.facetProduct(ctx, f, publishableTLP, "dp.product"); err != nil {
		return Facets{}, fmt.Errorf("product facet: %w", err)
	}

	// Severity buckets: one count per CVSS v3 band over the filtered set.
	if facets.Severity, err = db.facetSeverity(ctx, f, publishableTLP); err != nil {
		return Facets{}, fmt.Errorf("severity facet: %w", err)
	}

	return facets, nil
}

// facetColumn counts distinct values of a documents column (e.g. publisher_name,
// category) over the filtered set, ordered by descending count. capped applies
// the FacetCap top-N limit; unbounded facets (publisher) pass capped=true.
//
// expr must be a fixed, trusted column expression chosen by ComputeFacets — it
// is interpolated into the query and is NEVER derived from caller input. Every
// caller-supplied value reaches the query only through the bound parameters in
// newFilteredWhere.
func (db *DB) facetColumn(
	ctx context.Context,
	f Filters,
	publishableTLP []string,
	expr string,
	capped bool,
) (FacetGroup, error) {
	qb := newFilteredWhere(f, publishableTLP)
	whereBody, args := qb.where()

	// Fetch one extra row beyond the cap so we can detect (and flag) truncation.
	limit := FacetCap + 1
	query := fmt.Sprintf(`
		SELECT %[1]s AS value, count(*) AS n
		FROM documents d
		JOIN advisories a ON a.id = d.advisories_id
		WHERE %[2]s
		  AND %[1]s IS NOT NULL
		GROUP BY %[1]s
		ORDER BY n DESC, value ASC
		LIMIT %[3]d`, expr, whereBody, limit)

	return scanFacetGroup(ctx, db, query, args, capped)
}

// facetProduct counts distinct documents per vendor/product value via the
// documents_products side table, joined back to the filtered document set. The
// count is over distinct documents so a document listing a vendor under several
// products is counted once for that vendor.
func (db *DB) facetProduct(
	ctx context.Context,
	f Filters,
	publishableTLP []string,
	expr string,
) (FacetGroup, error) {
	qb := newFilteredWhere(f, publishableTLP)
	whereBody, args := qb.where()

	limit := FacetCap + 1
	query := fmt.Sprintf(`
		SELECT %[1]s AS value, count(DISTINCT d.id) AS n
		FROM documents d
		JOIN advisories a ON a.id = d.advisories_id
		JOIN documents_products dp ON dp.documents_id = d.id
		WHERE %[2]s
		  AND %[1]s IS NOT NULL
		GROUP BY %[1]s
		ORDER BY n DESC, value ASC
		LIMIT %[3]d`, expr, whereBody, limit)

	// Vendor and product are always treated as cappable (unbounded) facets.
	return scanFacetGroup(ctx, db, query, args, true)
}

// facetSeverity counts the filtered set into the CVSS v3 severity bands. A single
// pass classifies each row by its critical score (NULL or 0 -> none) so the band
// counts always sum to the filtered total.
func (db *DB) facetSeverity(
	ctx context.Context,
	f Filters,
	publishableTLP []string,
) (FacetGroup, error) {
	qb := newFilteredWhere(f, publishableTLP)
	whereBody, args := qb.where()

	// The CASE mirrors the bands in severityBands (none/low/medium/high/critical).
	query := fmt.Sprintf(`
		SELECT band, count(*) AS n
		FROM (
			SELECT CASE
				WHEN d.critical IS NULL OR d.critical = 0 THEN 'none'
				WHEN d.critical < 4.0  THEN 'low'
				WHEN d.critical < 7.0  THEN 'medium'
				WHEN d.critical < 9.0  THEN 'high'
				ELSE 'critical'
			END AS band
			FROM documents d
			JOIN advisories a ON a.id = d.advisories_id
			WHERE %s
		) AS classified
		GROUP BY band`, whereBody)

	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return FacetGroup{}, fmt.Errorf("querying severity buckets: %w", err)
	}
	defer rows.Close()

	counts := map[string]int64{}
	for rows.Next() {
		var band string
		var n int64
		if err := rows.Scan(&band, &n); err != nil {
			return FacetGroup{}, fmt.Errorf("scanning severity bucket: %w", err)
		}
		counts[band] = n
	}
	if err := rows.Err(); err != nil {
		return FacetGroup{}, fmt.Errorf("iterating severity buckets: %w", err)
	}

	// Emit the bands in the canonical low-to-high order, including zero counts so
	// the UI can render every bucket consistently.
	group := FacetGroup{Values: make([]FacetCount, 0, len(SeverityBandNames()))}
	for _, band := range SeverityBandNames() {
		group.Values = append(group.Values, FacetCount{Value: band, Count: counts[band]})
	}
	return group, nil
}

// scanFacetGroup runs query and collects the (value, count) rows into a
// FacetGroup. When cappable is true and the query returned more than FacetCap
// rows (it fetches FacetCap+1), the extra row is dropped and Capped is set.
func scanFacetGroup(
	ctx context.Context,
	db *DB,
	query string,
	args []any,
	cappable bool,
) (FacetGroup, error) {
	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return FacetGroup{}, fmt.Errorf("querying facet: %w", err)
	}
	defer rows.Close()

	values := make([]FacetCount, 0)
	for rows.Next() {
		var fc FacetCount
		if err := rows.Scan(&fc.Value, &fc.Count); err != nil {
			return FacetGroup{}, fmt.Errorf("scanning facet value: %w", err)
		}
		values = append(values, fc)
	}
	if err := rows.Err(); err != nil {
		return FacetGroup{}, fmt.Errorf("iterating facet values: %w", err)
	}

	group := FacetGroup{}
	if cappable && len(values) > FacetCap {
		group.Values = values[:FacetCap]
		group.Capped = true
	} else {
		group.Values = values
	}
	return group, nil
}
