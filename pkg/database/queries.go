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
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Ping checks that the database is reachable. The health endpoint uses it to
// distinguish a live API from one whose database has gone away.
func (db *DB) Ping(ctx context.Context) error {
	if err := db.pool.Ping(ctx); err != nil {
		return fmt.Errorf("pinging database: %w", err)
	}
	return nil
}

// LastIngest returns the most recent successful ingestion time and whether one
// has happened yet. The poll loop advances ingest_state.updated after every
// fully successful cycle (see ingest.RunOnce), so the newest updated value is a
// good "last successful ingest" signal for the health endpoint. ok is false on a
// freshly migrated database that has not polled yet.
func (db *DB) LastIngest(ctx context.Context) (time.Time, bool, error) {
	const query = `SELECT max(updated) FROM ingest_state`
	var last *time.Time
	if err := db.pool.QueryRow(ctx, query).Scan(&last); err != nil {
		return time.Time{}, false, fmt.Errorf("reading last ingest time: %w", err)
	}
	if last == nil {
		return time.Time{}, false, nil
	}
	return *last, true, nil
}

// Advisory is one row of the advisory list: the latest revision of an advisory,
// projected to the facet fields the result list and detail header need (spec
// §7/§8). Nullable generated columns are modelled as pointers so the JSON omits
// them when the source CSAF document did not carry the value.
type Advisory struct {
	ID                 int64      `json:"id"`
	TrackingID         string     `json:"tracking_id"`
	PublisherName      *string    `json:"publisher_name"`
	Title              *string    `json:"title"`
	CurrentReleaseDate *time.Time `json:"current_release_date"`
	InitialReleaseDate *time.Time `json:"initial_release_date"`
	TLP                *string    `json:"tlp"`
	Category           *string    `json:"category"`
	Critical           *float64   `json:"critical"`
	CVSSv2Score        *float64   `json:"cvss_v2_score"`
	CVSSv3Score        *float64   `json:"cvss_v3_score"`
	Lang               *string    `json:"lang"`
	TrackingStatus     *string    `json:"tracking_status"`
	Version            *string    `json:"version"`
	// CVEs are the CVE ids extracted from the document (documents_cves),
	// aggregated so the list view can show them without a second round-trip. Empty
	// for an advisory with no CVEs; never null in the JSON.
	CVEs []string `json:"cves"`
}

// AdvisoryList is a page of advisories plus the total count of rows matching the
// query (before limit/offset) so the caller can render pagination.
type AdvisoryList struct {
	Advisories []Advisory `json:"advisories"`
	Total      int64      `json:"total"`
}

// ListSort names a column the advisory list may be ordered by. The set is a
// closed whitelist so the column name is never derived from caller input — only
// the chosen direction varies (see ListAdvisories), keeping the query free of
// SQL injection surface.
type ListSort string

const (
	// SortCurrentReleaseDate orders by the latest revision's release date.
	SortCurrentReleaseDate ListSort = "current_release_date"
	// SortCritical orders by the effective CVSS severity score.
	SortCritical ListSort = "critical"
)

// ListOptions controls a single page of the advisory list: the combinable facet
// filters plus pagination and ordering.
type ListOptions struct {
	// Filters holds the combinable search/facet predicates (q/cve/severity/...).
	// An empty Filters narrows nothing beyond the always-on invariants.
	Filters Filters
	// Limit is the maximum number of rows to return. Callers are responsible for
	// clamping it to a sane bound before calling.
	Limit int
	// Offset is the number of rows to skip for pagination.
	Offset int
	// Sort selects the order column (whitelisted).
	Sort ListSort
	// Descending reverses the sort order when true.
	Descending bool
}

// orderClause maps the whitelisted (sort, direction) pair to a fixed ORDER BY
// fragment. Because both the column and the direction come from this closed set
// — never from raw caller input — the fragment is safe to interpolate. A stable
// tiebreaker on the document id keeps pagination deterministic across equal
// sort keys.
func (o ListOptions) orderClause() string {
	column := "d.current_release_date"
	if o.Sort == SortCritical {
		column = "d.critical"
	}
	direction := "ASC"
	if o.Descending {
		direction = "DESC"
	}
	// NULLS LAST keeps documents that lack the sort value (e.g. no CVSS score)
	// from dominating a descending sort.
	return fmt.Sprintf("ORDER BY %s %s NULLS LAST, d.id DESC", column, direction)
}

// ListAdvisories returns one page of the latest revision per advisory, filtered
// to publishable TLP labels, excluding withdrawn advisories, and narrowed by the
// combinable facet filters in opts.Filters.
//
// publishableTLP is the canonical upper-case set of TLP labels permitted in the
// public portal (config.PublishableTLPSet). It is matched as a parameter against
// upper(d.tlp), so even a document whose TLP somehow fell outside the ingest
// gate can never leak through the read API (defense in depth, spec §8). An
// optional tlp filter is intersected with this set, never substituted for it.
//
// All caller inputs are bound as query parameters (see filters.go); the only
// interpolated SQL text is the ORDER BY fragment built from a closed whitelist
// (orderClause) and, when a free-text query is present, the ts_rank ordering
// expression that references the same bound query parameter.
//
// CVEs are aggregated per document via a lateral subquery so a multi-CVE
// advisory yields one row (no fan-out), keeping the page size and total count
// honest.
func (db *DB) ListAdvisories(
	ctx context.Context,
	opts ListOptions,
	publishableTLP []string,
) (AdvisoryList, error) {
	// The WHERE clause (and its bound args) is shared by the count and the page
	// query so they stay in lock-step over the identical filtered set.
	qb := newFilteredWhere(opts.Filters, publishableTLP)
	whereBody, args := qb.where()
	const from = `
		FROM documents d
		JOIN advisories a ON a.id = d.advisories_id`
	where := from + "\n\t\tWHERE " + whereBody

	var total int64
	if err := db.pool.QueryRow(ctx, `SELECT count(*) `+where, args...).Scan(&total); err != nil {
		return AdvisoryList{}, fmt.Errorf("counting advisories: %w", err)
	}

	// When a free-text query is active, order by relevance first, then the normal
	// sort. The query string is already bound as the last filter parameter before
	// any pagination args, so its placeholder index is len(args).
	orderBy := opts.orderClause()
	if strings.TrimSpace(opts.Filters.Query) != "" {
		orderBy = "ORDER BY " + ftsRankExpr(qb.ftsParamIndex) + " DESC, " +
			strings.TrimPrefix(opts.orderClause(), "ORDER BY ")
	}

	limitIdx := qb.bind(opts.Limit)
	offsetIdx := qb.bind(opts.Offset)
	_, args = qb.where() // refresh args to include limit/offset

	query := fmt.Sprintf(`
		SELECT
			d.id,
			a.tracking_id,
			d.publisher_name,
			d.title,
			d.current_release_date,
			d.initial_release_date,
			d.tlp,
			d.category,
			d.critical,
			d.cvss_v2_score,
			d.cvss_v3_score,
			d.lang,
			d.tracking_status::text,
			d.version,
			coalesce((
				SELECT array_agg(uc.cve ORDER BY uc.cve)
				FROM documents_cves dc
				JOIN unique_cves uc ON uc.id = dc.cve_id
				WHERE dc.documents_id = d.id), '{}') AS cves
		%s
		%s
		LIMIT $%d OFFSET $%d`, where, orderBy, limitIdx, offsetIdx)

	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return AdvisoryList{}, fmt.Errorf("listing advisories: %w", err)
	}
	defer rows.Close()

	advisories := make([]Advisory, 0)
	for rows.Next() {
		var adv Advisory
		if err := rows.Scan(
			&adv.ID,
			&adv.TrackingID,
			&adv.PublisherName,
			&adv.Title,
			&adv.CurrentReleaseDate,
			&adv.InitialReleaseDate,
			&adv.TLP,
			&adv.Category,
			&adv.Critical,
			&adv.CVSSv2Score,
			&adv.CVSSv3Score,
			&adv.Lang,
			&adv.TrackingStatus,
			&adv.Version,
			&adv.CVEs,
		); err != nil {
			return AdvisoryList{}, fmt.Errorf("scanning advisory row: %w", err)
		}
		advisories = append(advisories, adv)
	}
	if err := rows.Err(); err != nil {
		return AdvisoryList{}, fmt.Errorf("iterating advisory rows: %w", err)
	}

	return AdvisoryList{Advisories: advisories, Total: total}, nil
}

// ErrDocumentNotFound is returned by GetDocument when no publishable document
// with the given id exists. A non-publishable-TLP document is reported as not
// found rather than forbidden so the API never confirms the existence of a
// restricted document (spec §12). A withdrawn advisory's document IS still
// served: permalink stability is intentional, and the "no longer published"
// notice is a later frontend concern driven by advisory metadata.
var ErrDocumentNotFound = fmt.Errorf("document not found")

// GetDocument returns the stored CSAF JSON bytes for one document revision,
// suitable for serving verbatim with Content-Type application/json. It returns
// ErrDocumentNotFound for a missing id or a document whose TLP is not in
// publishableTLP. The bytes are produced by Postgres from the jsonb column, so
// they are valid JSON but canonicalised (whitespace/key order may differ from
// the originally downloaded file); this is the document the webview consumes via
// convertToDocModel.
func (db *DB) GetDocument(ctx context.Context, id int64, publishableTLP []string) ([]byte, error) {
	const query = `
		SELECT document::text
		FROM documents
		WHERE id = $1
		  AND upper(tlp) = ANY($2::text[])`
	var raw []byte
	switch err := db.pool.QueryRow(ctx, query, id, publishableTLP).Scan(&raw); {
	case err == nil:
		return raw, nil
	case err == pgx.ErrNoRows:
		return nil, ErrDocumentNotFound
	default:
		return nil, fmt.Errorf("reading document %d: %w", id, err)
	}
}
