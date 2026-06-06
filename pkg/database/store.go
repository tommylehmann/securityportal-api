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
	"time"

	"github.com/jackc/pgx/v5"
)

// StoreResult reports whether a StoreDocument call actually inserted a new
// document revision (Inserted == true) or recognised an identical revision it
// had already stored (Inserted == false). The latter is the idempotent re-run
// case: seeing the same revision twice is a no-op.
type StoreResult struct {
	// Inserted is true when a new document revision row was written.
	Inserted bool
}

// StoreDocument persists one verified advisory revision in a single transaction.
//
// document is the full CSAF JSON (stored into documents.document, from which all
// generated facet columns are derived); original is the exact downloaded bytes
// (stored into documents.original) and may be nil. trackingID and publisher key
// the advisories parent.
//
// The advisory parent is upserted on (tracking_id, publisher); if it had been
// tombstoned (withdrawn) by a previous deletion sweep, reappearing here clears
// the marker. The document is inserted with ON CONFLICT DO NOTHING on the
// revision unique constraint so re-seeing an identical revision is idempotent.
// The latest/latest_document_id bookkeeping is left to the insert_document
// trigger, which promotes a newer revision and refuses to regress to an older
// late-arriving one.
func (db *DB) StoreDocument(
	ctx context.Context,
	trackingID, publisher string,
	document map[string]any,
	original []byte,
) (StoreResult, error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return StoreResult{}, fmt.Errorf("beginning store transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	advisoryID, err := upsertAdvisory(ctx, tx, trackingID, publisher)
	if err != nil {
		return StoreResult{}, err
	}

	// ON CONFLICT DO NOTHING on the revision unique constraint makes a repeated
	// identical revision a no-op. RETURNING id yields no row in that case, which
	// pgx surfaces as ErrNoRows; we read that as "already stored".
	const insertDocument = `
		INSERT INTO documents (advisories_id, document, original)
		VALUES ($1, $2, $3)
		ON CONFLICT (advisories_id, version, rev_history_length, tracking_status)
		DO NOTHING
		RETURNING id`
	var documentID int
	err = tx.QueryRow(ctx, insertDocument, advisoryID, document, original).Scan(&documentID)
	switch {
	case err == nil:
		// New revision inserted.
	case err == pgx.ErrNoRows:
		// Identical revision already present; nothing to do.
		if err := tx.Commit(ctx); err != nil {
			return StoreResult{}, fmt.Errorf("committing store transaction: %w", err)
		}
		return StoreResult{Inserted: false}, nil
	default:
		return StoreResult{}, fmt.Errorf("inserting document revision: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return StoreResult{}, fmt.Errorf("committing store transaction: %w", err)
	}
	return StoreResult{Inserted: true}, nil
}

// upsertAdvisory inserts the advisory parent or, if it already exists, returns
// its id. A previously withdrawn advisory that is being stored again has its
// tombstone cleared: it is published once more.
func upsertAdvisory(ctx context.Context, tx pgx.Tx, trackingID, publisher string) (int, error) {
	const upsert = `
		INSERT INTO advisories (tracking_id, publisher)
		VALUES ($1, $2)
		ON CONFLICT (tracking_id, publisher) DO UPDATE
			SET withdrawn = false,
			    withdrawn_at = NULL
		RETURNING id`
	var id int
	if err := tx.QueryRow(ctx, upsert, trackingID, publisher).Scan(&id); err != nil {
		return 0, fmt.Errorf("upserting advisory %q/%q: %w", publisher, trackingID, err)
	}
	return id, nil
}

// AdvisoryKey identifies an advisory parent by its natural key.
type AdvisoryKey struct {
	TrackingID string
	Publisher  string
}

// Watermark returns the stored incremental-poll watermark for feedURL and
// whether one exists. The first poll of a feed has no watermark, so ok is false
// and the caller does a full pull.
func (db *DB) Watermark(ctx context.Context, feedURL string) (time.Time, bool, error) {
	const query = `SELECT watermark FROM ingest_state WHERE feed_url = $1`
	var watermark time.Time
	err := db.pool.QueryRow(ctx, query, feedURL).Scan(&watermark)
	switch {
	case err == nil:
		return watermark, true, nil
	case err == pgx.ErrNoRows:
		return time.Time{}, false, nil
	default:
		return time.Time{}, false, fmt.Errorf("reading watermark for %q: %w", feedURL, err)
	}
}

// SetWatermark records watermark as the high-water mark for feedURL. It must
// only be called after a feed has been fully and successfully processed so an
// interrupted poll does not skip files on the next run.
func (db *DB) SetWatermark(ctx context.Context, feedURL string, watermark time.Time) error {
	const upsert = `
		INSERT INTO ingest_state (feed_url, watermark, updated)
		VALUES ($1, $2, CURRENT_TIMESTAMP)
		ON CONFLICT (feed_url) DO UPDATE
			SET watermark = EXCLUDED.watermark,
			    updated = CURRENT_TIMESTAMP`
	if _, err := db.pool.Exec(ctx, upsert, feedURL, watermark); err != nil {
		return fmt.Errorf("setting watermark for %q: %w", feedURL, err)
	}
	return nil
}

// CountActiveAdvisories returns how many advisories are currently not withdrawn.
// The deletion sweep uses it as a denominator for its sanity floor so it can
// refuse to withdraw an implausibly large fraction of the live corpus in a single
// cycle (see the guard in the poll loop).
func (db *DB) CountActiveAdvisories(ctx context.Context) (int64, error) {
	const query = `SELECT count(*) FROM advisories WHERE NOT withdrawn`
	var n int64
	if err := db.pool.QueryRow(ctx, query).Scan(&n); err != nil {
		return 0, fmt.Errorf("counting active advisories: %w", err)
	}
	return n, nil
}

// TombstoneAbsent marks as withdrawn every advisory that is not in present and
// not already withdrawn, and returns how many were newly tombstoned. It is the
// deletion sweep: an advisory that has vanished from the provider feeds is kept
// (no hard delete) but flagged so its permalink resolves to a "no longer
// published" notice.
//
// CRITICAL: callers must only invoke this after a COMPLETE, successful
// enumeration of every feed. Running it on a partial or failed poll would
// tombstone advisories that are merely missing because the poll did not finish,
// effectively wiping the portal on a transient provider hiccup.
func (db *DB) TombstoneAbsent(ctx context.Context, present []AdvisoryKey) (int64, error) {
	// Build parallel arrays for the present set so the sweep is a single
	// statement regardless of how many advisories are present.
	trackingIDs := make([]string, len(present))
	publishers := make([]string, len(present))
	for i, key := range present {
		trackingIDs[i] = key.TrackingID
		publishers[i] = key.Publisher
	}

	// unnest pairs the two arrays back into (tracking_id, publisher) rows; any
	// non-withdrawn advisory absent from that set is tombstoned.
	const sweep = `
		UPDATE advisories
		SET withdrawn = true,
		    withdrawn_at = CURRENT_TIMESTAMP
		WHERE NOT withdrawn
		  AND (tracking_id, publisher) NOT IN (
		      SELECT t, p FROM unnest($1::text[], $2::text[]) AS s(t, p)
		  )`
	tag, err := db.pool.Exec(ctx, sweep, trackingIDs, publishers)
	if err != nil {
		return 0, fmt.Errorf("tombstoning absent advisories: %w", err)
	}
	return tag.RowsAffected(), nil
}
