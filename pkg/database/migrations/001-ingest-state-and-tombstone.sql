-- This file is Free Software under the Apache-2.0 License
-- without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
--
-- SPDX-License-Identifier: Apache-2.0
--
-- SPDX-FileCopyrightText: 2026 SecurityPortal contributors

-- Incremental ingestion state + advisory tombstone marker (plan task 8).
--
-- These objects are part of the consolidated 000-setup.sql, so a freshly
-- initialised database already has them and never runs this script (the
-- migration runner records 000 as the latest version on a fresh install). This
-- incremental exists for databases that were created from an EARLIER 000-setup
-- that predates these columns/tables; it is written idempotently (IF NOT EXISTS)
-- so it is safe regardless of which 000 they started from.
--
--   1. ingest_state: per-feed watermark for incremental polling. On subsequent
--      polls the watermark feeds gocsaf's AgeAccept hook so files older than it
--      are skipped. Advanced only after a fully successful cycle, so an
--      interrupted poll stays resumable.
--   2. A "withdrawn" tombstone on advisories (OQ-3): a vanished advisory is not
--      hard-deleted (permalinks must stay stable) but flagged so the API/UI can
--      later show a "no longer published" notice. A withdrawn advisory that
--      reappears in the feed clears the marker.

CREATE TABLE IF NOT EXISTS ingest_state (
    feed_url    text PRIMARY KEY,
    watermark   timestamptz NOT NULL,
    updated     timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE advisories
    ADD COLUMN IF NOT EXISTS withdrawn boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS withdrawn_at timestamptz;

CREATE INDEX IF NOT EXISTS advisories_withdrawn_idx
    ON advisories (withdrawn) WHERE withdrawn;
