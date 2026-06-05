// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 SecurityPortal contributors

package database

import (
	"cmp"
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations
var migrationsFS embed.FS

// migrationFileRE matches embedded migration file names of the form
// "NNN-description.sql" (e.g. "000-setup.sql").
var migrationFileRE = regexp.MustCompile(`^(\d+)-([^.]+)\.sql$`)

// migration is the metadata extracted from an embedded SQL migration file.
type migration struct {
	version     int64
	description string
	path        string
}

// Migrate applies all pending embedded migrations to the database behind pool,
// in ascending version order. It is idempotent: migrations already recorded in
// the "versions" table are skipped, so it is safe to call on every startup.
//
// The "versions" bookkeeping table is created on first run; the special
// version 0 migration ("000-setup.sql") sets up the whole schema in one go and
// is recorded with the highest known version so that later incremental
// migrations layer cleanly on top of it.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	migs, err := listMigrations()
	if err != nil {
		return err
	}
	if len(migs) == 0 {
		return errors.New("no migrations found")
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquiring connection for migration: %w", err)
	}
	defer conn.Release()

	current, err := currentVersion(ctx, conn.Conn())
	if err != nil {
		return err
	}

	latest := migs[len(migs)-1].version
	if current >= latest {
		slog.InfoContext(ctx, "database schema up to date", "version", current)
		return nil
	}

	// A fresh database (no "versions" table yet) is initialised by the
	// consolidated "000-setup.sql" alone, which carries the entire current
	// schema. It is recorded as the latest known version so the incremental
	// migrations — whose changes are already baked into the setup script — are
	// not re-applied on top of it. Existing databases skip 000 and run only the
	// incrementals newer than their recorded version.
	if current < 0 {
		setup := &migs[0]
		if setup.version != 0 {
			return fmt.Errorf("expected 000 setup migration first, got version %d", setup.version)
		}
		if err := applyMigration(ctx, conn.Conn(), setup, latest); err != nil {
			return err
		}
		slog.InfoContext(ctx, "migrations applied", "version", latest)
		return nil
	}

	for i := range migs {
		mig := &migs[i]
		if mig.version <= current {
			continue
		}
		if err := applyMigration(ctx, conn.Conn(), mig, latest); err != nil {
			return err
		}
	}

	slog.InfoContext(ctx, "migrations applied", "version", latest)
	return nil
}

// currentVersion returns the highest applied migration version. It returns -1
// when the schema has never been initialised (the "versions" table is absent),
// which causes the version 0 setup migration to run.
func currentVersion(ctx context.Context, conn *pgx.Conn) (int64, error) {
	const versionsExists = `SELECT to_regclass('public.versions') IS NOT NULL`
	var exists bool
	if err := conn.QueryRow(ctx, versionsExists).Scan(&exists); err != nil {
		return -1, fmt.Errorf("checking for versions table: %w", err)
	}
	if !exists {
		return -1, nil
	}
	const selectVersion = `SELECT coalesce(max(version), -1) FROM versions`
	var version int64
	if err := conn.QueryRow(ctx, selectVersion).Scan(&version); err != nil {
		return -1, fmt.Errorf("reading schema version: %w", err)
	}
	return version, nil
}

// applyMigration runs a single migration inside a transaction and records it in
// the "versions" table. The version 0 setup migration is recorded as the latest
// known version so that incremental migrations are not re-run against a freshly
// initialised schema.
func applyMigration(ctx context.Context, conn *pgx.Conn, mig *migration, latest int64) error {
	script, err := migrationsFS.ReadFile(mig.path)
	if err != nil {
		return fmt.Errorf("loading migration %q: %w", mig.path, err)
	}

	recordedVersion := mig.version
	if recordedVersion == 0 {
		recordedVersion = latest
	}

	slog.InfoContext(ctx, "running migration", "version", mig.version, "name", mig.description)

	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("beginning transaction for migration %q: %w", mig.path, err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, string(script)); err != nil {
		return fmt.Errorf("executing migration %q: %w", mig.path, err)
	}
	const insertVersion = `INSERT INTO versions (version, description) VALUES ($1, $2)`
	if _, err := tx.Exec(ctx, insertVersion, recordedVersion, mig.description); err != nil {
		return fmt.Errorf("recording migration %q: %w", mig.path, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing migration %q: %w", mig.path, err)
	}
	return nil
}

// listMigrations reads and parses the embedded migration files, sorted by
// ascending version.
func listMigrations() ([]migration, error) {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("listing embedded migrations: %w", err)
	}
	var migs []migration
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		m := migrationFileRE.FindStringSubmatch(entry.Name())
		if m == nil {
			continue
		}
		version, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing version of migration %q: %w", entry.Name(), err)
		}
		migs = append(migs, migration{
			version:     version,
			description: strings.ReplaceAll(m[2], "_", " "),
			path:        "migrations/" + entry.Name(),
		})
	}
	slices.SortFunc(migs, func(a, b migration) int {
		return cmp.Compare(a.version, b.version)
	})
	return migs, nil
}
