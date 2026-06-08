// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

// Package database holds the PostgreSQL access layer: the embedded schema
// migrations, the connection pool, and the queries that back the read-only
// REST API.
package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps the PostgreSQL connection pool used by the service. The query and
// migration layers are added in later tasks.
type DB struct {
	pool *pgxpool.Pool
}

// NewDB creates a connection pool from the given PostgreSQL DSN.
//
// queryTimeout is the per-statement timeout enforced on every pooled connection.
// A positive value sets PostgreSQL's statement_timeout session variable each time
// a connection is acquired (C-7 / R-4: DoS guard against slow advisory queries).
// A zero value disables the timeout; negative values are rejected.
func NewDB(ctx context.Context, dsn string, queryTimeout time.Duration) (*DB, error) {
	if queryTimeout < 0 {
		return nil, fmt.Errorf("queryTimeout must be >= 0, got %s", queryTimeout)
	}

	cc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing database DSN: %w", err)
	}

	if queryTimeout > 0 {
		// Wire a BeforeAcquire hook so every connection pulled from the pool carries
		// the operator-configured statement_timeout. This protects every read query
		// (ListAdvisories, ComputeFacets, GetDocument) against an expensive full-scan
		// or deep-offset that would otherwise run until the client disconnects.
		//
		// The timeout is expressed in milliseconds because that is what Postgres
		// expects as a plain integer (a trailing unit is also accepted, but the
		// integer path avoids locale-formatting issues).
		timeoutMS := queryTimeout.Milliseconds()
		cc.BeforeAcquire = func(ctx context.Context, conn *pgx.Conn) bool {
			_, err := conn.Exec(ctx,
				fmt.Sprintf("SET statement_timeout = %d", timeoutMS))
			return err == nil
		}
	}

	pool, err := pgxpool.NewWithConfig(ctx, cc)
	if err != nil {
		return nil, fmt.Errorf("creating postgresql pool: %w", err)
	}
	return &DB{pool: pool}, nil
}

// Close releases the connection pool.
func (db *DB) Close() {
	db.pool.Close()
}

// Migrate creates or upgrades the database schema by applying all pending
// embedded migrations. It is idempotent and safe to run on every startup.
func (db *DB) Migrate(ctx context.Context) error {
	return Migrate(ctx, db.pool)
}
