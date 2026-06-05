// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 SecurityPortal contributors

// Package database holds the PostgreSQL access layer: the embedded schema
// migrations, the connection pool, and the queries that back the read-only
// REST API.
package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps the PostgreSQL connection pool used by the service. The query and
// migration layers are added in later tasks.
type DB struct {
	pool *pgxpool.Pool
}

// NewDB creates a connection pool from the given PostgreSQL DSN.
func NewDB(ctx context.Context, dsn string) (*DB, error) {
	cc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing database DSN: %w", err)
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
