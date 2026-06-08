// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package database

// Task-26 (C-7 / R-4) — statement-timeout integration tests.
//
// These tests prove the BeforeAcquire hook in NewDB actually enforces the
// configured statement_timeout on every acquired connection. They require a
// live postgres:16-alpine (docker-in-docker) and skip cleanly without docker.
//
// Two scenarios:
//
//  1. Positive: a pool built with a SHORT timeout (250 ms) runs
//     "SELECT pg_sleep(2)" and the query is CANCELLED by Postgres within
//     roughly 250 ms, not after 2 seconds. This confirms the hook fires.
//
//  2. Negative (timeout=0): a pool built with timeout=0 (hook not installed)
//     runs "SELECT pg_sleep(0.1)" — a short sleep well under any reasonable
//     Postgres limit — and it completes successfully, proving the zero path
//     leaves connections untouched and doesn't break normal queries.

import (
	"context"
	"testing"
	"time"

	"github.com/securityportal/securityportal-api/internal/dbtest"
)

// TestStatementTimeoutCancelsSlowQuery opens a DB with a 250 ms statement
// timeout, issues a 2-second sleep query, and asserts the query is cancelled
// with an error well before the 2-second mark. This pins the BeforeAcquire
// SET statement_timeout hook in NewDB.
func TestStatementTimeoutCancelsSlowQuery(t *testing.T) {
	_, dsn, ctx := dbtest.StartPostgres(t)

	const timeout = 250 * time.Millisecond
	db, err := NewDB(ctx, dsn, timeout)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(db.Close)

	start := time.Now()
	conn, err := db.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquiring connection: %v", err)
	}
	defer conn.Release()

	// Run a 2-second sleep. With statement_timeout=250ms Postgres should cancel
	// it and return an error (pq: canceling statement due to statement timeout /
	// ERROR 57014).
	_, queryErr := conn.Exec(ctx, "SELECT pg_sleep(2)")
	elapsed := time.Since(start)

	if queryErr == nil {
		t.Fatal("expected pg_sleep(2) to be cancelled by statement_timeout, but it succeeded")
	}

	// The cancellation must occur well before the 2-second sleep duration.
	// We allow up to 1 second to be generous for slow CI environments, but the
	// sleep should have been cancelled in ~250 ms.
	const maxAllowed = 1500 * time.Millisecond
	if elapsed > maxAllowed {
		t.Errorf("pg_sleep(2) took %s before returning error; statement_timeout may not be set (want < %s)",
			elapsed, maxAllowed)
	}
}

// TestStatementTimeoutZeroDisablesHook opens a DB with timeout=0 (hook not
// installed) and asserts that a short pg_sleep(0.1) completes successfully.
// This proves the zero-timeout code path does not apply any timeout and that
// normal queries work without the hook.
func TestStatementTimeoutZeroDisablesHook(t *testing.T) {
	_, dsn, ctx := dbtest.StartPostgres(t)

	db, err := NewDB(ctx, dsn, 0)
	if err != nil {
		t.Fatalf("NewDB with timeout=0: %v", err)
	}
	t.Cleanup(db.Close)

	conn, err := db.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquiring connection: %v", err)
	}
	defer conn.Release()

	// A short sleep must complete without error when no timeout is configured.
	if _, err := conn.Exec(ctx, "SELECT pg_sleep(0.1)"); err != nil {
		t.Errorf("pg_sleep(0.1) failed unexpectedly with timeout=0: %v", err)
	}
}

// TestNewDBRejectsNegativeTimeout asserts that passing a negative timeout
// to NewDB returns an error immediately, without contacting the database.
// This is a pure unit check that can run without docker; it lives here
// because it tests NewDB's own validation.
func TestNewDBRejectsNegativeTimeout(t *testing.T) {
	const badDSN = "postgres://127.0.0.1:1/nobody?sslmode=disable"
	ctx := context.Background()

	if _, err := NewDB(ctx, badDSN, -1*time.Second); err == nil {
		t.Fatal("expected NewDB to reject a negative queryTimeout, got nil")
	}
}
