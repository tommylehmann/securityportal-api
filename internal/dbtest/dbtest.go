// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 SecurityPortal contributors

// Package dbtest provides a shared docker-in-docker PostgreSQL fixture for the
// integration tests in this module. It centralises the throwaway-container
// helper so the database and ingest packages do not each carry their own copy.
//
// Every helper skips the calling test cleanly (t.Skip) when docker is not
// usable, so `go test ./...` still passes in environments without a docker
// daemon.
package dbtest

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// Image is the PostgreSQL image the integration tests run against; it matches
	// the version the production stack deploys (spec §6).
	Image    = "postgres:16-alpine"
	password = "securityportal-test"
	database = "securityportal"
)

// StartPostgres launches a throwaway postgres:16-alpine container and returns a
// ready connection pool, its DSN, and a bounded context. It calls t.Skip when
// docker is unavailable so the suite degrades gracefully, and registers all
// teardown (container stop, pool close, context cancel) via t.Cleanup.
func StartPostgres(t *testing.T) (*pgxpool.Pool, string, context.Context) {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available; skipping postgres integration test")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon not reachable; skipping postgres integration test")
	}

	port, err := freePort()
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}

	name := fmt.Sprintf("securityportal-it-%d", time.Now().UnixNano())
	runArgs := []string{
		"run", "--rm", "-d",
		"--name", name,
		"-e", "POSTGRES_PASSWORD=" + password,
		"-e", "POSTGRES_DB=" + database,
		"-p", fmt.Sprintf("%d:5432", port),
		Image,
	}
	if out, err := exec.Command("docker", runArgs...).CombinedOutput(); err != nil {
		t.Skipf("could not start %s (%v): %s", Image, err, strings.TrimSpace(string(out)))
	}

	t.Cleanup(func() {
		_ = exec.Command("docker", "stop", "-t", "1", name).Run()
	})

	dsn := fmt.Sprintf(
		"postgres://postgres:%s@127.0.0.1:%d/%s?sslmode=disable",
		password, port, database,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)

	pool, err := waitForPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("waiting for postgres to become ready: %v", err)
	}
	t.Cleanup(pool.Close)

	return pool, dsn, ctx
}

// waitForPostgres polls until the database accepts queries or the deadline hits.
func waitForPostgres(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	deadline := time.Now().Add(60 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if err := pool.Ping(ctx); err != nil {
			lastErr = err
			pool.Close()
			time.Sleep(500 * time.Millisecond)
			continue
		}
		return pool, nil
	}
	return nil, fmt.Errorf("postgres not ready before deadline: %w", lastErr)
}

// freePort asks the OS for an unused TCP port to avoid container collisions.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
