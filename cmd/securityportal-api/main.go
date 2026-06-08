// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

// Package main implements the main driver for the securityportal-api server.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/securityportal/securityportal-api/pkg/config"
	"github.com/securityportal/securityportal-api/pkg/database"
	"github.com/securityportal/securityportal-api/pkg/ingest"
	"github.com/securityportal/securityportal-api/pkg/web"
)

// version is the build version of the server. It is overridden at build time
// via -ldflags "-X main.version=...".
var version = "v0.0.0-dev"

func main() {
	slog.Info("starting securityportal-api", "version", version)

	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}
	cfg.Log()

	// Subcommands:
	//   migrate — apply pending schema migrations and exit.
	//   ingest  — run a single persisting ingestion cycle and exit.
	//   poll    — apply migrations, then run the ingestion loop until SIGINT/SIGTERM.
	//   serve   — apply migrations, then run the HTTP API AND the ingestion loop
	//             together until SIGINT/SIGTERM. This is the default and what the
	//             compose api service runs: one process, two concurrent workers
	//             sharing a single context that cancels on signal.
	command := "serve"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}

	switch command {
	case "migrate":
		if err := runMigrate(cfg); err != nil {
			slog.Error("migration failed", "error", err)
			os.Exit(1)
		}
	case "ingest":
		if err := runIngest(cfg); err != nil {
			slog.Error("ingestion failed", "error", err)
			os.Exit(1)
		}
	case "poll":
		if err := runPoll(cfg); err != nil {
			slog.Error("ingestion worker failed", "error", err)
			os.Exit(1)
		}
	case "serve", "run":
		if err := runServe(cfg); err != nil {
			slog.Error("server failed", "error", err)
			os.Exit(1)
		}
	default:
		slog.Error("unknown command", "command", command,
			"valid", "migrate | ingest | poll | serve")
		os.Exit(2)
	}
}

// runIngest performs one complete persisting ingestion cycle over the provider
// feeds (fetch + verify + TLP gate + upsert + deletion sweep) and exits.
// The query timeout is not applied here: ingestion writes are short-lived, but
// the sweep transaction over a large corpus could take longer than the read timeout.
func runIngest(cfg *config.Config) error {
	ctx := context.Background()

	db, err := database.NewDB(ctx, cfg.DatabaseDSN, 0)
	if err != nil {
		return err
	}
	defer db.Close()

	counts, err := ingest.RunOnce(ctx, cfg, db)
	if err != nil {
		return err
	}
	slog.Info("ingestion run complete",
		"stored", counts.Stored, "duplicate", counts.Duplicate, "skipped_tlp", counts.SkippedTLP)
	return nil
}

// runPoll applies pending migrations and then runs the ingestion poll loop until
// the process receives SIGINT or SIGTERM, at which point the context is
// cancelled and the loop shuts down cleanly between (or during) cycles.
// The query timeout is not applied to the ingest pool for the same reason as runIngest.
func runPoll(cfg *config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := database.NewDB(ctx, cfg.DatabaseDSN, 0)
	if err != nil {
		return err
	}
	defer db.Close()

	// Bring the schema up to date before polling so a fresh deployment works
	// from a single "poll" invocation.
	if err := db.Migrate(ctx); err != nil {
		return err
	}

	if err := ingest.Poll(ctx, cfg, db); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	slog.Info("securityportal-api stopped")
	return nil
}

// runServe applies pending migrations and then runs the HTTP API server and the
// ingestion poll loop concurrently until SIGINT/SIGTERM. Both share a single
// context that cancels on signal, so a graceful shutdown drains in-flight HTTP
// requests and stops the poller between cycles. If either worker fails fatally,
// the shared context is cancelled so the other stops too.
//
// The statement timeout (cfg.QueryTimeout, default 5 s) is applied to the shared
// pool so expensive read queries (ListAdvisories, ComputeFacets, GetDocument) are
// cancelled and return a clean error rather than hanging indefinitely. Ingestion
// writes in the same pool are also bounded; at 5 s that is well above the expected
// per-document write time but avoids a runaway sweep from blocking the whole pool
// (see threat model C-7 / R-4).
func runServe(cfg *config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := database.NewDB(ctx, cfg.DatabaseDSN, cfg.QueryTimeout)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := db.Migrate(ctx); err != nil {
		return err
	}

	group, ctx := errgroup.WithContext(ctx)

	// HTTP API: serves the read-only endpoints; drains on context cancel.
	group.Go(func() error {
		slog.Info("starting HTTP API", "address", cfg.Listen)
		if err := web.NewServer(cfg, db).Run(ctx); err != nil {
			return fmt.Errorf("http server: %w", err)
		}
		return nil
	})

	// Ingestion poll loop: pulls the provider on the configured interval. Poll
	// returns the context error on shutdown, which is not a failure.
	group.Go(func() error {
		if err := ingest.Poll(ctx, cfg, db); err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("ingestion worker: %w", err)
		}
		return nil
	})

	err = group.Wait()
	slog.Info("securityportal-api stopped")
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// runMigrate connects to the database and applies all pending schema migrations.
// No statement timeout is set: DDL statements on a large schema may take longer
// than the read-path default, and this command is operator-invoked, not public.
//
// When running as a Helm initContainer for a bundled PostgreSQL deployment the
// database may not be accepting connections yet when this command starts.
// runMigrate retries the connection with exponential backoff (2 s, 4 s, 8 s,
// capped at 16 s) for up to migrateMaxWait total.  This avoids a dependency on
// a shell-based pg_isready loop in the initContainer command — the api image is
// a scratch binary with no shell.  For external-DB deployments (hook Job path)
// the DB is already up, so the first attempt succeeds immediately and the retry
// logic is never exercised.
const (
	migrateMaxWait     = 5 * time.Minute
	migrateInitBackoff = 2 * time.Second
	migrateMaxBackoff  = 16 * time.Second
)

func runMigrate(cfg *config.Config) error {
	ctx := context.Background()

	// pgxpool connects lazily, so NewDB rarely errors even against a dead
	// server; the connection failure surfaces inside Migrate. Retry around
	// Migrate (which is idempotent / version-tracked, so re-running after a
	// connect failure is safe) so the bundled-Postgres initContainer waits
	// in-process instead of relying solely on kubelet restart loops.
	db, err := database.NewDB(ctx, cfg.DatabaseDSN, 0)
	if err != nil {
		return err
	}
	defer db.Close()

	deadline := time.Now().Add(migrateMaxWait)
	backoff := migrateInitBackoff
	attempt := 0

	for {
		attempt++
		if err = db.Migrate(ctx); err == nil {
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("migrate: not completed after %s (last error: %w)", migrateMaxWait, err)
		}

		slog.Warn("migrate: database not reachable, retrying",
			"attempt", attempt, "backoff", backoff, "error", err)
		time.Sleep(backoff)
		if backoff < migrateMaxBackoff {
			backoff *= 2
			if backoff > migrateMaxBackoff {
				backoff = migrateMaxBackoff
			}
		}
	}
}
