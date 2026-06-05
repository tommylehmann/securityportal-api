// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 SecurityPortal contributors

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
func runIngest(cfg *config.Config) error {
	ctx := context.Background()

	db, err := database.NewDB(ctx, cfg.DatabaseDSN)
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
func runPoll(cfg *config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := database.NewDB(ctx, cfg.DatabaseDSN)
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
func runServe(cfg *config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := database.NewDB(ctx, cfg.DatabaseDSN)
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
func runMigrate(cfg *config.Config) error {
	ctx := context.Background()

	db, err := database.NewDB(ctx, cfg.DatabaseDSN)
	if err != nil {
		return err
	}
	defer db.Close()

	return db.Migrate(ctx)
}
