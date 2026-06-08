// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package config

// Task-26 (C-7 / R-4) — SECURITYPORTAL_QUERY_TIMEOUT parsing tests.
//
// These cover the three behaviours documented in config.go:
//   1. Default (unset)    → 5s  (defaultQueryTimeout)
//   2. Valid override     → parsed duration stored in Config.QueryTimeout
//   3. Invalid input      → Load returns an error
//      a. Malformed string (not a Go duration)
//      b. Negative duration (explicitly rejected)
//      c. Zero is explicitly accepted (disables the timeout as documented)

import (
	"testing"
	"time"
)

// TestQueryTimeoutDefault asserts that when SECURITYPORTAL_QUERY_TIMEOUT is
// unset Load applies the documented 5-second default.
func TestQueryTimeoutDefault(t *testing.T) {
	t.Setenv(EnvQueryTimeout, "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.QueryTimeout != defaultQueryTimeout {
		t.Errorf("QueryTimeout = %s, want default %s", cfg.QueryTimeout, defaultQueryTimeout)
	}
}

// TestQueryTimeoutValidOverride asserts that a valid duration string is
// parsed and stored in Config.QueryTimeout.
func TestQueryTimeoutValidOverride(t *testing.T) {
	t.Setenv(EnvQueryTimeout, "2s")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.QueryTimeout != 2*time.Second {
		t.Errorf("QueryTimeout = %s, want 2s", cfg.QueryTimeout)
	}
}

// TestQueryTimeoutZeroIsAccepted asserts that "0" (or "0s") is valid and
// signals disabled timeout (no error). A zero timeout is documented as the
// way to disable the guard; it must not be confused with an invalid value.
func TestQueryTimeoutZeroIsAccepted(t *testing.T) {
	t.Setenv(EnvQueryTimeout, "0s")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with 0s: %v", err)
	}
	if cfg.QueryTimeout != 0 {
		t.Errorf("QueryTimeout = %s, want 0 (disabled)", cfg.QueryTimeout)
	}
}

// TestQueryTimeoutRejectsMalformedString asserts that a non-duration string
// causes Load to return an error rather than silently using the default.
func TestQueryTimeoutRejectsMalformedString(t *testing.T) {
	t.Setenv(EnvQueryTimeout, "five-seconds")

	if _, err := Load(); err == nil {
		t.Fatal("expected an error for a malformed duration, got nil")
	}
}

// TestQueryTimeoutRejectsNegativeValue asserts that a negative duration
// (e.g. "-1s") is rejected, matching the db.go validation that requires
// queryTimeout >= 0.
func TestQueryTimeoutRejectsNegativeValue(t *testing.T) {
	t.Setenv(EnvQueryTimeout, "-1s")

	if _, err := Load(); err == nil {
		t.Fatal("expected an error for a negative query timeout, got nil")
	}
}
