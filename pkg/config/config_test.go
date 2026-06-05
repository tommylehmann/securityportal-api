// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 SecurityPortal contributors

package config

import (
	"testing"
	"time"

	"github.com/gocsaf/csaf/v3/csaf"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv(EnvProviderURL, "")
	t.Setenv(EnvPublishableTLP, "")
	t.Setenv(EnvPollInterval, "")
	t.Setenv(EnvDatabaseDSN, "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PollInterval != defaultPollInterval {
		t.Errorf("expected default poll interval %s, got %s", defaultPollInterval, cfg.PollInterval)
	}
	if len(cfg.PublishableTLP) != 2 {
		t.Fatalf("expected 2 default publishable labels, got %d", len(cfg.PublishableTLP))
	}
	if !cfg.IsPublishable(csaf.TLPLabelWhite) || !cfg.IsPublishable(csaf.TLPLabelUnlabeled) {
		t.Error("default policy must publish WHITE and UNLABELED")
	}
	if cfg.IsPublishable(csaf.TLPLabelGreen) {
		t.Error("default policy must not publish GREEN")
	}
}

func TestLoadParsesEnv(t *testing.T) {
	t.Setenv(EnvProviderURL, "https://example.com")
	t.Setenv(EnvPublishableTLP, "white, green")
	t.Setenv(EnvPollInterval, "30m")
	t.Setenv(EnvDatabaseDSN, "postgres://localhost/db")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ProviderURL != "https://example.com" {
		t.Errorf("unexpected provider URL %q", cfg.ProviderURL)
	}
	if cfg.PollInterval != 30*time.Minute {
		t.Errorf("unexpected poll interval %s", cfg.PollInterval)
	}
	if !cfg.IsPublishable(csaf.TLPLabelGreen) {
		t.Error("GREEN should be publishable when configured")
	}
	if cfg.IsPublishable(csaf.TLPLabelUnlabeled) {
		t.Error("UNLABELED should not be publishable when not configured")
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	t.Run("unknown TLP", func(t *testing.T) {
		t.Setenv(EnvPublishableTLP, "PURPLE")
		if _, err := Load(); err == nil {
			t.Fatal("expected an error for an unknown TLP label")
		}
	})
	t.Run("bad interval", func(t *testing.T) {
		t.Setenv(EnvPublishableTLP, "")
		t.Setenv(EnvPollInterval, "soon")
		if _, err := Load(); err == nil {
			t.Fatal("expected an error for a malformed poll interval")
		}
	})
	t.Run("non-positive interval", func(t *testing.T) {
		t.Setenv(EnvPollInterval, "0s")
		if _, err := Load(); err == nil {
			t.Fatal("expected an error for a non-positive poll interval")
		}
	})
}

// TestCLEARAliasIsPublishable covers F3: TLP 2.0 renamed WHITE to CLEAR. A
// document labelled TLP:CLEAR must publish under either a WHITE or a CLEAR
// publishable-config spelling, while GREEN/AMBER/RED stay excluded under both.
func TestCLEARAliasIsPublishable(t *testing.T) {
	cases := []struct {
		name      string
		configRaw string // SECURITYPORTAL_PUBLISHABLE_TLP value
	}{
		{name: "config spells WHITE", configRaw: "WHITE"},
		{name: "config spells CLEAR", configRaw: "CLEAR"},
		{name: "config spells clear lowercase", configRaw: "clear"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvProviderURL, "https://example.com")
			t.Setenv(EnvPublishableTLP, tc.configRaw)
			t.Setenv(EnvPollInterval, "")
			t.Setenv(EnvDatabaseDSN, "")

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}

			// A CLEAR-labelled document must be publishable under either spelling.
			if !cfg.IsPublishable(csaf.TLPLabel("CLEAR")) {
				t.Error("a TLP:CLEAR document must be publishable")
			}
			// The WHITE spelling of the same level must publish too.
			if !cfg.IsPublishable(csaf.TLPLabelWhite) {
				t.Error("a TLP:WHITE document must be publishable")
			}
			// Restricted levels stay excluded regardless of the CLEAR/WHITE spelling.
			for _, restricted := range []csaf.TLPLabel{
				csaf.TLPLabelGreen, csaf.TLPLabelAmber, csaf.TLPLabelRed,
			} {
				if cfg.IsPublishable(restricted) {
					t.Errorf("%s must never be publishable under a WHITE/CLEAR policy", restricted)
				}
			}
		})
	}
}

// TestCLEARConfigCollapsesOntoWhite confirms a CLEAR config entry is stored as
// the canonical WHITE spelling, so the publishable set carries a single entry
// rather than an unknown CLEAR label the gate could never match.
func TestCLEARConfigCollapsesOntoWhite(t *testing.T) {
	t.Setenv(EnvProviderURL, "https://example.com")
	t.Setenv(EnvPublishableTLP, "CLEAR,UNLABELED")
	t.Setenv(EnvPollInterval, "")
	t.Setenv(EnvDatabaseDSN, "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, l := range cfg.PublishableTLP {
		if string(l) == "CLEAR" {
			t.Errorf("CLEAR must be normalised to WHITE in the publishable set, got %q", l)
		}
	}
	if !cfg.IsPublishable(csaf.TLPLabel("CLEAR")) || !cfg.IsPublishable(csaf.TLPLabelWhite) {
		t.Error("both CLEAR and WHITE documents must publish after normalisation")
	}
}

// TestListenAndCORSDefaults covers the new HTTP-API settings: the listen address
// defaults to the compose container port, and CORS is empty (disabled) unless
// configured.
func TestListenAndCORSDefaults(t *testing.T) {
	t.Setenv(EnvListen, "")
	t.Setenv(EnvCORSOrigins, "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != defaultListen {
		t.Errorf("listen = %q, want default %q", cfg.Listen, defaultListen)
	}
	if len(cfg.CORSOrigins) != 0 {
		t.Errorf("CORS origins = %v, want empty by default", cfg.CORSOrigins)
	}

	t.Setenv(EnvListen, "127.0.0.1:9000")
	t.Setenv(EnvCORSOrigins, "https://a.example.com, https://b.example.com")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != "127.0.0.1:9000" {
		t.Errorf("listen = %q, want overridden value", cfg.Listen)
	}
	if len(cfg.CORSOrigins) != 2 {
		t.Errorf("CORS origins = %v, want 2 entries", cfg.CORSOrigins)
	}
}

// TestPublishableTLPSet confirms the SQL filter set is canonical upper-case and
// that WHITE expands to also accept the TLP 2.0 CLEAR spelling, while restricted
// labels never appear.
func TestPublishableTLPSet(t *testing.T) {
	cfg := &Config{PublishableTLP: defaultPublishableTLP}
	set := cfg.PublishableTLPSet()

	want := map[string]bool{"WHITE": false, "CLEAR": false, "UNLABELED": false}
	for _, v := range set {
		if _, ok := want[v]; !ok {
			t.Errorf("unexpected TLP %q in publishable set", v)
		}
		want[v] = true
	}
	for label, seen := range want {
		if !seen {
			t.Errorf("publishable set missing %q", label)
		}
	}
}

func TestValidateForIngest(t *testing.T) {
	cfg := &Config{PublishableTLP: defaultPublishableTLP}
	if err := cfg.ValidateForIngest(); err == nil {
		t.Fatal("expected an error when the provider URL is missing")
	}
	cfg.ProviderURL = "https://example.com"
	if err := cfg.ValidateForIngest(); err != nil {
		t.Fatalf("did not expect an error: %v", err)
	}

	cfg.PublishableTLP = nil
	if err := cfg.ValidateForIngest(); err == nil {
		t.Fatal("expected an error when no publishable TLP labels are set")
	}
}
