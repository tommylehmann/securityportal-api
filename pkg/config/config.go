// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 SecurityPortal contributors

// Package config implements the configuration mechanisms for securityportal-api.
//
// All settings are read from the environment so that the service can be
// deployed via docker-compose without baking secrets into the image.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/gocsaf/csaf/v3/csaf"
)

// Environment variable names used to configure the service.
const (
	// EnvProviderURL is the base URL (domain) of the CSAF Trusted Provider to
	// pull advisories from, e.g. "https://example.com".
	EnvProviderURL = "SECURITYPORTAL_PROVIDER_URL"
	// EnvPublishableTLP is a comma-separated list of TLP labels that are
	// allowed to be ingested and served publicly, e.g. "WHITE,UNLABELED".
	EnvPublishableTLP = "SECURITYPORTAL_PUBLISHABLE_TLP"
	// EnvPollInterval is the duration between ingestion polls, e.g. "15m".
	EnvPollInterval = "SECURITYPORTAL_POLL_INTERVAL"
	// EnvDatabaseDSN is the PostgreSQL connection string used to store and
	// query advisories. It is a secret and must never be logged verbatim.
	EnvDatabaseDSN = "SECURITYPORTAL_DATABASE_DSN"
	// EnvListen is the TCP address the read-only HTTP API listens on, e.g.
	// ":8081" or "127.0.0.1:8081".
	EnvListen = "SECURITYPORTAL_LISTEN"
	// EnvCORSOrigins is a comma-separated list of web origins allowed to call the
	// API from a browser, e.g. "https://portal.example.com". Empty disables CORS
	// (no Access-Control-Allow-Origin header is emitted).
	EnvCORSOrigins = "SECURITYPORTAL_CORS_ORIGINS"
)

// Defaults applied when the corresponding environment variable is unset.
const (
	defaultPollInterval = 15 * time.Minute
	// defaultListen matches the API container's internal port in
	// docker/docker-compose.yml so the bundled web service can reach it.
	defaultListen = ":8081"
)

// defaultPublishableTLP is the conservative publish policy applied when
// SECURITYPORTAL_PUBLISHABLE_TLP is unset: only WHITE and UNLABELED documents
// are treated as public (the exact policy is confirmed per deployment).
var defaultPublishableTLP = []csaf.TLPLabel{
	csaf.TLPLabelWhite,
	csaf.TLPLabelUnlabeled,
}

// Config holds the runtime configuration of the service.
type Config struct {
	// ProviderURL is the Trusted Provider domain to pull from.
	ProviderURL string
	// PublishableTLP is the set of TLP labels considered public; documents with
	// any other label are never stored or served.
	PublishableTLP []csaf.TLPLabel
	// PollInterval is the time between ingestion runs.
	PollInterval time.Duration
	// DatabaseDSN is the PostgreSQL connection string. Treated as a secret.
	DatabaseDSN string
	// Listen is the TCP address the HTTP API binds to.
	Listen string
	// CORSOrigins lists the browser origins permitted to call the API. Empty
	// means no CORS headers are emitted.
	CORSOrigins []string
}

// Load reads the configuration from the environment, applying defaults for
// optional values and validating required ones.
func Load() (*Config, error) {
	cfg := &Config{
		ProviderURL:    os.Getenv(EnvProviderURL),
		PublishableTLP: defaultPublishableTLP,
		PollInterval:   defaultPollInterval,
		DatabaseDSN:    os.Getenv(EnvDatabaseDSN),
		Listen:         defaultListen,
	}

	if raw := os.Getenv(EnvListen); raw != "" {
		cfg.Listen = raw
	}

	if raw := os.Getenv(EnvCORSOrigins); raw != "" {
		cfg.CORSOrigins = parseCSV(raw)
	}

	if raw := os.Getenv(EnvPublishableTLP); raw != "" {
		labels, err := parseTLPLabels(raw)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", EnvPublishableTLP, err)
		}
		cfg.PublishableTLP = labels
	}

	if raw := os.Getenv(EnvPollInterval); raw != "" {
		interval, err := time.ParseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", EnvPollInterval, err)
		}
		if interval <= 0 {
			return nil, fmt.Errorf("%s must be a positive duration, got %q", EnvPollInterval, raw)
		}
		cfg.PollInterval = interval
	}

	return cfg, nil
}

// ValidateForIngest checks that the settings required to run the ingestion
// worker are present. It is intentionally separate from Load so that the
// "migrate" subcommand, which only needs the database DSN, does not require a
// provider URL to be configured.
func (c *Config) ValidateForIngest() error {
	if c.ProviderURL == "" {
		return fmt.Errorf("%s must be set", EnvProviderURL)
	}
	if len(c.PublishableTLP) == 0 {
		return fmt.Errorf("%s must list at least one TLP label", EnvPublishableTLP)
	}
	return nil
}

// tlpClear is the TLP 2.0 spelling of the public level the gocsaf library models
// as WHITE (TLP 1.0). The two are the same level — TLP 2.0 renamed WHITE to
// CLEAR — so we accept either spelling and normalise CLEAR to WHITE everywhere.
const tlpClear = "CLEAR"

// normalizeTLP upper-cases, trims, and folds the TLP 2.0 CLEAR alias onto the
// WHITE label the csaf library uses, so a document or config entry spelled
// either way compares equal.
func normalizeTLP(label csaf.TLPLabel) string {
	name := strings.ToUpper(strings.TrimSpace(string(label)))
	if name == tlpClear {
		return csaf.TLPLabelWhite
	}
	return name
}

// IsPublishable reports whether label is in the configured publishable TLP set.
// CLEAR is treated as an alias of WHITE (see normalizeTLP).
func (c *Config) IsPublishable(label csaf.TLPLabel) bool {
	want := normalizeTLP(label)
	for _, l := range c.PublishableTLP {
		if string(l) == want {
			return true
		}
	}
	return false
}

// PublishableTLPSet returns the publishable TLP labels as canonical upper-case
// strings for use as a SQL filter parameter (defense in depth: the read API
// also constrains rows to this set, even though non-publishable documents are
// never ingested). Because TLP 2.0 renamed WHITE to CLEAR and a stored CSAF
// document may carry either spelling, the WHITE entry expands to both WHITE and
// CLEAR so a CLEAR-labelled document is matched too.
func (c *Config) PublishableTLPSet() []string {
	out := make([]string, 0, len(c.PublishableTLP)+1)
	for _, label := range c.PublishableTLP {
		name := normalizeTLP(label)
		out = append(out, name)
		if name == csaf.TLPLabelWhite {
			// Accept the TLP 2.0 spelling of the same level in the stored data.
			out = append(out, tlpClear)
		}
	}
	return out
}

// parseCSV splits a comma-separated list, trimming whitespace and dropping empty
// entries.
func parseCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// parseTLPLabels splits a comma-separated list into validated TLP labels.
func parseTLPLabels(raw string) ([]csaf.TLPLabel, error) {
	parts := strings.Split(raw, ",")
	labels := make([]csaf.TLPLabel, 0, len(parts))
	for _, part := range parts {
		name := strings.ToUpper(strings.TrimSpace(part))
		if name == "" {
			continue
		}
		label := csaf.TLPLabel(name)
		if !isKnownTLPLabel(label) {
			return nil, fmt.Errorf("unknown TLP label %q", name)
		}
		// Store the canonical csaf spelling so CLEAR and WHITE collapse into a
		// single WHITE entry the publish gate can match directly.
		labels = append(labels, csaf.TLPLabel(normalizeTLP(label)))
	}
	if len(labels) == 0 {
		return nil, fmt.Errorf("no TLP labels given")
	}
	return labels, nil
}

// isKnownTLPLabel reports whether label is one of the TLP labels defined by the
// CSAF specification. The TLP 2.0 CLEAR spelling of WHITE is also accepted; it is
// normalised to WHITE by the caller (see normalizeTLP).
func isKnownTLPLabel(label csaf.TLPLabel) bool {
	switch string(label) {
	case csaf.TLPLabelUnlabeled,
		csaf.TLPLabelWhite,
		tlpClear,
		csaf.TLPLabelGreen,
		csaf.TLPLabelAmber,
		csaf.TLPLabelRed:
		return true
	default:
		return false
	}
}

// Log writes a summary of the configuration to the default slog logger. The
// database DSN is intentionally not logged because it may contain credentials;
// only whether it is configured is reported.
func (c *Config) Log() {
	tlps := make([]string, len(c.PublishableTLP))
	for i, label := range c.PublishableTLP {
		tlps[i] = string(label)
	}
	slog.Info("configuration loaded",
		"provider_url", c.ProviderURL,
		"publishable_tlp", strings.Join(tlps, ","),
		"poll_interval", c.PollInterval.String(),
		"database_configured", c.DatabaseDSN != "",
		"listen", c.Listen,
		"cors_origins", strings.Join(c.CORSOrigins, ","),
	)
}
