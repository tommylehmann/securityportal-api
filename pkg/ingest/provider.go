// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package ingest

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/util"
)

// httpTimeout bounds every request made against the Trusted Provider so a slow
// or unresponsive endpoint cannot stall an ingestion run indefinitely.
const httpTimeout = 60 * time.Second

// userAgent identifies the portal to the provider in request logs.
const userAgent = "securityportal-api"

// newHTTPClient builds the [util.Client] used for all provider requests. The
// provider is public and unauthenticated (no client certificate or
// credentials), so the client only sets a timeout and a descriptive
// User-Agent header.
func newHTTPClient() util.Client {
	return &util.HeaderClient{
		Client: &http.Client{Timeout: httpTimeout},
		Header: http.Header{"User-Agent": []string{userAgent}},
	}
}

// LoadProviderMetadata fetches and schema-validates the provider-metadata.json
// for the given provider domain or URL using the gocsaf
// [csaf.ProviderMetadataLoader]. Any loader messages (warnings about
// mismatching well-known/security.txt entries, schema problems, etc.) are
// surfaced via slog. It returns the validated PMD together with the parsed
// [csaf.ProviderMetadata] model, or a wrapped error if loading or validation
// failed.
func LoadProviderMetadata(
	client util.Client,
	providerURL string,
) (*csaf.LoadedProviderMetadata, *csaf.ProviderMetadata, error) {
	loader := csaf.NewProviderMetadataLoader(client)
	lpmd := loader.Load(providerURL)

	logLoadMessages(providerURL, lpmd.Messages)

	if !lpmd.Valid() {
		return nil, nil, fmt.Errorf(
			"loading provider-metadata.json for %q failed: no valid document found", providerURL)
	}

	// Re-marshal the generic document into the typed model so the rest of the
	// pipeline can use the PGP keys, distributions, and publisher fields
	// directly.
	var pmd csaf.ProviderMetadata
	if err := util.ReMarshalJSON(&pmd, lpmd.Document); err != nil {
		return nil, nil, fmt.Errorf("decoding provider-metadata.json for %q: %w", providerURL, err)
	}

	slog.Info("loaded provider-metadata.json",
		"provider_url", providerURL,
		"source_url", lpmd.URL,
		"pgp_keys", len(pmd.PGPKeys),
		"distributions", len(pmd.Distributions),
	)

	return lpmd, &pmd, nil
}

// logLoadMessages reports loader warnings/errors at the appropriate level. A
// failed load still surfaces detail here even though the caller turns the
// missing document into an error.
func logLoadMessages(providerURL string, msgs csaf.ProviderMetadataLoadMessages) {
	for _, msg := range msgs {
		switch msg.Type {
		case csaf.HTTPFailed,
			csaf.JSONDecodingFailed,
			csaf.SchemaValidationFailed,
			csaf.SchemaValidationFailedDetail:
			slog.Warn("provider-metadata.json load message",
				"provider_url", providerURL, "message", msg.Message)
		default:
			slog.Info("provider-metadata.json load message",
				"provider_url", providerURL, "message", msg.Message)
		}
	}
}
