# This file is Free Software under the Apache-2.0 License
# without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
#
# SPDX-License-Identifier: Apache-2.0
#
# SPDX-FileCopyrightText: 2026 Tommy Lehmann

.PHONY: all build vet test vuln sbom

all: build vet test

build:
	go build ./...

vet:
	go vet ./...

test:
	go test ./...

# vuln — known-vulnerability scan (C-6 / SA-16).
# govulncheck performs symbol-level reachability analysis; only flags
# vulnerabilities in code paths actually reached by this binary.
# Requires: go >= 1.26.4 (go.mod minimum) to avoid false positives from the
# stdlib vulns fixed in 1.26.1–1.26.4.
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# sbom — generate a CycloneDX SBOM (app scope: only reachable modules).
# Requires cyclonedx-gomod: go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
sbom:
	cyclonedx-gomod app \
		-main ./cmd/securityportal-api \
		-output securityportal-api-sbom.cdx.json \
		-json
	@echo "SBOM written to securityportal-api-sbom.cdx.json"
