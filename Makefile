# This file is Free Software under the Apache-2.0 License
# without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
#
# SPDX-License-Identifier: Apache-2.0
#
# SPDX-FileCopyrightText: 2026 Tommy Lehmann

.PHONY: all build vet test vuln sbom openapi openapi-lint version dist

# Version is derived from git, SemVer-style, so local `make dist` matches what
# the release workflow builds. On a tagged checkout this is the tag (e.g.
# v1.2.3); past a tag it's the `git describe` form (v1.2.3-4-gabc1234); with no
# tag yet it falls back to v0.0.0-g<sha>. Released versions come from the tag in
# CI (release.yml); this target is for local/parity builds.
VERSION ?= $(shell \
	d=$$(git describe --tags --always --dirty 2>/dev/null); \
	if printf '%s' "$$d" | grep -qE '^v?[0-9]+\.[0-9]+\.[0-9]+'; then \
		printf 'v%s' "$$(printf '%s' "$$d" | sed -E 's/^v//')"; \
	elif [ -n "$$d" ]; then \
		printf 'v0.0.0-g%s' "$$d"; \
	else \
		printf 'v0.0.0'; \
	fi)

DISTDIR := dist
DISTNAME := securityportal-api-$(VERSION)-linux-amd64
LDFLAGS := -s -w -X main.version=$(VERSION)

all: build vet test

build:
	go build ./...

vet:
	go vet ./...

test:
	go test ./...

# openapi — regenerate pkg/web/static/openapi.json from the human-readable
# pkg/web/static/openapi.yaml. Run this after editing openapi.yaml; commit both
# files together so the embedded JSON is always in sync (ADR-0015/C-37).
# Requires Python 3 with PyYAML (pip install pyyaml) in the PATH.
openapi:
	PYTHONPATH="$${HOME}/.local/lib/python3.11/site-packages:$${PYTHONPATH}" \
	python3 -c \
	  "import yaml,json,sys; d=yaml.safe_load(open('pkg/web/static/openapi.yaml')); \
	   open('pkg/web/static/openapi.json','w').write(json.dumps(d,indent=2))"
	@echo "openapi.json updated"

# openapi-lint — validate the OpenAPI spec with redocly CLI.
# Install: npm install -g @redocly/cli  (dev-dependency only, not in go.mod).
# Runs: redocly lint pkg/web/static/openapi.yaml
# ADR-0015 requires the spec to lint clean before merge. Wire this in CI as:
#   npx @redocly/cli@latest lint securityportal-api/pkg/web/static/openapi.yaml
openapi-lint:
	redocly lint pkg/web/static/openapi.yaml

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

# version — print the git-derived SemVer the build would stamp in.
version:
	@echo "$(VERSION)"

# dist — build the release tarball the way the release workflow does:
# a version-stamped linux/amd64 binary plus a CycloneDX SBOM. Note that CI
# additionally builds and publishes the container image (the primary artifact)
# and generates an SPDX SBOM via anchore; see .github/workflows/release.yml and
# RELEASING.md.
dist: sbom
	mkdir -p $(DISTDIR)/$(DISTNAME)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		-trimpath \
		-ldflags "$(LDFLAGS)" \
		-o $(DISTDIR)/$(DISTNAME)/securityportal-api \
		./cmd/securityportal-api
	cp securityportal-api-sbom.cdx.json $(DISTDIR)/$(DISTNAME)/
	cp README.md LICENSE CHANGELOG.md $(DISTDIR)/$(DISTNAME)/
	cd $(DISTDIR) && tar -czf $(DISTNAME).tar.gz $(DISTNAME)
	@echo "dist written to $(DISTDIR)/$(DISTNAME).tar.gz (version $(VERSION))"
