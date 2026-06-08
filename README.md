<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Tommy Lehmann
-->

# securityportal-api — Read-only CSAF Advisory API

A Go backend that ingests advisories from a CSAF Trusted Provider, stores them in PostgreSQL, and serves them over a read-only HTTP API.

**This is part of the SecurityPortal public advisory portal.** See the top-level workspace for architecture context and deployment instructions.

## Overview

- **Ingestion worker:** polls a Trusted Provider's ROLIE feeds, verifies SHA256/512 + PGP signatures, applies TLP publish policy, and stores only publishable advisories in Postgres.
- **Read-only REST API:** exposes `/api/advisories` (list + search), `/api/documents/:id` (single advisory JSON), `/api/facets` (filter sidebar counts), and `/api/health` (liveness).
- **Database:** PostgreSQL 16 with `tsvector` full-text search, per-document revision tracking, and TLP-gated access.
- **No authentication:** the API is public and read-only. All endpoints return 404 for non-publishable documents (defense in depth).

## Quick start

### Prerequisites

- Go 1.26 or later (matching `go.mod`)
- PostgreSQL 16 (local or via Docker)
- Environment variables (copy `.env.example` to `.env` and adjust)

### Local development

```bash
# Download dependencies
go mod download

# Run migrations and start (applies schema, runs ingest poller + API server)
go run ./cmd/securityportal-api serve

# Or separate commands:
go run ./cmd/securityportal-api migrate          # Apply migrations and exit
go run ./cmd/securityportal-api ingest           # Run one ingest cycle and exit
go run ./cmd/securityportal-api poll             # Run ingest loop only (no API)
```

### Docker Compose

```bash
cd docker
cp .env.example .env
# Edit .env: set SECURITYPORTAL_PROVIDER_URL and database credentials
docker compose up
```

The stack brings up Postgres, the API on `:8081`, and the web frontend on `:8080`.

## Configuration

All settings are environment variables (no config files or secrets in source). The stack shares configuration across three deployment targets (Compose, Kubernetes, bare-metal); see the Deployment options section for target-specific instructions.

### API configuration (Go backend)

| Variable | Default | Description |
|----------|---------|-------------|
| **Ingestion** | | |
| `SECURITYPORTAL_PROVIDER_URL` | (required) | Base URL or PMD URL of the CSAF Trusted Provider to pull advisories from, e.g. `https://provider.example.com` or the full `https://provider.example.com/.well-known/csaf/provider-metadata.json`. The gocsaf loader supports both; the full URL short-circuits discovery. (See §9 / task 36 for the BSI WID example.) |
| `SECURITYPORTAL_PUBLISHABLE_TLP` | `WHITE,UNLABELED` | Comma-separated TLP labels that are public (publish policy). Documents with other labels are never ingested or served. Alias `CLEAR` is normalized to `WHITE` (CSAF 2.0 renamed WHITE→CLEAR; both are the same level). |
| `SECURITYPORTAL_POLL_INTERVAL` | `15m` | Time between polling cycles (Go duration syntax: `15m`, `1h`, `6h`). Set to `0` to disable polling (serve-only mode). Large corpora (e.g., BSI WID) benefit from longer intervals (e.g., 6h) to avoid hammering the provider; see `.env.wid.example`. |
| **API service** | | |
| `SECURITYPORTAL_LISTEN` | `:8081` | TCP address the read-only HTTP API binds to. Use `:8081` for all interfaces or `127.0.0.1:8081` for localhost only. |
| `SECURITYPORTAL_CORS_ORIGINS` | (empty) | Comma-separated browser origins allowed to call the API cross-origin (e.g., `https://portal.example.com`). Leave empty (or unset) in same-origin deployments (Compose via Caddy, Kubernetes via Ingress) where the browser never talks to the API directly; CSP handles it. Only set for non-proxy deploys where the frontend is separate or cross-origin. |
| `SECURITYPORTAL_QUERY_TIMEOUT` | `5s` | Per-query statement timeout (Go duration syntax). Protects against expensive searches and DoS via Postgres (threat model C-7 / R-4). Set to `0` to disable (not recommended for production). |
| **Database** | | |
| `SECURITYPORTAL_DATABASE_DSN` | (required) | PostgreSQL connection string, e.g. `postgres://user:pass@localhost:5432/securityportal?sslmode=disable`. This is a **secret**; never log it verbatim or commit it to source. |

### Web + portal configuration (SvelteKit frontend, Phase 7)

These are read by the web service at **runtime** via `$env/dynamic/private` (server-side only) and `$env/dynamic/public` (accessible to browser). See `securityportal-web/README.md` §Configuration for the full reference.

| Variable | Scope | Default | Description |
|----------|-------|---------|-------------|
| `PUBLIC_API_BASE_URL` | browser | `""` (same-origin) | Backend API base URL for the browser. Empty = same-origin relative `/api/...` (correct for Compose/Kubernetes). Absolute origin (e.g., `https://api.example.com`) = cross-origin API; CSP is extended to allow it. |
| `SECURITYPORTAL_API_INTERNAL_URL` | server-only | unset | **Compose/Kubernetes only:** internal address for SSR load functions (e.g., `http://api:8081`). When set, SSR bypasses the reverse proxy and hits the API directly on the internal network. When unset, SSR falls through to the browser's base. |
| `SECURITYPORTAL_BRAND_NAME` | server-only | `"SecurityPortal"` | Portal title (header + logo alt text). No HTML; plain text only. |
| `SECURITYPORTAL_BRAND_SUBTITLE` | server-only | `"CSAF Advisory Portal"` | Portal subtitle (header). Plain text. |
| `SECURITYPORTAL_THEME_PRIMARY` | server-only | `"#2563eb"` | Primary brand color (hex `#rrggbb` or RGB `R G B` decimal). Validated server-side; invalid values are logged and ignored (SA-22). |
| `SECURITYPORTAL_THEME_PRIMARY_FG` | server-only | unset | Foreground (text) color on primary bg (hex or RGB). **v1 scope: unused.** |
| `SECURITYPORTAL_THEME_ACCENT` | server-only | unset | Accent color override (hex or RGB). **v1 scope: unused.** |
| `SECURITYPORTAL_LOGO_PATH` | server-only | unset | Path to a logo file (SVG/PNG/WebP) served at `/branding/logo`. Fixed at process start (never request-derived, SA-20). When unset, a built-in shield glyph is shown. In containerized deployments, mount the logo file and set the path to where it exists inside the container (e.g., `/config/logo.png`). |
| `SECURITYPORTAL_LEGAL_DIR` | server-only | unset | Directory containing legal Markdown files (`impressum.de.md`, `impressum.en.md`, `datenschutz.de.md`, `datenschutz.en.md`). When unset, placeholders with amber banners are shown (OQ-4 default). In containerized deployments, mount the directory and set the path to the mount point (e.g., `/config/legal`). See ADR-0010 for sanitization + fallback chain. |

### Reverse proxy configuration (Caddy, Compose deployment)

These are read by the Caddy reverse proxy in the Docker Compose stack. See `docker/.env.example` and `docker/caddy/Caddyfile` for details.

| Variable | Default | Description |
|----------|---------|-------------|
| `SP_SITE_ADDRESS` | `localhost` | Public hostname for the Caddy site block. Unset or `localhost` selects self-signed TLS (MODE 1). Set to a public FQDN for ACME/Let's Encrypt (MODE 2, requires `SP_ACME_EMAIL`). |
| `SP_ACME_EMAIL` | unset | ACME registration email (Let's Encrypt, MODE 2). Uncomment in `.env` to enable ACME; leave unset (not empty string) for MODE 1 self-signed. When unset, Caddy defaults to `{$SP_ACME_EMAIL:internal}` → self-signed. |
| `SP_TLS_CERT` / `SP_TLS_KEY` | unset | **BYO certificate paths (MODE 3, documentation only).** Absolute paths *inside the Caddy container* to the PEM files. To use BYO: set `SP_SITE_ADDRESS` to your FQDN, leave `SP_ACME_EMAIL` unset, and bind-mount the cert/key files into the container. Update the compose service to mount `docker/caddy/Caddyfile.byo` instead of the default Caddyfile. |
| `SP_RATE_LIMIT_REQUESTS` | `60` | Requests per sliding window per source IP (Caddy rate limiting). Tuned via `SP_RATE_LIMIT_WINDOW`. Requires custom Caddy image with `caddy-ratelimit` module (built via `docker/caddy/Dockerfile` in the default compose setup). |
| `SP_RATE_LIMIT_WINDOW` | `1m` | Rate-limit sliding window (e.g., `1m`, `60s`). Example: `60` requests per `1m` = 1 req/sec per IP. |

## Subcommands

- **`serve` (default):** apply migrations, then run the API server (`:8081`) and ingestion poller concurrently. Exits on SIGINT/SIGTERM after draining in-flight requests.
- **`migrate`:** apply pending migrations and exit. Useful for initialization or during a rolling restart.
- **`poll`:** apply migrations, then run the ingestion worker only (no API). Pulls the provider on the configured interval.
- **`ingest`:** apply migrations, run one complete ingestion cycle, and exit. For manual testing or forced updates.

## REST API

Base path: `/api`. All responses are JSON. No authentication required.

### `GET /api/health`

Liveness and readiness check.

**Response (200 OK):**
```json
{
  "status": "ok",
  "database": "reachable",
  "last_ingest": "2026-06-08T14:30:00Z",
  "version": "v1.0.0"
}
```

**Responses:**
- **200 OK:** database is reachable and healthy.
- **503 Service Unavailable:** database is unreachable or degraded.

**Fields:**
- `status`: `"ok"` or `"unavailable"`
- `database`: `"reachable"` or `"unreachable"`
- `last_ingest`: timestamp of the most recent successful ingestion cycle (omitted if no polls have completed yet)
- `version`: the API build version

### `GET /api/advisories`

List the latest revision of each advisory with facet fields.

**Query parameters:**
- `limit` (integer, default 25): rows per page. Clamped to max 100. Setting to 0 uses max 100.
- `offset` (integer, default 0): pagination offset. Capped at 10,000 to prevent deep-offset DoS.
- `sort` (string, default `current_release_date`): sort column. Must be one of `current_release_date` or `critical`.
- `sort` direction: append `:asc` or `:desc` to the column, e.g. `sort=critical:asc`. Default is descending.

**Facet / search filters (all optional, combinable):**
- `q` (string): free-text search in title, notes, product names
- `cve` (string): CVE ID filter (exact or substring match)
- `severity` (repeatable, or comma-separated): none, low, medium, high, critical
- `score_min`, `score_max` (float): CVSS score range
- `from`, `to` (date or RFC 3339): release date range (bare date interpreted as UTC midnight)
- `publisher` (string): publisher name filter
- `product` (string): product name filter
- `vendor` (string): vendor name filter
- `tlp` (repeatable, or comma-separated): TLP label filter (intersected with publishable set, never overriding it)
- `category` (string): CSAF document category
- `lang` (string): document language (e.g. `en`, `de`)

**Response (200 OK):**
```json
{
  "advisories": [
    {
      "id": 1,
      "tracking_id": "securityportal-2026-0001",
      "publisher_name": "Example AG",
      "title": "Critical vulnerability in Example Product",
      "current_release_date": "2026-06-08T00:00:00Z",
      "initial_release_date": "2026-06-01T00:00:00Z",
      "tlp": "WHITE",
      "category": "csaf_security_advisory",
      "critical": 9.8,
      "cvss_v2_score": null,
      "cvss_v3_score": 9.8,
      "lang": "en",
      "tracking_status": "final",
      "version": "1"
    }
  ],
  "total": 42,
  "limit": 25,
  "offset": 0
}
```

**Responses:**
- **200 OK:** success. The `advisories` list may be empty if no rows match the filters.
- **400 Bad Request:** malformed parameter (e.g. invalid date, unknown severity, offset too large).
- **500 Internal Server Error:** database or query timeout. Inspect logs.

**Filtering rules:**
- All filters are AND-combined (all conditions must match).
- TLP filter (`tlp=`) is **intersected** with the publishable set. Requesting `tlp=RED` when RED is not publishable returns zero rows.
- Non-publishable documents are never stored or returned (double-layered gate: ingestion + query).
- Withdrawn advisories are excluded from the list.
- Results are limited to the latest revision per advisory (determined by version and release date).

### `GET /api/advisories/search`

Alias for `/api/advisories`. Both paths accept the same query parameters.

### `GET /api/documents/:id`

Fetch the stored CSAF JSON for a single advisory revision.

**Path parameter:**
- `id` (integer): the document ID (from the `advisories` list response)

**Response (200 OK):**
```json
{
  "document": {
    "csaf_version": "2.0",
    "tracking": { "id": "securityportal-2026-0001", ... },
    ...
  }
}
```

The response body is the exact stored CSAF JSON, served with `Content-Type: application/json; charset=utf-8`.

**Responses:**
- **200 OK:** document found and publishable.
- **404 Not Found:** document does not exist, is withdrawn, or is non-publishable. (404 is returned for both missing and unpublishable to avoid confirming the existence of restricted documents.)
- **400 Bad Request:** malformed ID (not an integer).
- **500 Internal Server Error:** database error.

**Semantics:**
- The stored JSON is canonicalized (may have reordered keys, normalized whitespace). For byte-identical retrieval, `original` bytes are available but not currently exposed.
- Withdrawn advisories' documents are still served (permalink stability).

### `GET /api/facets`

Compute distinct values and counts for filter sidebar facets, applying all active filters (drill-down behavior).

**Query parameters:** Same as `/api/advisories` (all facet and search filters).

**Response (200 OK):**
```json
{
  "publishers": [
    { "name": "Example AG", "count": 15 },
    { "name": "Other Corp", "count": 8 }
  ],
  "tlps": [
    { "label": "WHITE", "count": 22 },
    { "label": "UNLABELED", "count": 1 }
  ],
  "categories": [
    { "name": "csaf_security_advisory", "count": 20 },
    { "name": "csaf_vex", "count": 3 }
  ],
  "severities": [
    { "band": "critical", "count": 3 },
    { "band": "high", "count": 7 },
    ...
  ],
  "languages": [
    { "lang": "en", "count": 18 },
    { "lang": "de", "count": 5 }
  ],
  "vendors": [
    { "name": "Vendor A", "count": 12 },
    ...
  ],
  "products": [
    { "name": "Product X", "count": 9 },
    ...
  ]
}
```

**Responses:**
- **200 OK:** success.
- **400 Bad Request:** malformed filter parameter.
- **500 Internal Server Error:** database error.

## Development and testing

### Commands

```bash
# Build
go build ./...

# Lint and format
go vet ./...
gofmt -l .  # Shows files needing formatting (none = clean)

# Tests (unit + integration with docker-in-docker)
go test ./...

# Known-vulnerability check (requires Go 1.26.4+)
make vuln

# Software Bill of Materials (requires cyclonedx-gomod)
make sbom
```

### Integration tests

Tests that require a database run against a temporary `postgres:16-alpine` container via Docker-in-Docker. They skip gracefully if Docker is unavailable:

```bash
go test ./...  # All tests run
# Without docker on PATH: integration tests skip cleanly, unit tests run
```

Test files:
- `pkg/database/migrations_integration_test.go` — schema and trigger correctness
- `pkg/database/store_integration_test.go` — persistence and TLP gating
- `pkg/database/queries_integration_test.go` — list/search/facet SQL
- `pkg/ingest/ingest_test.go` — download + verify (in-process TLS provider)
- `pkg/ingest/persist_integration_test.go` — full ingest cycle with DB
- `pkg/ingest/sweepguard_integration_test.go` — deletion sweep safety guards
- `pkg/web/api_integration_test.go` — HTTP API end-to-end with real DB
- `pkg/web/handlers_test.go` — handler unit tests with fake DB

## Security notes

### TLP publishing policy

The `SECURITYPORTAL_PUBLISHABLE_TLP` env variable controls which TLP labels are public. Default is `WHITE,UNLABELED`. Documents with any other label (GREEN, AMBER, RED) are never ingested or served.

**Two-layer gate:**
1. **Ingestion:** advisories whose feed TLP or document TLP is not in the publishable set are dropped entirely. Non-publishable documents are never written to Postgres.
2. **API:** every query (list, facets, document fetch) applies an additional `upper(tlp) = ANY(publishable_set)` filter in SQL (defense in depth).

### Hash and signature verification

Every advisory is verified before storage:
1. Downloaded over HTTPS from the Trusted Provider.
2. SHA256 or SHA512 hash (strongest available) is checked against the provider's hash file.
3. Detached PGP signature is verified against keys listed in the provider's `provider-metadata.json`.

Verification failures cause the advisory to be skipped (logged as a warning); a missing or invalid key ring causes the entire ingestion run to abort. The ingestion is fail-closed.

### Read-only API

The API exposes GET endpoints only. No mutation, no user accounts, no sessions (except a client-side locale preference).

### DoS protection

- **Pagination offset cap:** requests with `offset > 10000` are rejected with 400 rather than silently clamped, so the caller knows to use cursor pagination instead. Deep offsets force Postgres to scan and discard many rows (C-7 / R-4).
- **Query timeout:** the `SECURITYPORTAL_QUERY_TIMEOUT` setting (default 5s) cancels slow queries server-side (threat model C-7 / R-4).
- **Download size limit:** advisories larger than 32 MiB are rejected during ingestion.

### Secrets and logging

- The `DATABASE_DSN` is **never logged** (only whether it is set).
- API errors are generic (no SQL, stack traces, or internal hostnames).
- The server runs in Gin release mode (no debug logging).

### Content security

Untrusted CSAF content is treated carefully by the frontend:
- Free-text fields are **escaped plain text with `white-space: pre-wrap`** (see ADR-0001).
- HTML-derived URLs are scheme-checked (allow `http`, `https`, `mailto`; block `javascript:`, `data:`) before rendering.
- A Content Security Policy (CSP) restricts script execution.

## Deployment options

SecurityPortal supports three deployment targets with identical runtime config and security properties:

1. **Docker Compose** (batteries-included) — `docs/DEPLOYMENT.md`. Bundled Caddy reverse proxy, all services in containers, local self-signed or ACME/BYO TLS.
2. **Kubernetes Helm chart** — `deploy/helm/securityportal/` in the main repository. Deployments + Services, Ingress for TLS, optional bundled PostgreSQL, ConfigMap/Secret for config.
3. **Bare-metal / hand-rolled** — `docs/DEPLOYMENT-BAREMETAL.md`. Go binary + Node.js under systemd, external Postgres, operator-provided reverse proxy (nginx/Caddy examples included).

All three share the same `SECURITYPORTAL_*` environment variables and security-header ownership model (app owns CSP, proxy owns HSTS/TLS). Choose the target that fits your infrastructure.

## Deployment checklist

Before going live, ensure:

- [ ] `SECURITYPORTAL_PROVIDER_URL` points to your Trusted Provider.
- [ ] `SECURITYPORTAL_PUBLISHABLE_TLP` lists only the TLP labels you want public.
- [ ] Database credentials are strong (not the `changeme` defaults).
- [ ] The reverse proxy in front of the stack owns TLS/HSTS and rate limiting (not implemented here).
- [ ] Postgres is backed up regularly (e.g., `pg_dump` snapshots).
- [ ] Logs are monitored (poll success/failure, API errors).
- [ ] The web frontend's legal pages (`/impressum`, `/datenschutz`) are completed (currently placeholders).

## Architecture and decisions

See the workspace-level documentation:
- **Threat model:** `.ai/shared/threat-model.md`
- **ADRs (Architecture Decision Records):** `.ai/shared/decisions/`
  - ADR-0001: CSAF free-text rendering (escaped plain text + pre-wrap)
  - ADR-0003: Vendoring csaf_webview components (Svelte 5)
  - ADR-0005: Facet extraction and full-text search (tsvector)
  - ADR-0006: Content Security Policy headers
  - ADR-0007: URL-scheme allow-list for `<a href>` elements
  - ADR-0008: Ingestion SSRF posture for provider metadata URLs

## License

Apache-2.0. See `LICENSES/Apache-2.0.txt` and `LICENSE`.

Vendored dependencies retain their original licenses (e.g., `gocsaf` is Apache-2.0 by BSI/Intevation).
