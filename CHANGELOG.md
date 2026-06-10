<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Tommy Lehmann
-->

# Changelog

All notable changes to the SecurityPortal API are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (Phase 8 — REST maturity, publisher routing, feeds, content pages, authz seam)

#### API Contract & OpenAPI (ADR-0015)
- **Named response structs:** all endpoints return typed JSON responses (`AdvisoryListResponse`, `HealthResponse`, `ErrorResponse`, `WithdrawnEnvelope`, `FacetsResponse`) instead of `gin.H{}` literals. The same types appear in the OpenAPI document, ensuring schema and implementation stay in sync.
- **OpenAPI 3.1 contract:** `GET /api/openapi.json` serves a hand-written specification of all public endpoints, response schemas, and status matrices. `GET /api/docs` provides an interactive Redoc viewer with same-origin JS (no CDN) — the canonical reference for API consumers.
- **Withdrawn advisories now return HTTP 410 Gone** (was 200 in earlier phases): when an advisory is tombstoned, the response is 410 with the minimal envelope `{ "withdrawn": true, "tracking_id": "...", "withdrawn_at": "..." }` — semantically correct for "gone but historically addressable" and properly handled by feed readers and caches.
- **HATEOAS `_links`:** collection responses (list, publisher-collection, facets) carry `_links` with pagination controls (`first`, `prev`, `next`, `self`); each advisory row carries `_links.self` pointing to its canonical permalink.
- **CSV export:** `format=csv` on list endpoints streams the advisory columns as RFC-4180 CSV with OWASP formula-injection guards (cells starting with `=+-@` are prefixed with `'`).

#### Publisher-hierarchy routing (ADR-0016)
- **Publisher-scoped permalink:** `GET /api/advisories/{publisher}/{trackingid}` is the **only** public advisory permalink (no flat single-segment form). Both segments are URL-encoded path parameters (256-byte max each), TLP-gated, and bound to prevent SQL injection and traversal attacks.
- **Publisher collection:** `GET /api/advisories/{publisher}` lists advisories for one publisher (reuses list filters; arity of 1 segment disambiguates collection from the 2-segment resource).
- **Static routes protected:** `feed.atom` and `openapi.json` are registered as static segments before the `{publisher}` wildcard, so they cannot be shadowed by publisher names containing those strings.

#### Atom feeds (ADR-0017)
- **Global feed:** `GET /api/feed.atom` returns valid Atom 1.0 XML of the most-recent publishable, non-withdrawn advisories (limit 25–100, default 25). Entries are metadata-only: title, dates, CVE list, severity band; **no free-text body** (readers follow the HTML link to the portal).
- **Per-publisher feed:** `GET /api/advisories/{publisher}/feed.atom` mirrors the global feed scoped to one publisher. Unknown publisher returns a valid empty feed.
- **XML escaping:** all advisory-derived text is marshalled via `encoding/xml`, so HTML/special chars are automatically escaped — no manual XML concatenation.
- **Web link:** each entry's `<link rel="alternate">` points to the publisher-scoped web detail route `/advisories/{publisher}/{trackingid}` (percent-encoded).

#### Content-page system (ADR-0018)
- **Closed registry:** `src/lib/content/registry.ts` maps slug → `{ titleKey, kind }`. Request input is looked up in the registry only; no path join ever touches untrusted input (SA-52 / C-36).
- **Two source kinds:**
  - `legal` — operator-mounted Markdown at `${LEGAL_DIR}/<slug>.<locale>.md`; uses the 512 KiB cap, missing→other-locale→i18n-placeholder fallback, and sanitization pipeline from ADR-0010.
  - `repo` — bundled Markdown in `src/lib/content/<slug>.<locale>.md`; trusted but still sanitized (belt-and-suspenders).
- **User manual:** a new `manual` page (kind `repo`) documents the public API with links to `/api/docs`.

#### Authorization seam (ADR-0019 — prepare only, no live OAuth2)
- **Principal abstraction:** `pkg/auth/principal.go` defines a `Principal` type with `AllowedTLP()` and `Roles()` methods.
- **Anonymous principal:** v1 always uses the anonymous principal, which returns the configured public TLP set (default: `{WHITE, UNLABELED}`). Behaviour is byte-identical to earlier phases.
- **Seam for OAuth2:** an unregistered `bearerTokenResolver` stub documents the integration point for future OIDC/Keycloak additions. The roles→TLP mapping is config-driven; authenticated roles *widen* the allowed set (e.g., `green-reader` adds `GREEN`), never narrow it.
- **TLP gate unchanged:** the SQL-layer enforcement point (`upper(d.tlp)=ANY($allowed_set)`) stays the single gate; only its source changes (static field → per-request principal).

### Changed

- **`GET /api/documents/:id` reclassified as internal:** The numeric surrogate ID endpoint is no longer the public advisory permalink. It is retained for internal revision-level access and debug use; the frontend now links to `/api/advisories/{publisher}/{trackingid}` (ADR-0016).
- **`GET /api/advisories/search` removed:** the old search alias is retired; `q` parameter is honoured on the main `/api/advisories` list endpoint (ADR-0015).
- **Withdrawn response code:** now 410 Gone instead of 200 OK, with the same envelope structure. The web frontend and feed readers handle 410 correctly; HTTP caches respect the "gone" semantics.

### Security

- **Publisher routing:** both `{publisher}` and `{trackingid}` path segments are URL-decoded by the router and bound as statement parameters (no SQL injection). Segment length is capped at 256 bytes before any query.
- **Path safety:** `UseRawPath=true` prevents `%2F` from shifting arity; static `feed.atom` and `openapi.json` are registered before wildcards to prevent shadowing.
- **CSV injection guards:** cells starting with `=+-@` are prefixed with `'` to prevent formula injection in spreadsheet apps (OWASP CWE-1236).
- **Atom XML escaping:** all entry text fields are marshalled via `encoding/xml`, automatically escaping `<`, `&`, etc. No free-text content is placed in feed entries, so hostile notes/remediation cannot break XML structure or inject markup.
- **Withdrawn/missing parity:** 404 is returned for both missing and non-publishable advisories; withdrawn advisories return 410 (distinct, so the "no longer published" notice can be shown). No existence oracle for restricted documents (spec §12 defense in depth).
- **OpenAPI same-origin:** the Redoc JS bundle is vendored and embedded (`pkg/web/static/redoc.standalone.js`), served from the same origin. No external CDN is contacted — the security-critical no-CDN property is verified by tests.
