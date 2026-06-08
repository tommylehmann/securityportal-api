#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tommy Lehmann
#
# Task 35 — Caddy proxy e2e smoke test.
#
# Brings up caddy + web + api + db in the same topology as the production
# docker/docker-compose.yml and asserts the full same-origin contract.
#
# Usage:
#   bash securityportal-api/tests/e2e/e2e-proxy.sh            # build+up+assert+down
#   bash securityportal-api/tests/e2e/e2e-proxy.sh --no-build # skip docker build
#   bash securityportal-api/tests/e2e/e2e-proxy.sh --no-down  # leave stack running
#
# Port mapping (avoids collision with the production stack on 80/443):
#   Host 8443  → Caddy 443  (HTTPS — primary entry point, -k for self-signed cert)
#   Host 8880  → Caddy 80   (HTTP)
#   Host 55490 → db   5432  (psql seed)
#
# Assertions:
#   1  HTTPS /api/health through Caddy → 200, status=ok, database=reachable (SA-21 same-origin /api)
#   2  HTTPS / through Caddy → 200, web app SSR HTML contains a known string
#   3  HTTPS /api/advisories → seeded advisory titles in SSR HTML (list through proxy)
#   4  SA-24: HTTPS response carries Strict-Transport-Security (set exactly once)
#   5  SA-23: response carries exactly one CSP, one X-Frame-Options, one Referrer-Policy,
#            one X-Content-Type-Options (no duplication from app+proxy)
#   6  SA-21 no-bypass: api:8081 and web:8080 are NOT reachable on former direct host ports;
#          docker compose ps confirms only Caddy publishes 80/443 (mapped to 8443/8880)
#   7  SA-26 rate-limit (caddy-ratelimit module): burst of requests over the low cap (5/60s)
#          configured in compose.proxy.test.yml yields at least one 429 Too Many Requests;
#          requests under the cap succeed with 200. Proves the custom Caddy image is used
#          (stock caddy:2 rejects the rate_limit directive entirely).

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths — derived from this script's location so it can be called from anywhere.
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_REPO="$(cd "${SCRIPT_DIR}/../.." && pwd)"

COMPOSE_FILE="${SCRIPT_DIR}/compose.proxy.test.yml"
SEED_SQL="${SCRIPT_DIR}/seed.sql"

# Host ports — must match compose.proxy.test.yml.
# NOTE: Caddy's self-signed cert (tls internal) is issued for the hostname
# "localhost", so HTTPS connections must use "localhost" as the hostname.
# Using 127.0.0.1 triggers an SSL handshake error (curl exit 35) because the
# certificate SAN covers "localhost", not the bare IP.
CADDY_HTTPS="https://localhost:8443"
CADDY_HTTP="http://localhost:8880"
DB_PORT="55490"
DB_USER="sptest"
DB_PASS="sptest"
DB_NAME="sptest"

HEALTH_TIMEOUT=120

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
DO_BUILD=1
DO_DOWN=1
for arg in "$@"; do
    case "$arg" in
        --no-build) DO_BUILD=0 ;;
        --no-down)  DO_DOWN=0  ;;
    esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '\033[1;34m[e2e-proxy]\033[0m %s\n' "$*"; }
pass() { printf '\033[1;32m[PASS]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; }

FAILURES=0
assert_pass() {
    local name="$1"; shift
    if "$@" 2>/dev/null; then
        pass "$name"
    else
        fail "$name"
        FAILURES=$(( FAILURES + 1 ))
    fi
}

assert_fail() {
    # asserts a command FAILS (e.g. connection refused = expected no port exposed)
    local name="$1"; shift
    if ! "$@" 2>/dev/null; then
        pass "$name"
    else
        fail "$name"
        FAILURES=$(( FAILURES + 1 ))
    fi
}

wait_for_url() {
    local url="$1" timeout="$2"
    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        # -k: skip cert verification (self-signed); -L: follow redirects;
        # --max-time 5: per-attempt timeout so a hung TLS handshake doesn't stall.
        if curl -skL --max-time 5 "$url" > /dev/null 2>&1; then
            return 0
        fi
        sleep 3
        elapsed=$(( elapsed + 3 ))
    done
    return 1
}

# count_header <header-name> <headers-blob>
# Counts exact header occurrences (case-insensitive name match, colon-terminated).
count_header() {
    local name="$1" headers="$2"
    echo "$headers" | grep -ic "^${name}:" || true
}

# ---------------------------------------------------------------------------
# Cleanup trap
# ---------------------------------------------------------------------------
teardown() {
    if [[ $DO_DOWN -eq 1 ]]; then
        log "Tearing down proxy test stack..."
        docker compose -f "$COMPOSE_FILE" down --volumes --remove-orphans 2>/dev/null || true
    else
        log "--no-down: leaving stack running"
    fi
}
trap teardown EXIT

# ---------------------------------------------------------------------------
# 1. Build images
# ---------------------------------------------------------------------------
if [[ $DO_BUILD -eq 1 ]]; then
    log "Building api image (sp-proxy-e2e-api:latest)..."
    BUILD_START=$(date +%s)
    docker compose -f "$COMPOSE_FILE" build api
    log "API image built in $(( $(date +%s) - BUILD_START ))s"

    log "Building web image (sp-proxy-e2e-web:latest)..."
    BUILD_START=$(date +%s)
    docker compose -f "$COMPOSE_FILE" build web
    log "Web image built in $(( $(date +%s) - BUILD_START ))s"

    log "Building caddy image (sp-proxy-e2e-caddy:latest) — custom xcaddy + caddy-ratelimit..."
    BUILD_START=$(date +%s)
    docker compose -f "$COMPOSE_FILE" build caddy
    log "Caddy image built in $(( $(date +%s) - BUILD_START ))s"
fi

# ---------------------------------------------------------------------------
# 2. Start stack
# ---------------------------------------------------------------------------
log "Starting proxy test stack (db + api + web + caddy)..."
docker compose -f "$COMPOSE_FILE" down --volumes --remove-orphans 2>/dev/null || true

STACK_START=$(date +%s)
docker compose -f "$COMPOSE_FILE" up -d

# ---------------------------------------------------------------------------
# 3. Wait for DB healthcheck
# ---------------------------------------------------------------------------
log "Waiting for db healthcheck..."
UP_TIMEOUT=60
elapsed=0
while [[ $elapsed -lt $UP_TIMEOUT ]]; do
    state=$(docker inspect --format='{{.State.Health.Status}}' sp-proxy-test-db 2>/dev/null || echo "missing")
    if [[ "$state" == "healthy" ]]; then break; fi
    sleep 2; elapsed=$(( elapsed + 2 ))
done
if [[ "$state" != "healthy" ]]; then
    fail "db never became healthy (${elapsed}s)"
    docker compose -f "$COMPOSE_FILE" logs db
    exit 1
fi
log "DB healthy after ${elapsed}s"

# ---------------------------------------------------------------------------
# 4. Wait for API health (migrations applied inside serve startup)
# ---------------------------------------------------------------------------
log "Waiting for API health via Caddy HTTPS (${CADDY_HTTPS}/api/health)..."
if ! wait_for_url "${CADDY_HTTPS}/api/health" "$HEALTH_TIMEOUT"; then
    fail "Caddy/API did not become reachable within ${HEALTH_TIMEOUT}s"
    docker compose -f "$COMPOSE_FILE" logs caddy
    docker compose -f "$COMPOSE_FILE" logs api
    exit 1
fi
STACK_UP=$(( $(date +%s) - STACK_START ))
log "Stack up in ${STACK_UP}s"

# ---------------------------------------------------------------------------
# 5. Seed fixture data (same seed.sql as compose.test.yml)
# ---------------------------------------------------------------------------
log "Seeding fixture data via docker exec..."
docker exec -i sp-proxy-test-db \
    psql -U "$DB_USER" -d "$DB_NAME" < "$SEED_SQL"
log "Seed complete"
sleep 1

# ---------------------------------------------------------------------------
# 6. Assertions
# ---------------------------------------------------------------------------
log "Running assertions..."

# Fetch headers for header-duplication checks (assertions 4 + 5).
# We fetch the web root which carries all app security headers.
WEB_HEADERS=$(curl -sk -D - -o /dev/null "${CADDY_HTTPS}/" 2>/dev/null || true)

# ---------------------------------------------------------------------------
# Assertion 1 — /api/health through Caddy → 200, DB reachable
# ---------------------------------------------------------------------------
check_health_through_caddy() {
    local body
    body=$(curl -sk "${CADDY_HTTPS}/api/health") || return 1
    echo "$body" | grep -q '"status":"ok"' || { echo "status not ok: $body" >&2; return 1; }
    echo "$body" | grep -q '"database":"reachable"' || { echo "database not reachable: $body" >&2; return 1; }
}
assert_pass "1: HTTPS /api/health through Caddy → 200, status=ok, database=reachable" \
    check_health_through_caddy

# ---------------------------------------------------------------------------
# Assertion 2 — HTTPS / serves the web app (known SSR string)
# We confirm the response is HTTP 200 and that x-sveltekit-page header is set
# (adapter-node sets it on every SSR page). Using headers rather than body to
# avoid brittle content matching.
# ---------------------------------------------------------------------------
check_web_root() {
    local code headers
    headers=$(curl -sk -D - -o /dev/null "${CADDY_HTTPS}/") || return 1
    code=$(echo "$headers" | grep -i "^HTTP/" | tail -1 | awk '{print $2}')
    if [[ "$code" != "200" ]]; then
        echo "Expected 200, got ${code}" >&2; return 1
    fi
    # adapter-node sets x-sveltekit-page on all SSR page responses.
    echo "$headers" | grep -qi "x-sveltekit-page" || {
        echo "x-sveltekit-page header not found (not a SvelteKit SSR response)" >&2
        return 1
    }
}
assert_pass "2: HTTPS / through Caddy → 200, web app SSR HTML present (x-sveltekit-page)" check_web_root

# ---------------------------------------------------------------------------
# Assertion 3 — seeded advisory titles appear in SSR list HTML through proxy
# ---------------------------------------------------------------------------
check_list_renders_seeded_titles() {
    local html
    html=$(curl -sk "${CADDY_HTTPS}/") || return 1
    echo "$html" | grep -q "Schwachstelle" || {
        echo "DE advisory title missing from web home HTML" >&2; return 1; }
    echo "$html" | grep -q "CVRF-CSAF-Converter" || {
        echo "EN advisory title missing from web home HTML" >&2; return 1; }
}
assert_pass "3: Seeded advisory titles visible in SSR list HTML through proxy" \
    check_list_renders_seeded_titles

# ---------------------------------------------------------------------------
# Assertion 4 — SA-24: HTTPS response carries Strict-Transport-Security (once)
# ---------------------------------------------------------------------------
check_hsts_present_once() {
    local count
    count=$(count_header "strict-transport-security" "$WEB_HEADERS")
    if [[ "$count" -eq 0 ]]; then
        echo "Strict-Transport-Security header ABSENT" >&2; return 1
    fi
    if [[ "$count" -gt 1 ]]; then
        echo "Strict-Transport-Security duplicated (count=${count})" >&2; return 1
    fi
    # Also confirm it contains the expected max-age value.
    echo "$WEB_HEADERS" | grep -i "^strict-transport-security:" | grep -q "max-age=31536000" || {
        echo "HSTS max-age not 31536000: $(echo "$WEB_HEADERS" | grep -i 'strict-transport-security')" >&2
        return 1
    }
}
assert_pass "4 (SA-24): Strict-Transport-Security present exactly once with max-age=31536000" \
    check_hsts_present_once

# ---------------------------------------------------------------------------
# Assertion 5 — SA-23: no header duplication from app+proxy layers
# Check CSP, X-Frame-Options, Referrer-Policy, X-Content-Type-Options each appear exactly once.
# ---------------------------------------------------------------------------
check_no_duplicate_security_headers() {
    local ok=0

    for header in \
        "content-security-policy" \
        "x-frame-options" \
        "referrer-policy" \
        "x-content-type-options"; do

        local count
        count=$(count_header "$header" "$WEB_HEADERS")
        if [[ "$count" -eq 0 ]]; then
            echo "MISSING expected header: ${header}" >&2
            ok=1
        elif [[ "$count" -gt 1 ]]; then
            echo "DUPLICATED header (count=${count}): ${header}" >&2
            ok=1
        fi
    done

    # Confirm CSP contains expected directives (set by app hooks.server.ts).
    local csp
    csp=$(echo "$WEB_HEADERS" | grep -i "^content-security-policy:" | head -1)
    echo "$csp" | grep -q "default-src" || {
        echo "CSP does not contain default-src: ${csp}" >&2; ok=1; }
    echo "$csp" | grep -q "frame-ancestors" || {
        echo "CSP does not contain frame-ancestors: ${csp}" >&2; ok=1; }

    # Confirm X-Frame-Options has expected value.
    echo "$WEB_HEADERS" | grep -i "^x-frame-options:" | grep -qi "DENY\|SAMEORIGIN" || {
        echo "X-Frame-Options does not contain DENY or SAMEORIGIN" >&2; ok=1; }

    return $ok
}
assert_pass "5 (SA-23): CSP/X-Frame-Options/Referrer-Policy/X-Content-Type-Options each exactly once (no app+proxy duplication)" \
    check_no_duplicate_security_headers

# ---------------------------------------------------------------------------
# Assertion 6 — SA-21 no-bypass: api and web have no direct host ports.
# Test via docker compose ps / docker inspect (no host port = no bypass).
# Also confirm Caddy is the only service with host port bindings.
# ---------------------------------------------------------------------------
check_no_direct_host_ports() {
    # docker compose ps for the proxy test project
    local ps_out
    ps_out=$(docker compose -f "$COMPOSE_FILE" ps 2>/dev/null) || return 1

    # Caddy must be present with 8443/8880 bindings.
    echo "$ps_out" | grep -q "sp-proxy-test-caddy" || {
        echo "caddy container not in compose ps" >&2; return 1; }

    # api must NOT have any host port bindings (only internal 8081).
    local api_ports
    api_ports=$(docker inspect sp-proxy-test-api \
        --format '{{range $p, $b := .NetworkSettings.Ports}}{{if $b}}{{$p}}={{index $b 0}}|{{end}}{{end}}' \
        2>/dev/null || echo "")
    if [[ -n "$api_ports" ]]; then
        echo "api has host port bindings: ${api_ports}" >&2; return 1
    fi

    # web must NOT have any host port bindings (only internal 8080).
    local web_ports
    web_ports=$(docker inspect sp-proxy-test-web \
        --format '{{range $p, $b := .NetworkSettings.Ports}}{{if $b}}{{$p}}={{index $b 0}}|{{end}}{{end}}' \
        2>/dev/null || echo "")
    if [[ -n "$web_ports" ]]; then
        echo "web has host port bindings: ${web_ports}" >&2; return 1
    fi

    # Caddy must expose the expected host ports (8443→443, 8880→80).
    local caddy_ports
    caddy_ports=$(docker inspect sp-proxy-test-caddy \
        --format '{{range $p, $b := .NetworkSettings.Ports}}{{if $b}}{{$p}}:{{(index $b 0).HostPort}} {{end}}{{end}}' \
        2>/dev/null || echo "")
    echo "$caddy_ports" | grep -q "443/tcp:8443" || {
        echo "caddy not binding 8443->443: ${caddy_ports}" >&2; return 1; }
    echo "$caddy_ports" | grep -q "80/tcp:8880" || {
        echo "caddy not binding 8880->80: ${caddy_ports}" >&2; return 1; }
}
assert_pass "6a (SA-21): api has no direct host-port bindings (only reachable through Caddy)" \
    check_no_direct_host_ports

# Additionally: assert a direct connection to former api port (8081) on host is REFUSED.
# The host port 8081 should not be listening for this stack (only Caddy's 8443/8880 are).
check_api_port_not_on_host() {
    # Attempt to connect to localhost:8081 with a short timeout.
    # If the port is unbound, curl fails with "Connection refused".
    # We expect this to FAIL (connection refused = correct, no bypass).
    if curl -s --max-time 2 --connect-timeout 2 "http://127.0.0.1:8081/api/health" > /dev/null 2>&1; then
        echo "api port 8081 is reachable on host — SA-21 bypass possible!" >&2
        return 1
    fi
    return 0
}
assert_pass "6b (SA-21): api:8081 NOT directly reachable on host (connection refused)" \
    check_api_port_not_on_host

check_web_port_not_on_host() {
    # Port 8080 is used by isduba-keycloak in this env; skip this check if it's taken
    # by a foreign container to avoid a false positive.
    local keycloak_running
    keycloak_running=$(docker ps --filter name=isduba-keycloak --format '{{.Names}}' 2>/dev/null | head -1)
    if [[ -n "$keycloak_running" ]]; then
        log "  (skipping web:8080 host-port check — isduba-keycloak is also on 8080; assertion covered by docker inspect above)"
        return 0
    fi
    if curl -s --max-time 2 --connect-timeout 2 "http://127.0.0.1:8080/" > /dev/null 2>&1; then
        echo "web port 8080 is reachable on host — SA-21 bypass possible!" >&2
        return 1
    fi
    return 0
}
assert_pass "6c (SA-21): web:8080 NOT directly reachable on host (or covered by inspect)" \
    check_web_port_not_on_host

# ---------------------------------------------------------------------------
# Assertion 7 — SA-26 (C-14): proxy rate-limit returns 429 on burst.
#
# The compose file sets SP_RATE_LIMIT_REQUESTS=5 / SP_RATE_LIMIT_WINDOW=60s so
# we can trigger the limit with a small burst. We issue 10 rapid requests to
# /api/health (a public read endpoint covered by the @public matcher) and assert
# that at least one returned 429. We also assert the first request returned 200
# (traffic under the limit is not blocked).
#
# A stock caddy:2 image would refuse to start at all because "rate_limit" is an
# unknown directive — so reaching this assertion with the stack already up (where
# /api/health returned 200 in assertion 1) already proves the custom image is
# running. The 429 check provides the explicit functional gate.
# ---------------------------------------------------------------------------
check_rate_limit_returns_429() {
    # The rate-limit cap is 5 requests per 60 s window. Assertions 1-6 have
    # already spent up to 5 requests, so the window may be exhausted by the time
    # we reach this assertion. We therefore issue 10 burst requests and require
    # only that at least one 429 is returned. We do NOT require 200s here because
    # earlier assertions already proved normal traffic succeeds (assertion 1 got
    # 200 from /api/health); requiring 200s here would create a race between
    # whether the window resets before the burst.
    local url="${CADDY_HTTPS}/api/health"
    local got_200=0 got_429=0 got_other=0

    # Fire 10 back-to-back requests as fast as curl allows.
    for i in $(seq 1 10); do
        local code
        code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || true)
        if [[ "$code" == "200" ]]; then
            got_200=$(( got_200 + 1 ))
        elif [[ "$code" == "429" ]]; then
            got_429=$(( got_429 + 1 ))
        else
            got_other=$(( got_other + 1 ))
        fi
    done

    log "  Burst result: ${got_200}×200, ${got_429}×429, ${got_other}×other (cap=5/60s)"

    if [[ "$got_429" -eq 0 ]]; then
        echo "No 429 received after 10 burst requests over the 5/60s cap (rate limit not enforced)." >&2
        echo "got_200=${got_200} got_429=${got_429} got_other=${got_other}" >&2
        echo "Check that SP_RATE_LIMIT_REQUESTS=5 reached the Caddy container and that " \
             "the custom caddy-ratelimit image is in use (not stock caddy:2)." >&2
        return 1
    fi
    return 0
}
assert_pass "7 (SA-26): burst over rate limit (cap=5/60s) → at least one 429 from Caddy" \
    check_rate_limit_returns_429

# ---------------------------------------------------------------------------
# 8. Report
# ---------------------------------------------------------------------------
echo ""
TOTAL_ASSERTIONS=9  # assertions 1,2,3,4,5,6a,6b,6c,7
PASSED=$(( TOTAL_ASSERTIONS - FAILURES ))
log "Assertions: ${PASSED}/${TOTAL_ASSERTIONS} passed, ${FAILURES} failed."

if [[ $FAILURES -eq 0 ]]; then
    log "All assertions passed."
else
    fail "${FAILURES} assertion(s) FAILED."
    echo ""
    echo "--- caddy logs ---"
    docker compose -f "$COMPOSE_FILE" logs --no-log-prefix caddy 2>/dev/null | tail -30
    echo "--- api logs ---"
    docker compose -f "$COMPOSE_FILE" logs --no-log-prefix api 2>/dev/null | tail -30
    echo "--- web logs ---"
    docker compose -f "$COMPOSE_FILE" logs --no-log-prefix web 2>/dev/null | tail -20
    exit 1
fi
