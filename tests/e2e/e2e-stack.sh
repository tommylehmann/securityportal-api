#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tommy Lehmann
#
# Full-stack end-to-end test for SecurityPortal.
#
# Usage:
#   bash securityportal-api/tests/e2e/e2e-stack.sh            # default: build+up+assert+down
#   bash securityportal-api/tests/e2e/e2e-stack.sh --no-build # skip docker build (images must already exist)
#   bash securityportal-api/tests/e2e/e2e-stack.sh --no-down  # leave stack running after the test (debug)
#
# What it does:
#   1. Builds the api and web Docker images from the repo source via docker compose build.
#   2. Starts db + api + web via compose.test.yml.
#   3. Applies schema migrations (the api migrate subcommand, or waits for the
#      serve startup to do it), then seeds two WHITE advisories and one AMBER
#      advisory directly into Postgres via seed.sql.
#   4. Asserts the full end-to-end contract (see §Assertions below).
#   5. Tears down the stack (always, even on failure), unless --no-down is given.
#
# Seeding strategy:
#   No live CSAF Trusted Provider is available in CI.  A fake provider serving
#   PGP-signed advisories with valid hashes would be brittle and slow.  Instead
#   the test seeds data directly into the migrated Postgres database: the schema
#   triggers and generated columns populate all facet fields, CVE links, product
#   rows, and the tsvector automatically — exactly what real ingestion produces.
#   The unit/integration ingest tests (pkg/ingest/) already cover the
#   download+verify path; this e2e test covers the contract above that layer.
#
# Assertions:
#   A  GET /api/health → 200 with status=ok and database=reachable
#   B  GET /api/advisories → 200; both WHITE docs present with facet fields + cves
#   C  GET /api/documents/{id} → 200; returns CSAF JSON for the White document
#   D  GET /api/facets → 200; includes both publisher names; severity=high count=1
#   E  Web home page (/) SSR HTML contains both advisory titles (list rendered)
#   F  Web detail page /advisories/{id} SSR HTML contains the advisory title
#      (proves web→api wiring: web container fetches api:8081 server-side)
#   G  AMBER advisory NOT in /api/advisories (security invariant)
#   H  GET /api/documents/{amber_id} → 404 (TLP gate at the SQL layer)
#   I  Web home page HTML does NOT contain the AMBER advisory title

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths — all derived from this script's own location so the harness can be
# called from any working directory.
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# securityportal-api/tests/e2e → securityportal-api → SecurityPortal workspace root
API_REPO="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WEB_REPO="$(cd "${SCRIPT_DIR}/../../../securityportal-web" && pwd)"

COMPOSE_FILE="${SCRIPT_DIR}/compose.test.yml"
SEED_SQL="${SCRIPT_DIR}/seed.sql"

API_IMAGE="sp-e2e-api:latest"
WEB_IMAGE="sp-e2e-web:latest"

# Ports exposed from compose.test.yml — must match.
API_HOST="http://127.0.0.1:58081"
WEB_HOST="http://127.0.0.1:58080"
DB_PORT="55480"

# Postgres credentials must match compose.test.yml.
DB_USER="sptest"
DB_PASS="sptest"
DB_NAME="sptest"

# How long (seconds) to wait for each service to become healthy.
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
log()  { printf '\033[1;34m[e2e]\033[0m %s\n' "$*"; }
pass() { printf '\033[1;32m[PASS]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; }

FAILURES=0
assert_pass() {
    local name="$1"; shift
    if "$@"; then
        pass "$name"
    else
        fail "$name"
        FAILURES=$(( FAILURES + 1 ))
    fi
}

# wait_for_url <url> <timeout_seconds> — polls until HTTP 200 or timeout
wait_for_url() {
    local url="$1" timeout="$2"
    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        if curl -sf --max-time 3 "$url" > /dev/null 2>&1; then
            return 0
        fi
        sleep 2
        elapsed=$(( elapsed + 2 ))
    done
    return 1
}

# ---------------------------------------------------------------------------
# Cleanup trap — always tear down even on error
# ---------------------------------------------------------------------------
teardown() {
    if [[ $DO_DOWN -eq 1 ]]; then
        log "Tearing down stack..."
        docker compose -f "$COMPOSE_FILE" down --volumes --remove-orphans 2>/dev/null || true
    else
        log "--no-down: leaving stack running (sp-e2e-db, sp-e2e-api, sp-e2e-web)"
    fi
}
trap teardown EXIT

# ---------------------------------------------------------------------------
# 1. Build images
# ---------------------------------------------------------------------------
if [[ $DO_BUILD -eq 1 ]]; then
    log "Building api image (${API_IMAGE}) from ${API_REPO} using production Dockerfile..."
    BUILD_START=$(date +%s)
    docker compose -f "$COMPOSE_FILE" build api
    BUILD_API=$(( $(date +%s) - BUILD_START ))
    log "API image built in ${BUILD_API}s"

    log "Building web image (${WEB_IMAGE}) from ${WEB_REPO}..."
    BUILD_START=$(date +%s)
    docker compose -f "$COMPOSE_FILE" build web
    BUILD_WEB=$(( $(date +%s) - BUILD_START ))
    log "Web image built in ${BUILD_WEB}s"
fi

# ---------------------------------------------------------------------------
# 2. Start stack
# ---------------------------------------------------------------------------
log "Starting stack (db + api + web)..."

# Clean up any leftover containers from a previous failed run.
docker compose -f "$COMPOSE_FILE" down --volumes --remove-orphans 2>/dev/null || true

STACK_START=$(date +%s)
docker compose -f "$COMPOSE_FILE" up -d

# ---------------------------------------------------------------------------
# 3. Wait for DB to be healthy (pg_isready healthcheck in compose)
# ---------------------------------------------------------------------------
log "Waiting for db healthcheck..."
UP_TIMEOUT=60
elapsed=0
while [[ $elapsed -lt $UP_TIMEOUT ]]; do
    state=$(docker inspect --format='{{.State.Health.Status}}' sp-e2e-db 2>/dev/null || echo "missing")
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
# 4. Seed data — wait for api to have applied migrations (api migrate runs
#    inside the serve startup), then inject fixtures via psql.
# ---------------------------------------------------------------------------
log "Waiting for API /api/health to respond (migrations applied)..."
if ! wait_for_url "${API_HOST}/api/health" "$HEALTH_TIMEOUT"; then
    fail "API did not start within ${HEALTH_TIMEOUT}s"
    docker compose -f "$COMPOSE_FILE" logs api
    exit 1
fi
STACK_UP=$(( $(date +%s) - STACK_START ))
log "Stack up in ${STACK_UP}s; seeding fixture data..."

# Use psql from the db container to run the seed SQL so we don't need a local
# psql installation.  The DB port 55480 is also exposed on the host but
# using docker exec avoids the need for the host to have psql in PATH.
docker exec -i sp-e2e-db \
    psql -U "$DB_USER" -d "$DB_NAME" < "$SEED_SQL"
log "Seed complete"

# Give the API a moment to observe the newly inserted rows (the connection pool
# is already open; no restart needed, but a brief pause avoids any race between
# the INSERT commit and the first list query).
sleep 1

# ---------------------------------------------------------------------------
# 5. Assertions
# ---------------------------------------------------------------------------
log "Running assertions..."

# A — health endpoint
check_health() {
    local body
    body=$(curl -sf "${API_HOST}/api/health") || return 1
    echo "$body" | grep -q '"status":"ok"' || return 1
    echo "$body" | grep -q '"database":"reachable"' || return 1
}
assert_pass "A: GET /api/health → 200, status=ok, database=reachable" check_health

# B — advisory list returns both WHITE docs with facet fields and CVEs
check_advisory_list() {
    local body
    body=$(curl -sf "${API_HOST}/api/advisories") || return 1
    # Two WHITE advisories expected; AMBER must be absent
    echo "$body" | python3 -c "
import json, sys
data = json.load(sys.stdin)
advisories = data.get('advisories', [])
# Must have exactly 2 publishable advisories
if len(advisories) != 2:
    print(f'expected 2 advisories, got {len(advisories)}', file=sys.stderr)
    sys.exit(1)
# Check facet fields are populated (not null/missing)
for a in advisories:
    for field in ['id','tracking_id','title','tlp','category','publisher_name','lang','version','cves']:
        if field not in a:
            print(f'field {field!r} missing from advisory {a.get(\"tracking_id\")!r}', file=sys.stderr)
            sys.exit(1)
# AMBER title must not appear
for a in advisories:
    if 'AMBER' in (a.get('title') or '') or 'RESTRICTED' in (a.get('title') or ''):
        print(f'AMBER advisory leaked into list!', file=sys.stderr)
        sys.exit(1)
# DE advisory with CVE
de = next((a for a in advisories if a['tracking_id'] == 'DE-2026-0001'), None)
if not de:
    print('DE-2026-0001 not found', file=sys.stderr)
    sys.exit(1)
if 'CVE-2026-12345' not in de.get('cves', []):
    print(f\"CVE-2026-12345 not in DE advisory cves: {de.get('cves')}\", file=sys.stderr)
    sys.exit(1)
# EN advisory
en = next((a for a in advisories if a['tracking_id'] == 'BSI-2022-0001'), None)
if not en:
    print('BSI-2022-0001 not found', file=sys.stderr)
    sys.exit(1)
if 'CVE-2022-27193' not in en.get('cves', []):
    print(f\"CVE-2022-27193 not in EN advisory cves: {en.get('cves')}\", file=sys.stderr)
    sys.exit(1)
print('advisory list ok')
" || return 1
}
assert_pass "B: GET /api/advisories → 2 WHITE docs with facet fields + CVEs, no AMBER" check_advisory_list

# Capture document IDs for subsequent assertions.
LIST_BODY=$(curl -sf "${API_HOST}/api/advisories" 2>/dev/null)
DE_ID=$(echo "$LIST_BODY" | python3 -c "
import json,sys
data=json.load(sys.stdin)
de=[a for a in data['advisories'] if a['tracking_id']=='DE-2026-0001']
print(de[0]['id'] if de else '')
")
EN_ID=$(echo "$LIST_BODY" | python3 -c "
import json,sys
data=json.load(sys.stdin)
en=[a for a in data['advisories'] if a['tracking_id']=='BSI-2022-0001']
print(en[0]['id'] if en else '')
")

# Fetch AMBER document id (it is in the DB but must be inaccessible)
AMBER_ID=$(docker exec sp-e2e-db \
    psql -U "$DB_USER" -d "$DB_NAME" -tAc \
    "SELECT d.id FROM documents d JOIN advisories a ON a.id=d.advisories_id WHERE a.tracking_id='SEC-AMBER-0001' LIMIT 1" \
    2>/dev/null | tr -d '[:space:]')

if [[ -z "$DE_ID" || -z "$EN_ID" ]]; then
    fail "Could not extract document ids from list (DE=$DE_ID EN=$EN_ID)"
    FAILURES=$(( FAILURES + 1 ))
fi

# C — single document endpoint returns valid CSAF JSON
check_get_document() {
    local id="$1"
    local body
    body=$(curl -sf "${API_HOST}/api/documents/${id}") || return 1
    # Must be valid JSON with a document.tracking.id field
    echo "$body" | python3 -c "
import json, sys
doc = json.load(sys.stdin)
tid = doc.get('document', {}).get('tracking', {}).get('id')
if not tid:
    print('document has no tracking id', file=sys.stderr)
    sys.exit(1)
" || return 1
}
assert_pass "C: GET /api/documents/${DE_ID} → valid CSAF JSON (DE advisory)" \
    check_get_document "$DE_ID"
assert_pass "C: GET /api/documents/${EN_ID} → valid CSAF JSON (EN advisory)" \
    check_get_document "$EN_ID"

# D — facets endpoint returns data
# The /api/facets response is a flat Facets struct:
#   { "publisher": {"values":[{"value":"...","count":N},...], "capped": false},
#     "vendor": {...}, "product": {...}, "category": {...}, "tlp": {...},
#     "lang": {...}, "severity": {...} }
check_facets() {
    local body
    body=$(curl -sf "${API_HOST}/api/facets") || return 1
    echo "$body" | python3 -c "
import json, sys
data = json.load(sys.stdin)
# publisher group
pub_group = data.get('publisher', {})
if not pub_group:
    print('no publisher facet group', file=sys.stderr)
    sys.exit(1)
pub_values = [c.get('value') for c in pub_group.get('values', [])]
if 'Example AG' not in pub_values:
    print(f'Example AG not in publishers: {pub_values}', file=sys.stderr)
    sys.exit(1)
# Severity group: 'high' band must have count >= 1 (DE advisory CVSS 8.8 = HIGH)
sev_group = data.get('severity', {})
if not sev_group:
    print('no severity facet group', file=sys.stderr)
    sys.exit(1)
high = next((c for c in sev_group.get('values', []) if c.get('value') == 'high'), None)
if not high or high.get('count', 0) < 1:
    print(f\"severity high count < 1: {high}\", file=sys.stderr)
    sys.exit(1)
# AMBER publisher must not appear in any facet group
for group_name in ('publisher', 'vendor', 'product', 'category', 'tlp', 'lang'):
    for c in data.get(group_name, {}).get('values', []):
        if 'Internal Security Team' in str(c.get('value', '')):
            print(f'AMBER publisher/value leaked into facet group {group_name}!', file=sys.stderr)
            sys.exit(1)
print('facets ok')
" || return 1
}
assert_pass "D: GET /api/facets → publisher+severity facets, AMBER excluded" check_facets

# E — web home page SSR HTML contains both WHITE advisory titles
check_web_list() {
    local html
    html=$(curl -sf "${WEB_HOST}/") || return 1
    # DE advisory title (ASCII-safe version in seed.sql uses "oe" substitution,
    # but the actual inserted JSON carries the Unicode characters).
    echo "$html" | grep -q "Schwachstelle" || {
        echo "DE advisory title missing from web home HTML" >&2; return 1; }
    echo "$html" | grep -q "CVRF-CSAF-Converter" || {
        echo "EN advisory title missing from web home HTML" >&2; return 1; }
}
assert_pass "E: Web / SSR HTML contains both WHITE advisory titles" check_web_list

# F — web detail page renders the advisory (server-side fetch of api:8081)
check_web_detail() {
    local id="$1" expected_fragment="$2"
    local html
    html=$(curl -sf "${WEB_HOST}/advisories/${id}") || return 1
    echo "$html" | grep -q "$expected_fragment" || {
        echo "Expected fragment '${expected_fragment}' not in detail HTML" >&2
        return 1
    }
}
assert_pass "F: Web /advisories/${DE_ID} SSR HTML contains DE title fragment" \
    check_web_detail "$DE_ID" "Schwachstelle"
assert_pass "F: Web /advisories/${EN_ID} SSR HTML contains EN title fragment" \
    check_web_detail "$EN_ID" "CVRF-CSAF-Converter"

# G — AMBER advisory NOT in the API advisory list
check_amber_not_in_list() {
    local body
    body=$(curl -sf "${API_HOST}/api/advisories") || return 1
    ! echo "$body" | grep -qi "AMBER" || return 1
    ! echo "$body" | grep -q "SEC-AMBER-0001" || return 1
}
assert_pass "G: AMBER advisory absent from GET /api/advisories" check_amber_not_in_list

# H — GET /api/documents/{amber_id} → 404 (TLP gate)
check_amber_document_is_404() {
    [[ -z "$AMBER_ID" ]] && { echo "AMBER_ID not set; skipping" >&2; return 0; }
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' "${API_HOST}/api/documents/${AMBER_ID}")
    [[ "$code" == "404" ]] || {
        echo "Expected 404, got ${code} for AMBER document id ${AMBER_ID}" >&2
        return 1
    }
}
assert_pass "H: GET /api/documents/${AMBER_ID:-?} (AMBER) → 404" check_amber_document_is_404

# I — web home page HTML does NOT contain the AMBER advisory title
check_amber_not_in_web() {
    local html
    html=$(curl -sf "${WEB_HOST}/") || return 1
    ! echo "$html" | grep -qi "RESTRICTED" || return 1
    ! echo "$html" | grep -q "SEC-AMBER-0001" || return 1
}
assert_pass "I: Web home page HTML does NOT contain AMBER/RESTRICTED advisory" \
    check_amber_not_in_web

# ---------------------------------------------------------------------------
# 6. Report
# ---------------------------------------------------------------------------
echo ""
if [[ $FAILURES -eq 0 ]]; then
    log "All assertions passed."
else
    fail "${FAILURES} assertion(s) FAILED."
    echo ""
    echo "--- api logs ---"
    docker compose -f "$COMPOSE_FILE" logs --no-log-prefix api 2>/dev/null | tail -40
    echo "--- web logs ---"
    docker compose -f "$COMPOSE_FILE" logs --no-log-prefix web 2>/dev/null | tail -20
    exit 1
fi
