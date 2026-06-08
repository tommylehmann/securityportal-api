<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Tommy Lehmann
-->

# SecurityPortal Deployment Guide (Docker Compose)

This document covers deploying the complete SecurityPortal stack (API + web frontend + Postgres database) to production using Docker Compose.

For other deployment options, see:
- **Bare-metal / hand-rolled:** [`DEPLOYMENT-BAREMETAL.md`](DEPLOYMENT-BAREMETAL.md) (Go binary + Node.js under systemd, external Postgres, operator-provided reverse proxy).
- **Kubernetes:** Helm chart at `deploy/helm/securityportal` in the main repository (Deployments + Ingress, optional bundled PostgreSQL).

## Architecture overview

```
┌─────────────────────────────────────────┐
│        Reverse Proxy / TLS Handler       │
│   (operator-managed: nginx/Caddy/etc)   │
│  - HTTPS termination (TLS/HSTS)          │
│  - Rate limiting                         │
│  - Request logging / WAF                 │
└──────────────┬──────────────────────────┘
               │ HTTPS (port 443)
               ▼
       ┌───────────────────┐
       │   Docker Compose  │
       │  (on Linux host)  │
       ├───────────────────┤
       │ api:8081          │ securityportal-api
       │ web:8080          │ securityportal-web
       │ db:5432           │ postgres:16-alpine
       └───────────────────┘
               │ Port mappings
               ├─ API_PORT:8081
               ├─ WEB_PORT:8080
               └─ DB internal
```

- **Reverse proxy** (not in scope): your nginx/Caddy/Apache instance that:
  - Terminates TLS (provides HTTPS, HSTS, OCSP stapling)
  - Proxies `/` → web container
  - Proxies `/api` → api container
  - Rate limits (per IP, per endpoint) to prevent DoS
  - Logs requests
- **Docker Compose stack** (in scope): runs the three containers on one Linux host, sharing a private network.

## Prerequisites

- Linux host (Ubuntu 22.04 LTS, Rocky Linux 9, etc.) with Docker and Docker Compose installed
- CSAF Trusted Provider URL (you operate this; e.g., `https://provider.example.com`)
- PostgreSQL credentials (generate strong passwords; do NOT use `changeme`)
- Reverse proxy configuration (Nginx/Caddy/Apache outside of SecurityPortal)
- SSL/TLS certificate for your public domain (managed by the reverse proxy)

## Step 1: Prepare the deployment

### Clone / download the code

```bash
git clone <repo-url> /opt/securityportal
cd /opt/securityportal
```

### Generate strong secrets

```bash
# PostgreSQL password (use a password manager to generate this)
POSTGRES_PASSWORD=$(openssl rand -base64 32)
POSTGRES_USER=securityportal
POSTGRES_DB=securityportal

# Confirm they are not empty and look reasonable
echo "User: $POSTGRES_USER"
echo "Password: $POSTGRES_PASSWORD"
```

### Prepare the environment file

```bash
cd docker
cp .env.example .env
```

Edit `docker/.env` with your deployment values. The Compose stack bundles a Caddy reverse proxy that handles TLS and same-origin routing, so only Caddy publishes host ports (80/443):

```bash
# --- CSAF Trusted Provider ---
SECURITYPORTAL_PROVIDER_URL=https://provider.example.com
SECURITYPORTAL_PUBLISHABLE_TLP=WHITE,UNLABELED
SECURITYPORTAL_POLL_INTERVAL=15m

# --- API ---
# Internal listen address (inside the container). Leave as :8081.
SECURITYPORTAL_LISTEN=:8081
# Cross-origin CORS: leave empty for same-origin via Caddy (ADR-0011).
# Only set if the web frontend runs separately (cross-origin API call).
SECURITYPORTAL_CORS_ORIGINS=
SECURITYPORTAL_QUERY_TIMEOUT=5s

# --- Database ---
POSTGRES_USER=securityportal
POSTGRES_PASSWORD=YOUR_GENERATED_PASSWORD_HERE
POSTGRES_DB=securityportal
SECURITYPORTAL_DATABASE_DSN=postgres://securityportal:YOUR_GENERATED_PASSWORD_HERE@db:5432/securityportal?sslmode=disable

# --- Caddy reverse proxy (Phase 7) ---
# Public hostname for the site. "localhost" = self-signed TLS (default).
# Set to a real FQDN for ACME/Let's Encrypt (and set SP_ACME_EMAIL below).
SP_SITE_ADDRESS=localhost

# ACME email (uncomment for Let's Encrypt MODE 2; leave commented for self-signed MODE 1).
# SP_ACME_EMAIL=ops@example.com

# Rate limiting (requests per sliding window per IP; requires custom Caddy image).
SP_RATE_LIMIT_REQUESTS=60
SP_RATE_LIMIT_WINDOW=1m
```

For more details on TLS modes and rate limiting, see `docker/caddy/Caddyfile` and the API README.

**IMPORTANT:** Do NOT commit `.env` to git. Add it to `.gitignore` (already in place).

### Validate the environment

```bash
cd /opt/securityportal/docker

# Check the compose file syntax and env variable substitution
docker compose config

# Should print the resolved services (db, api, web) with all env values filled in
```

### Branding (optional, Phase 7)

To customize the portal's appearance without rebuilding the container:

**Brand name and subtitle** — add to `.env`:
```bash
SECURITYPORTAL_BRAND_NAME="Your Organization PSIRT"
SECURITYPORTAL_BRAND_SUBTITLE="Security Advisory Portal"
```

**Primary color** — hex or RGB decimal (e.g., `#b91c1c` or `185 28 28`):
```bash
SECURITYPORTAL_THEME_PRIMARY="#b91c1c"
# or
SECURITYPORTAL_THEME_PRIMARY="185 28 28"
```

**Logo** — place an SVG, PNG, or WebP file on the host, then bind-mount it and set the path:
```bash
# 1. Prepare the file (e.g., /opt/securityportal/branding/logo.png)
# 2. Add to docker-compose.override.yml or edit docker-compose.yml:
web:
  volumes:
    - /opt/securityportal/branding/logo.png:/config/logo.png:ro
  environment:
    SECURITYPORTAL_LOGO_PATH: /config/logo.png
```

**Legal pages (Markdown)** — place `impressum.de.md`, `impressum.en.md`, `datenschutz.de.md`, `datenschutz.en.md` in a directory on the host, bind-mount it, and set the path. Each file supports Markdown (headings, lists, tables, safe links). Content is sanitized at render time (no inline HTML, no scripts). When files are missing the portal shows placeholders (required for German compliance):

```bash
# 1. Create the directory structure:
/opt/securityportal/legal/
  ├── impressum.de.md       # German company/contact info
  ├── impressum.en.md       # English imprint
  ├── datenschutz.de.md     # German privacy policy
  └── datenschutz.en.md     # English privacy policy

# 2. Add to docker-compose.override.yml:
web:
  volumes:
    - /opt/securityportal/legal:/config/legal:ro
  environment:
    SECURITYPORTAL_LEGAL_DIR: /config/legal
```

See the web README (§Configuration, "Legal content") for the full Markdown + sanitization reference.

## Step 2: First-time setup

### Build the images

```bash
cd /opt/securityportal/docker

# Build the API and web images (db is pre-built from library/postgres)
docker compose build

# If building on a slow connection, use --progress=plain for more output
docker compose build --progress=plain
```

### Start the stack for initialization

```bash
docker compose up -d

# Watch the logs for any startup errors
docker compose logs -f db api web

# Wait for postgres to be healthy (look for "pg_isready accepting connections")
# and the API/web to log startup messages
```

### Verify the database schema

```bash
# Once the API is running, check that migrations have applied
docker compose exec db psql -U securityportal -d securityportal -c "SELECT * FROM versions;"

# Should show:
#  version | description
# ---------+----------
#        0 | setup
#        1 | ingest-state-and-tombstone
#        2 | facets-and-fts
```

### Run an initial ingest cycle

```bash
# Trigger the API to fetch advisories from the provider once
docker compose exec api securityportal-api ingest

# Check the logs for success
docker compose logs api | tail -20

# You should see log lines like:
#   stored=42 duplicate=0 skipped_tlp=5 withdrawn=0
```

### Verify the API is responding

```bash
curl http://localhost:8081/api/health
# Should return:
# {"status":"ok","database":"reachable","last_ingest":"2026-06-08T15:00:00Z","version":"v0.0.0"}

curl http://localhost:8080/
# Should return HTML (the web home page)
```

## Step 3: Bundled Caddy reverse proxy

The Docker Compose stack includes Caddy, which handles TLS and same-origin routing. It publishes ports 80 and 443; the API and web services are internal-only (SA-21). Caddy is already configured via `docker/caddy/Caddyfile` with:

- **TLS:** MODE 1 (self-signed, default) → `{$SP_SITE_ADDRESS:localhost}` with local cert. Set `SP_SITE_ADDRESS` to a real FQDN and `SP_ACME_EMAIL` to enable MODE 2 (ACME/Let's Encrypt). For MODE 3 (bring-your-own cert), see `docker/caddy/Caddyfile.byo`.
- **Routing:** `/api/*` → api:8081, `/*` → web:8080 (same-origin, no CORS needed).
- **HSTS:** `max-age=31536000; includeSubDomains` set by Caddy (proxy responsibility per ADR-0011).
- **Rate limiting:** default 60 requests per 1m per IP (requires custom Caddy image built with `caddy-ratelimit`).

**To customize:**
- Edit `.env` to change `SP_SITE_ADDRESS`, `SP_ACME_EMAIL`, `SP_RATE_LIMIT_REQUESTS`, `SP_RATE_LIMIT_WINDOW`.
- Restart the stack: `docker compose down && docker compose up -d`.

### Optional: External reverse proxy

If you prefer to run an external reverse proxy (nginx, Apache, another Caddy instance) in front of the stack, you can disable the bundled Caddy and expose the web/api services directly:

**Edit docker/docker-compose.override.yml:**
```yaml
services:
  caddy:
    profiles: [disabled]  # Skip bundled Caddy
  web:
    ports:
      - "8080:8080"       # Expose web to host
  api:
    ports:
      - "8081:8081"       # Expose API to host
```

Then configure your external proxy to route `/api/*` to `localhost:8081` and `/*` to `localhost:8080`. Examples:

### Example external nginx configuration

```nginx
# /etc/nginx/sites-available/securityportal

upstream securityportal_api {
  server 127.0.0.1:8081;
}

upstream securityportal_web {
  server 127.0.0.1:8080;
}

# Rate limiting zones
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=web_limit:10m rate=30r/s;

server {
  listen 80;
  server_name portal.example.com;

  # Redirect HTTP to HTTPS
  return 301 https://$server_name$request_uri;
}

server {
  listen 443 ssl http2;
  server_name portal.example.com;

  # TLS configuration (use certbot / Let's Encrypt, or your CA)
  ssl_certificate /etc/letsencrypt/live/portal.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/portal.example.com/privkey.pem;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers HIGH:!aNULL:!MD5;
  ssl_prefer_server_ciphers on;

  # HSTS (strict-transport-security)
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

  # Rate limiting
  limit_req zone=api_limit burst=20 nodelay;
  limit_req zone=web_limit burst=50 nodelay;

  # API proxy
  location /api/ {
    proxy_pass http://securityportal_api/api/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_read_timeout 10s;
  }

  # Web proxy (everything else)
  location / {
    proxy_pass http://securityportal_web/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
  }
}
```

### Example Caddy configuration

```
portal.example.com {
  encode gzip

  # Rate limiting on the API
  handle /api/* {
    rate_limit {
      zone api
      key {remote_host}
      rate 10/s
    }
    reverse_proxy localhost:8081
  }

  # Everything else to the web server
  reverse_proxy localhost:8080
}
```

After configuring your reverse proxy, reload it:

```bash
# Nginx
sudo systemctl reload nginx

# Caddy
sudo caddy reload
```

Test the proxy:

```bash
# From your browser or a remote machine
curl https://portal.example.com/api/health
curl https://portal.example.com/

# Check headers
curl -I https://portal.example.com/api/health
# Should show Strict-Transport-Security, X-Content-Type-Options, etc.
```

## Step 4: Ongoing operations

### Monitor the stack

```bash
# View real-time logs
docker compose logs -f api web db

# Check individual container status
docker compose ps

# If a container exits unexpectedly
docker compose up -d
```

### Backup the database

PostgreSQL data is stored in the `db-data` volume. Automate daily backups:

```bash
#!/bin/bash
# /opt/securityportal/backup-db.sh

DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR=/backups/securityportal
mkdir -p $BACKUP_DIR

# Dump the entire database
docker compose exec -T db pg_dump \
  -U securityportal \
  -d securityportal \
  -F custom \
  -f /tmp/securityportal-$DATE.dump

# Copy dump from container to host
docker compose cp db:/tmp/securityportal-$DATE.dump $BACKUP_DIR/

# Keep only the last 30 days of backups
find $BACKUP_DIR -name "securityportal-*.dump" -mtime +30 -delete

echo "Backup completed: $BACKUP_DIR/securityportal-$DATE.dump"
```

Add to crontab:

```bash
crontab -e
# 0 2 * * * /opt/securityportal/backup-db.sh
```

### Update to a new release

```bash
cd /opt/securityportal

# Pull the latest code
git pull origin main

# Rebuild the images
cd docker
docker compose build

# Apply any new migrations and restart
docker compose up -d
docker compose logs api  # Wait for migrations to complete
```

### Scale the API (optional)

If one API container is not enough, create a replica:

```bash
# Edit docker/docker-compose.yml, uncomment or add:
services:
  api2:
    container_name: securityportal-api-2
    build:
      context: ..
      dockerfile: ./docker/api/Dockerfile
    networks:
      - securityportal
    environment:
      # Same as api service
      SECURITYPORTAL_PROVIDER_URL: ${SECURITYPORTAL_PROVIDER_URL}
      ...
    ports:
      - "${API_PORT_2}:8081"  # Different port
    depends_on:
      db:
        condition: service_healthy

# Then update nginx to upstream both:
# upstream securityportal_api {
#   server 127.0.0.1:8081;
#   server 127.0.0.1:8082;  # api2's port
# }
```

Both containers connect to the same Postgres instance; ingestion is idempotent (re-storing the same advisory is a no-op).

## Step 5: Pre-launch checklist

Before going public with the portal:

- [ ] **Test ingest:** confirmed that `POST /api/health` works and shows a recent `last_ingest` timestamp. If ingest is stalled, check logs: `docker compose logs api | grep -i ingest`.
- [ ] **Test search/list:** `GET /api/advisories?limit=10` returns advisories. Try filtering by `tlp=WHITE`.
- [ ] **Test document fetch:** `GET /api/documents/1` returns valid CSAF JSON. Try a non-existent ID: expect 404.
- [ ] **Test detail page:** click an advisory on the web frontend (`/`); it should render correctly with the webview.
- [ ] **Legal pages complete:** `/impressum` and `/datenschutz` are filled with real company / privacy information (not placeholders). Germany (and many EU countries) require these.
- [ ] **Branding customized:** logo, colors, footer links are correct (if applicable).
- [ ] **Backups running:** confirm `backup-db.sh` is in crontab and has run at least once.
- [ ] **Monitoring configured:** logs are forwarded to your observability tool (Sentry, ELK, Datadog, etc.).
- [ ] **SSL/TLS working:** visit `https://portal.example.com` in a browser; check the lock icon and certificate details. HSTS header should be present.
- [ ] **Rate limiting in place:** confirm your reverse proxy is rate-limiting `/api/` endpoints to prevent abuse.
- [ ] **Test provider URL:** confirm the configured `SECURITYPORTAL_PROVIDER_URL` is reachable and serving valid ROLIE feeds (check logs of a test ingest cycle).

## Troubleshooting

### API won't start: "database connection refused"

```bash
# Check if postgres is running and healthy
docker compose ps | grep db

# If not healthy, check logs
docker compose logs db

# Common fix: postgres container exited; restart everything
docker compose down
docker compose up -d
docker compose logs db  # Wait for pg_isready
```

### Ingest loop is stuck or not running

```bash
# Check if the API container is running
docker compose ps api

# Inspect logs for the last poll
docker compose logs api | tail -50 | grep -E 'ingestion|poll|error'

# If the provider URL is wrong or unreachable, you'll see network errors
# Edit .env and restart
docker compose down
docker compose up -d
```

### TLP filtering not working (RED/GREEN advisories appearing)

```bash
# Confirm the config
docker compose exec api env | grep PUBLISHABLE

# If wrong, edit .env and restart
docker compose down
docker compose up -d

# Then run a fresh ingest
docker compose exec api securityportal-api ingest
```

### Database query timeout errors (5s exceeded)

```bash
# Increase the timeout in .env
SECURITYPORTAL_QUERY_TIMEOUT=10s

# Restart
docker compose down
docker compose up -d

# Or lower the timeout if you're confident the query pattern is efficient
```

### Out of disk space (Docker volumes)

```bash
# Check size of the db-data volume
docker volume inspect securityportal-db-data | grep Mountpoint
du -sh /var/lib/docker/volumes/securityportal-db-data/_data

# If too large, back up and prune
docker compose down
docker volume rm securityportal-db-data

# Restore from backup or re-ingest
```

## Security reminders

1. **Never commit `.env`** with real secrets to git. Use environment files managed outside the repo.
2. **Reverse proxy owns TLS.** The Docker Compose stack assumes `http://` to the proxy and `https://` from the proxy to clients.
3. **Database is not exposed.** Postgres binds on the private Docker network (not to the host's network interface). No direct access from outside.
4. **Rate limit aggressively.** Set your reverse proxy to limit `/api/advisories` to ~10 req/s per IP to prevent Postgres DoS.
5. **Monitor ingestion.** If the poll loop stops, the portal becomes stale. Set up alerts.
6. **Backup regularly.** If the Postgres volume is lost, all advisory data is gone.

## Further reading

- **Threat model:** `.ai/shared/threat-model.md` — detailed security analysis
- **API README:** `securityportal-api/README.md` — endpoint reference and config details
- **Web README:** `securityportal-web/README.md` — UI configuration and locale setup
- **Decisions (ADRs):** `.ai/shared/decisions/` — architecture and security decisions

---

**Generated:** 2026-06-08  
**Maintainer:** SecurityPortal team
