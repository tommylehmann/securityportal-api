<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Tommy Lehmann
-->

# SecurityPortal Deployment Guide

This document covers deploying the complete SecurityPortal stack (API + web frontend + Postgres database) to production.

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

Edit `docker/.env` with your deployment values:

```bash
# --- CSAF Trusted Provider ---
SECURITYPORTAL_PROVIDER_URL=https://provider.example.com
SECURITYPORTAL_PUBLISHABLE_TLP=WHITE,UNLABELED
SECURITYPORTAL_POLL_INTERVAL=15m

# --- API ---
SECURITYPORTAL_LISTEN=:8081
SECURITYPORTAL_CORS_ORIGINS=
# ^ Leave empty if your reverse proxy handles same-origin requests
# ^ Set to https://portal.example.com if the frontend is separate/cross-origin

SECURITYPORTAL_QUERY_TIMEOUT=5s

# --- Database ---
POSTGRES_USER=securityportal
POSTGRES_PASSWORD=YOUR_GENERATED_PASSWORD_HERE
POSTGRES_DB=securityportal
SECURITYPORTAL_DATABASE_DSN=postgres://securityportal:YOUR_GENERATED_PASSWORD_HERE@db:5432/securityportal?sslmode=disable

# --- Ports (on the host, mapped from the containers) ---
API_PORT=8081
WEB_PORT=8080
```

**IMPORTANT:** Do NOT commit `.env` to git. Add it to `.gitignore` (already in place).

### Validate the environment

```bash
cd /opt/securityportal/docker

# Check the compose file syntax and env variable substitution
docker compose config

# Should print the resolved services (db, api, web) with all env values filled in
```

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

## Step 3: Configure the reverse proxy

Your reverse proxy (nginx, Caddy, Apache) is responsible for:
1. Terminating TLS (HTTPS)
2. Proxying `/api/*` to `http://localhost:8081/`
3. Proxying `/` to `http://localhost:8080/`
4. Setting security headers (if not already set by the application)
5. Rate limiting (e.g., per-IP limits on `/api/advisories`)

### Example nginx configuration

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
