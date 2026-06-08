<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Tommy Lehmann
-->

# SecurityPortal Bare-Metal Deployment Guide

This guide covers hand-rolled deployment of SecurityPortal without Docker Compose: building the services from source, running them under systemd, and connecting them to a Postgres database and your own reverse proxy.

For a batteries-included Docker Compose deployment, see [`DEPLOYMENT.md`](DEPLOYMENT.md).  
For Kubernetes Helm deployment, see the chart at `deploy/helm/securityportal` in the main repository.

## When to use bare-metal

- You operate your own Linux servers and prefer systemd service management.
- You already run Postgres and a reverse proxy (nginx, Caddy, Apache) elsewhere.
- You want to integrate the components with existing monitoring and log aggregation.
- You need tighter control over resource allocation and process supervision.

## Architecture overview

```
┌──────────────────────────────────────────┐
│   Your Reverse Proxy / TLS Handler        │
│  (nginx, Caddy, Apache — operator-run)   │
│  - HTTPS termination (TLS/HSTS)           │
│  - Rate limiting                          │
│  - Request logging / WAF                  │
│  - Security headers: HSTS only            │
└──────────────┬───────────────────────────┘
               │ HTTP
               ├─ /api → localhost:8081 (api service)
               └─ / → localhost:8080 (web service)

   Linux systemd services:
   ├─ securityportal-api (Go binary)
   │  - ingestion poller + HTTP API
   │  - reads PostgreSQL
   │  - env: /etc/securityportal/api.env
   │
   └─ securityportal-web (Node.js adapter-node)
      - SvelteKit frontend
      - talks to /api (internal URL)
      - env: /etc/securityportal/web.env

   External databases:
   └─ PostgreSQL 16+ (operator-managed)
```

**Security ownership:**
- **Reverse proxy** owns TLS/HTTPS, HSTS header, rate limiting.
- **Application** owns CSP, response security headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy).
- **Database** is not exposed to the network; only the systemd services connect via PostgreSQL protocol.

## Prerequisites

- **Linux host** (Ubuntu 22.04 LTS, Rocky Linux 9, Debian 12, or equivalent) with systemd.
- **Go toolchain** ≥ 1.26.4 installed at `/usr/local/go/bin/go` (or on `$PATH`).
- **Node.js** ≥ 20.x and npm ≥ 10.x.
- **PostgreSQL** ≥ 16 (external, not on this host; or installed locally and externally accessible).
- **Reverse proxy** already running (nginx/Caddy/Apache on this host or nearby).
- **CSAF Trusted Provider URL** (you operate this; e.g., `https://provider.example.com/.well-known/csaf/provider-metadata.json`).
- Root or sudo access to manage systemd services and `/etc/securityportal/`.

## Step 1: Prepare the source and build artifacts

### Clone the repository

```bash
mkdir -p /opt/securityportal
cd /opt/securityportal
git clone <repo-url> .
```

### Build the API binary

```bash
cd /opt/securityportal/securityportal-api

# Ensure Go is on PATH
export PATH=/usr/local/go/bin:$PATH
go version  # Verify ≥ 1.26.4

# Download dependencies
go mod download

# Build the binary (cross-compile if needed)
# For the local host:
go build -o securityportal-api ./cmd/securityportal-api

# For a different architecture (example: linux/amd64 from linux/arm64):
# GOOS=linux GOARCH=amd64 go build -o securityportal-api ./cmd/securityportal-api

# Optionally, embed a version at build time:
# go build -ldflags="-X main.version=v1.0.0" -o securityportal-api ./cmd/securityportal-api

# Verify the binary
./securityportal-api --help 2>&1 | head -5
# Should print usage without error
```

### Build the web bundle

```bash
cd /opt/securityportal/securityportal-web

npm ci              # Install dependencies (reproducible; uses package-lock.json)
npm run build       # Build SvelteKit with adapter-node

# Verify the build directory is present and contains build/index.js
test -f build/index.js && echo "Web build OK"

# The build/ directory (incl. build/index.js, build/client/, build/server/) is what we'll run
```

### Copy binaries to systemd-accessible locations

```bash
# API binary
sudo mkdir -p /usr/local/bin
sudo cp /opt/securityportal/securityportal-api/securityportal-api /usr/local/bin/
sudo chmod 0755 /usr/local/bin/securityportal-api
securityportal-api --help 2>&1 | head -1  # Verify it's on PATH

# Web bundle to a service directory
sudo mkdir -p /srv/securityportal-web
sudo cp -r /opt/securityportal/securityportal-web/build /srv/securityportal-web/
sudo cp /opt/securityportal/securityportal-web/package.json /srv/securityportal-web/
sudo cp /opt/securityportal/securityportal-web/package-lock.json /srv/securityportal-web/

# Install production dependencies in the service directory
cd /srv/securityportal-web
sudo npm ci --omit=dev

sudo chmod -R 0755 /srv/securityportal-web/build
sudo chmod 0644 /srv/securityportal-web/package*.json
```

## Step 2: Set up PostgreSQL and run migrations

### Create database and user

```bash
# On your PostgreSQL host (example: localhost:5432)
# Run as a superuser (psql -U postgres, or via your cloud provider's SQL console)

CREATE USER securityportal WITH PASSWORD 'your_secure_password_here';
CREATE DATABASE securityportal OWNER securityportal;

-- Ensure the user can connect from the API host
-- (For example, if the API runs on 192.0.2.50, add a pg_hba.conf entry
-- or a security group rule allowing host 192.0.2.50 to connect)
```

### Create the configuration for migrations

```bash
# Create the config directory
sudo mkdir -p /etc/securityportal
sudo chmod 0750 /etc/securityportal

# Create a temporary env file with just the database DSN (needed for migrations)
sudo tee /etc/securityportal/api.env > /dev/null <<'EOF'
# Postgres connection string
SECURITYPORTAL_DATABASE_DSN=postgres://securityportal:your_secure_password_here@postgres.example.com:5432/securityportal?sslmode=require

# API binding
SECURITYPORTAL_LISTEN=:8081

# Ingestion configuration (fill in your provider)
SECURITYPORTAL_PROVIDER_URL=https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json
SECURITYPORTAL_PUBLISHABLE_TLP=WHITE,UNLABELED
SECURITYPORTAL_POLL_INTERVAL=6h

# Query timeout (protects against DoS)
SECURITYPORTAL_QUERY_TIMEOUT=5s

# CORS (leave empty; same-origin behind reverse proxy)
SECURITYPORTAL_CORS_ORIGINS=

# Web-specific env
SECURITYPORTAL_API_INTERNAL_URL=http://localhost:8081
EOF

sudo chmod 0640 /etc/securityportal/api.env
```

### Run migrations

```bash
# Load the env and run migrate
sudo -E bash -c 'source /etc/securityportal/api.env && securityportal-api migrate'

# Expected output:
#   securityportal-api | Running migration version=0 name=setup
#   securityportal-api | Migrations applied successfully
```

Verify the schema was created:

```bash
# Connect to your Postgres instance and check
psql -U securityportal -d securityportal -h postgres.example.com -c "SELECT * FROM versions;"

# Should show:
#  version | description
# ---------+----------
#        0 | setup
```

## Step 3: Configure runtime environment files

### API environment file

```bash
sudo tee /etc/securityportal/api.env > /dev/null <<'EOF'
# ============================================================================
# SecurityPortal API environment (systemd EnvironmentFile)
# ============================================================================

# --- PostgreSQL connection (required) ---
# DSN format: postgres://user:password@host:port/database?sslmode=...
# sslmode: require (prod), disable (test). Never store this in code.
SECURITYPORTAL_DATABASE_DSN=postgres://securityportal:your_secure_password_here@postgres.example.com:5432/securityportal?sslmode=require

# --- CSAF Provider (required for ingestion) ---
SECURITYPORTAL_PROVIDER_URL=https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json

# Publishable TLP labels (comma-separated). Default: WHITE,UNLABELED
# Use only WHITE,UNLABELED for public portals.
# GREEN for additional internal distribution is excluded by default (confirm per deployment).
SECURITYPORTAL_PUBLISHABLE_TLP=WHITE,UNLABELED

# Polling interval (Go duration). Adjust for your provider's update frequency.
# For BSI WID (large corpus): 6h is reasonable.
# For smaller providers: 1h or 30m.
SECURITYPORTAL_POLL_INTERVAL=6h

# --- HTTP API binding ---
# Format: :PORT (all interfaces) or IP:PORT (specific interface)
SECURITYPORTAL_LISTEN=:8081

# --- Query timeout (protects against DoS) ---
# Per-query statement timeout. 5s is generous for well-indexed reads.
# Set to 0 to disable (not recommended for production).
SECURITYPORTAL_QUERY_TIMEOUT=5s

# --- CORS (optional) ---
# Leave empty for same-origin (recommended behind a reverse proxy).
# Set to https://portal.example.com if the frontend is cross-origin.
SECURITYPORTAL_CORS_ORIGINS=
EOF

sudo chmod 0640 /etc/securityportal/api.env
```

### Web environment file

```bash
sudo tee /etc/securityportal/web.env > /dev/null <<'EOF'
# ============================================================================
# SecurityPortal Web environment (systemd EnvironmentFile)
# ============================================================================

# Node.js adapter-node runtime
NODE_ENV=production
HOST=127.0.0.1
PORT=8080

# --- API connection (server-side only, never shipped to browser) ---
# Use the internal service URL (same host, no reverse proxy loop).
# If the API is on a different machine: http://api.example.com:8081
SECURITYPORTAL_API_INTERNAL_URL=http://localhost:8081

# --- Public API base URL (sent to browser, drives client-side fetch) ---
# Empty = same-origin relative (recommended; reverse proxy handles routing).
# Set to https://portal.example.com if the browser needs a full URL.
PUBLIC_API_BASE_URL=

# --- Branding (optional) ---
# These override the default SecurityPortal theme. Leave unset for defaults.
# SECURITYPORTAL_BRAND_NAME=My Organization
# SECURITYPORTAL_BRAND_SUBTITLE=CSAF Advisories
# SECURITYPORTAL_THEME_PRIMARY=51 122 183
# SECURITYPORTAL_THEME_PRIMARY_FG=255 255 255
# SECURITYPORTAL_THEME_ACCENT=230 126 34
# SECURITYPORTAL_LOGO_PATH=/srv/securityportal/logo.svg

# --- Legal documents (operator-provided Markdown) ---
# Directory containing impressum.<locale>.md and datenschutz.<locale>.md files.
# Required for compliance. See section "Legal content" below.
SECURITYPORTAL_LEGAL_DIR=/srv/securityportal/legal
EOF

sudo chmod 0640 /etc/securityportal/web.env
```

## Step 4: Set up legal documents and branding assets

### Legal markdown files

Create the legal directory and populate it with operator-authored content:

```bash
sudo mkdir -p /srv/securityportal/legal
sudo chmod 0755 /srv/securityportal/legal

# Each file must be named <page>.<locale>.md
# Supported pages: impressum, datenschutz (and optionally others)
# Supported locales: de, en

# Example (German)
sudo tee /srv/securityportal/legal/impressum.de.md > /dev/null <<'EOF'
# Impressum

Angaben gemäß §5 TMG:

**Verantwortlich:**
Ihre Organisation  
Straße 123  
12345 Stadt  
Deutschland

**Kontakt:**
E-Mail: legal@example.com
Telefon: +49 123 45678

**Vertreten durch:**
Name, Titel

...rest of impressum...
EOF

# Example (English)
sudo tee /srv/securityportal/legal/impressum.en.md > /dev/null <<'EOF'
# Legal Notice

Information in accordance with section 5 TMG:

**Responsible:**
Your Organization  
Street 123  
12345 City  
Germany

**Contact:**
Email: legal@example.com
Phone: +49 123 45678

...rest of legal notice...
EOF

# Data privacy (same pattern: datenschutz.de.md, datenschutz.en.md)
# sudo tee /srv/securityportal/legal/datenschutz.de.md > /dev/null <<'EOF'
# ...content...
# EOF

sudo chmod 0644 /srv/securityportal/legal/*.md
```

**File naming rules:**
- Name pattern: `<page>.<locale>.md` (e.g., `impressum.de.md`, `datenschutz.en.md`)
- Supported pages: `impressum`, `datenschutz` (and others for future locales)
- Supported locales: `de`, `en`
- Missing files fall back to other available locales or a placeholder.
- Files are sanitized (HTML allowed only for safe tags: `<a>`, `<p>`, `<h1>`–`<h6>`, `<strong>`, `<em>`, `<ul>`, `<ol>`, `<li>`, `<table>`, `<tr>`, `<th>`, `<td>`). `<script>`, `<iframe>`, `<img>` are stripped.

### Logo file (optional)

```bash
# Place a logo file (SVG preferred for scaling) at:
sudo cp /path/to/your/logo.svg /srv/securityportal/logo.svg
sudo chmod 0644 /srv/securityportal/logo.svg

# Update /etc/securityportal/web.env:
# SECURITYPORTAL_LOGO_PATH=/srv/securityportal/logo.svg
```

## Step 5: Create systemd service files

### API service

```bash
sudo tee /etc/systemd/system/securityportal-api.service > /dev/null <<'EOF'
[Unit]
Description=SecurityPortal API
Documentation=https://github.com/securityportal/securityportal-api
After=network.target postgresql.service
Wants=securityportal-web.service

[Service]
Type=simple
User=securityportal
Group=securityportal
WorkingDirectory=/srv/securityportal

# Load environment file
EnvironmentFile=/etc/securityportal/api.env

# The binary
ExecStart=/usr/local/bin/securityportal-api serve

# Restart on failure
Restart=on-failure
RestartSec=10s

# Resource limits
MemoryMax=512M
CPUQuota=75%

# Logging to systemd journal
StandardOutput=journal
StandardError=journal
SyslogIdentifier=securityportal-api

[Install]
WantedBy=multi-user.target
EOF

sudo chmod 0644 /etc/systemd/system/securityportal-api.service
```

### Web service

```bash
sudo tee /etc/systemd/system/securityportal-web.service > /dev/null <<'EOF'
[Unit]
Description=SecurityPortal Web Frontend
Documentation=https://github.com/securityportal/securityportal-web
After=network.target securityportal-api.service
Requires=securityportal-api.service

[Service]
Type=simple
User=securityportal
Group=securityportal
WorkingDirectory=/srv/securityportal-web

# Load environment file
EnvironmentFile=/etc/securityportal/web.env

# The Node.js runtime
ExecStart=/usr/bin/node build

# Restart on failure
Restart=on-failure
RestartSec=10s

# Resource limits
MemoryMax=256M
CPUQuota=50%

# Logging to systemd journal
StandardOutput=journal
StandardError=journal
SyslogIdentifier=securityportal-web

[Install]
WantedBy=multi-user.target
EOF

sudo chmod 0644 /etc/systemd/system/securityportal-web.service
```

### Create the service user

```bash
# Create a dedicated user for the services (if not present)
sudo useradd -r -s /bin/false -d /srv/securityportal securityportal 2>/dev/null || true

# Ensure directories are owned by the service user
sudo chown -R securityportal:securityportal /srv/securityportal /etc/securityportal
sudo chmod 0750 /etc/securityportal
sudo chmod 0640 /etc/securityportal/*.env
```

### Enable and start services

```bash
# Reload systemd daemon
sudo systemctl daemon-reload

# Enable services to start on boot
sudo systemctl enable securityportal-api.service
sudo systemctl enable securityportal-web.service

# Start the services
sudo systemctl start securityportal-api.service
sudo systemctl start securityportal-web.service

# Verify they're running
sudo systemctl status securityportal-api.service
sudo systemctl status securityportal-web.service

# Check logs
sudo journalctl -u securityportal-api.service -n 20
sudo journalctl -u securityportal-web.service -n 20
```

## Step 6: Configure the reverse proxy

The reverse proxy (nginx, Caddy, or Apache) is **operator-provided** and owns TLS/HTTPS and rate limiting. The application does NOT implement these; they are delegated to the proxy for security and operational clarity.

### nginx example

```nginx
# /etc/nginx/sites-available/securityportal

# Upstream definitions
upstream securityportal_api {
    server 127.0.0.1:8081;
}

upstream securityportal_web {
    server 127.0.0.1:8080;
}

# Rate limiting zones
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=web_limit:10m rate=30r/s;
limit_req_zone $binary_remote_addr zone=legal_limit:10m rate=5r/s;

# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name portal.example.com;

    return 301 https://$server_name$request_uri;
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name portal.example.com;

    # TLS certificates (managed by certbot, your CA, or similar)
    ssl_certificate /etc/letsencrypt/live/portal.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/portal.example.com/privkey.pem;

    # TLS hardening
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers on;
    ssl_session_timeout 1d;
    ssl_session_caching shared:SSL:50m;
    ssl_stapling on;
    ssl_stapling_verify on;

    # HSTS (strict-transport-security) — proxy owns this, not the app
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Logging
    access_log /var/log/nginx/portal-access.log combined;
    error_log /var/log/nginx/portal-error.log;

    # === API proxy ===
    location /api/ {
        # Rate limiting
        limit_req zone=api_limit burst=20 nodelay;

        proxy_pass http://securityportal_api/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 10s;
    }

    # === Legal pages (higher rate limit — lower traffic) ===
    location ~ ^/(impressum|datenschutz) {
        limit_req zone=legal_limit burst=5 nodelay;

        proxy_pass http://securityportal_web;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    # === Web frontend (everything else) ===
    location / {
        # Rate limiting
        limit_req zone=web_limit burst=50 nodelay;

        proxy_pass http://securityportal_web/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

After updating nginx configuration:

```bash
sudo nginx -t        # Verify syntax
sudo systemctl reload nginx
```

### Caddy example

```caddy
# /etc/caddy/Caddyfile

portal.example.com {
    # TLS is automatic (Let's Encrypt by default)
    # HSTS is set by Caddy automatically on HTTPS

    # Logging
    log {
        format json
        output file /var/log/caddy/portal.log
    }

    # Rate limiting
    @api_paths path /api/*
    handle @api_paths {
        rate_limit {
            zone api
            key {remote_host}
            rate 10/s
        }
        reverse_proxy localhost:8081
    }

    # Legal pages (stricter rate limit)
    @legal_paths path /impressum /datenschutz
    handle @legal_paths {
        rate_limit {
            zone legal
            key {remote_host}
            rate 5/s
        }
        reverse_proxy localhost:8080
    }

    # Web frontend (default, everything else)
    reverse_proxy localhost:8080

    # Enable compression
    encode gzip
}
```

After updating Caddy:

```bash
sudo caddy reload -c /etc/caddy/Caddyfile
```

## Step 7: Verify the deployment

### Health check

```bash
# Wait for services to stabilize (10–15 seconds)
sleep 15

# Health endpoint (through the reverse proxy)
curl https://portal.example.com/api/health

# Expected response (HTTPS, signed cert):
# {
#   "status": "ok",
#   "database": "reachable",
#   "last_ingest": "2026-06-08T15:00:00Z",
#   "version": "v0.0.0"
# }
```

### Test the API

```bash
# List advisories (with filtering)
curl 'https://portal.example.com/api/advisories?limit=5&tlp=WHITE'

# Get facets
curl 'https://portal.example.com/api/facets'

# Fetch a single advisory (once at least one has been ingested)
curl 'https://portal.example.com/api/documents/1'
```

### Test the web UI

```bash
# Open a browser and visit:
# https://portal.example.com/

# You should see:
# - The SecurityPortal home page (or custom branding if configured)
# - A language toggle (DE / EN)
# - A search sidebar with faceted filtering
# - An empty or populated list (depends on ingest status)
```

### Check logs

```bash
# API logs
sudo journalctl -u securityportal-api.service -f

# Web logs
sudo journalctl -u securityportal-web.service -f

# Nginx/Caddy logs (if applicable)
sudo tail -f /var/log/nginx/portal-access.log
# or
sudo tail -f /var/log/caddy/portal.log
```

## Step 8: Ongoing operations

### Monitor ingestion

```bash
# Check the last ingest result
curl 'https://portal.example.com/api/health' | jq '.last_ingest'

# If `last_ingest` is older than your poll interval, the ingestion loop may be stuck.
# Check logs:
sudo journalctl -u securityportal-api.service --since "1 hour ago" | grep -i ingest
```

### Restart services

```bash
# Gracefully restart the API (drains in-flight requests)
sudo systemctl restart securityportal-api.service

# Restart the web service
sudo systemctl restart securityportal-web.service

# Restart both
sudo systemctl restart securityportal-api.service securityportal-web.service
```

### Database backups

Automate PostgreSQL backups:

```bash
#!/bin/bash
# /usr/local/bin/backup-securityportal-db.sh

DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR=/backups/securityportal
mkdir -p "$BACKUP_DIR"

# Dump the database (as the connecting role, no superuser needed)
PGPASSWORD="your_password_here" pg_dump \
  -U securityportal \
  -h postgres.example.com \
  -d securityportal \
  -F custom \
  -f "$BACKUP_DIR/securityportal-$DATE.dump"

# Keep only the last 30 days
find "$BACKUP_DIR" -name "securityportal-*.dump" -mtime +30 -delete

echo "Backup completed: $BACKUP_DIR/securityportal-$DATE.dump"
```

Add to crontab (runs daily at 2:00 AM):

```bash
sudo bash -c 'echo "0 2 * * * /usr/local/bin/backup-securityportal-db.sh" | crontab -'
```

### Updates and rolling deployments

To update the services:

```bash
# 1. Pull new code
cd /opt/securityportal
git pull origin main

# 2. Rebuild the API
cd securityportal-api
go build -o securityportal-api ./cmd/securityportal-api
sudo cp securityportal-api /usr/local/bin/

# 3. Apply any new database migrations
sudo -E bash -c 'source /etc/securityportal/api.env && securityportal-api migrate'

# 4. Rebuild the web bundle
cd ../securityportal-web
npm ci
npm run build
sudo rm -rf /srv/securityportal-web/build
sudo cp -r build /srv/securityportal-web/

# 5. Restart services
sudo systemctl restart securityportal-api.service
sudo systemctl restart securityportal-web.service

# 6. Verify
sleep 5
curl https://portal.example.com/api/health
```

## Pre-launch checklist

Before going public with the portal:

- [ ] **Ingest working:** `GET /api/health` returns a recent `last_ingest` timestamp. If not, check logs: `journalctl -u securityportal-api.service | grep ingest`.
- [ ] **Provider URL reachable:** Verify the configured `SECURITYPORTAL_PROVIDER_URL` is accessible from the API host. Test: `curl https://provider.example.com/.well-known/csaf/provider-metadata.json`.
- [ ] **Database healthy:** Run `psql -U securityportal -h postgres.example.com -d securityportal -c "SELECT COUNT(*) FROM advisories;"`. Should return a number (possibly 0 if no ingest has run yet).
- [ ] **API responding:** `curl https://portal.example.com/api/advisories?limit=5` returns JSON (may be empty list on first run).
- [ ] **Web UI loads:** Visit `https://portal.example.com/` in a browser. You should see the SecurityPortal home page with a search sidebar.
- [ ] **Legal pages filled:** `/impressum` and `/datenschutz` display operator-authored content (not placeholders). **Required in Germany and most EU countries.**
- [ ] **Branding correct:** Logo, colors, brand name reflect your organization (if customized).
- [ ] **TLS certificate valid:** Browser shows a green lock; `openssl s_client -connect portal.example.com:443` shows a valid cert.
- [ ] **HSTS header present:** `curl -I https://portal.example.com/ | grep -i hsts` should show the header.
- [ ] **Rate limiting in place:** Verify your reverse proxy is rate-limiting (nginx logs or Caddy config).
- [ ] **Backups running:** Confirm `backup-securityportal-db.sh` has run at least once and the dump file exists at `/backups/securityportal/`.
- [ ] **Monitoring configured:** Logs are forwarded to your observability tool (ELK, Sentry, Datadog, etc.), or you have a plan to tail `journalctl` regularly.
- [ ] **TLP filtering verified:** Check that only `WHITE`/`UNLABELED` advisories are served. If you have `GREEN` docs in your provider, confirm they are NOT stored: `curl 'https://portal.example.com/api/advisories?tlp=GREEN'` should return no results.

## Troubleshooting

### Services won't start

```bash
# Check the service status and logs
sudo systemctl status securityportal-api.service
sudo journalctl -u securityportal-api.service -n 50

# Common issues:
# - Port 8081 already in use: netstat -tlnp | grep 8081
# - Environment file not found: verify /etc/securityportal/api.env exists and is readable
# - Binary not found: verify /usr/local/bin/securityportal-api exists and is executable
```

### Database connection fails

```bash
# Test the connection from the API host:
PGPASSWORD="password" psql -U securityportal -h postgres.example.com -d securityportal -c "SELECT 1"

# If it fails:
# - Check if the Postgres host is reachable: ping postgres.example.com
# - Verify the password and user name in the DSN
# - Check firewall rules (port 5432 open from API host to Postgres host)
# - Check PostgreSQL pg_hba.conf for connection method (md5/scram-sha-256)
```

### Ingest loop stuck / no new advisories

```bash
# Check logs
sudo journalctl -u securityportal-api.service --since "1 hour ago" | grep -i ingest

# Manually trigger an ingest (one-shot):
sudo -E bash -c 'source /etc/securityportal/api.env && securityportal-api ingest'

# Common issues:
# - Provider URL unreachable or down: test curl https://provider.example.com/
# - Invalid TLP label in SECURITYPORTAL_PUBLISHABLE_TLP: must be WHITE, UNLABELED, etc.
# - Network timeouts: check firewall, DNS resolution, https certificate validation
```

### API returning 5xx errors

```bash
# Check logs for exceptions
sudo journalctl -u securityportal-api.service -n 100

# Likely causes:
# - Database connection lost: verify DSN and Postgres health
# - Query timeout: increase SECURITYPORTAL_QUERY_TIMEOUT in api.env and restart
# - Memory pressure: check available RAM, increase MemoryMax in the systemd unit
```

### TLS certificate errors

```bash
# Verify the cert on the reverse proxy host
openssl s_client -connect localhost:443 -servername portal.example.com < /dev/null | openssl x509 -text -noout

# Check cert expiration
openssl x509 -in /path/to/cert.pem -noout -enddate

# For Let's Encrypt (certbot), renew manually:
sudo certbot renew --force-renewal

# Restart the reverse proxy
sudo systemctl reload nginx  # or caddy, apache2, etc.
```

### Rate limiting too aggressive

```bash
# Adjust the limits in your reverse proxy config:
# For nginx: increase rate in limit_req_zone
# For Caddy: increase rate in rate_limit directive

# Restart the proxy:
sudo systemctl reload nginx
# or
sudo caddy reload
```

## Security notes

1. **Never commit `.env` files or passwords to git.** Use `/etc/securityportal/*.env` managed outside the repo.
2. **Reverse proxy owns TLS.** The application binds on `http://localhost:8081` and `http://localhost:8080` (plain HTTP internally). Only the reverse proxy exposes HTTPS to the public.
3. **Database is not exposed.** Postgres is on an internal network or password-protected; no direct access from the public internet.
4. **Rate limit aggressively.** Set your reverse proxy to limit `/api/advisories` to ~10 req/s per IP and `/` to ~30 req/s to prevent DoS and excessive database load.
5. **Monitor ingestion health.** Set up alerts if `last_ingest` becomes stale (older than 2× your poll interval).
6. **Back up regularly.** Automate `pg_dump` and test restores at least monthly.
7. **Keep legal pages current.** Update `/srv/securityportal/legal/*.md` when your company details or privacy policy change.
8. **Log aggregation.** Forward systemd journal entries to a central log service (ELK, Syslog, Cloud Logs) for auditing and debugging.

## Further reading

- **API reference:** `securityportal-api/README.md` — endpoint details, config, development.
- **Web UI documentation:** `securityportal-web/README.md` — frontend architecture, i18n, testing.
- **Docker Compose deployment:** `securityportal-api/docs/DEPLOYMENT.md` — batteries-included setup.
- **Kubernetes Helm chart:** `deploy/helm/securityportal/` — cloud-native deployment.
- **Threat model & decisions:** `.ai/shared/threat-model.md`, `.ai/shared/decisions/` — security analysis and ADRs.

---

**Maintainer:** SecurityPortal team  
**Updated:** 2026-06-08
