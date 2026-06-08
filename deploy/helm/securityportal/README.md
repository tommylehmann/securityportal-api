<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Tommy Lehmann
-->

# SecurityPortal Helm chart

Deploys the SecurityPortal CSAF advisory portal to Kubernetes:

- **securityportal-api** — Go HTTP API + CSAF ingestion poller (port 8081)
- **securityportal-web** — SvelteKit public UI, adapter-node (port 8080)
- A single **Ingress** routing `/api/*` to the api and `/` to the web
- Optional bundled **PostgreSQL** (Bitnami subchart, dev only)
- A pre-install/pre-upgrade **migration Job**

This is one of three first-class deployment targets described in ADR-0012.
The Docker Compose target lives in `docker/` and uses Caddy instead of an
Ingress.  The application code and runtime config contract are identical across
all three targets.

---

## Quick start (default values, no live cluster)

```
helm dependency update deploy/helm/securityportal
helm template my-portal deploy/helm/securityportal
```

The default values render a complete, valid manifest set with placeholder
credentials.  No live cluster is needed to inspect the output.

---

## Production install

```bash
# 1. Create the namespace.
kubectl create namespace securityportal

# 2. Create the database DSN Secret (recommended: manage outside Helm).
kubectl -n securityportal create secret generic my-db-secret \
  --from-literal=dsn='postgres://user:password@db-host:5432/securityportal?sslmode=require'

# 3. Install the chart.
helm upgrade --install my-portal deploy/helm/securityportal \
  --namespace securityportal \
  --set externalDatabase.existingSecret=my-db-secret \
  --set postgresql.enabled=false \
  --set ingress.host=portal.example.com \
  --set ingress.tls.enabled=true \
  --set ingress.tls.secretName=portal-tls \
  --set provider.url=https://provider.example.com
```

---

## Key design decisions

### Ingress — same-origin routing (ADR-0011 / ADR-0012)

The Ingress is the single public entry point (SA-21 k8s analog).  Both
Services are `ClusterIP`; no `NodePort` or `LoadBalancer` is ever created.
The routing uses `pathType: Prefix` (controller-agnostic) and mirrors the
Caddy deployment:

```
/api  →  api Service :8081   (longest-prefix wins; /api/health reaches api)
/     →  web Service :8080
```

nginx selects the longest matching prefix, so `/api/...` routes to the api
before the catch-all `/` rule — no regex annotation needed.

The web app's SSR `load` functions reach the api directly via
`SECURITYPORTAL_API_INTERNAL_URL=http://<release>-api:8081` (cluster-internal
DNS), bypassing the Ingress for server-side fetches.

### TLS + HSTS — owned by the Ingress controller (ADR-0011)

The Ingress controller (e.g. nginx-ingress) handles TLS termination.  HSTS is
the controller's responsibility, not the application's.  nginx-ingress enables
HSTS by default; customise via `ingress.annotations`.

The application owns CSP + per-response security headers (ADR-0006).  Do NOT
add nginx `ConfigurationSnippets` that re-emit `Content-Security-Policy`,
`X-Frame-Options`, `Referrer-Policy`, or `Permissions-Policy` — that would
duplicate or override the app's values.

### Secrets vs ConfigMap (SA-13 / ADR-0012)

| What | Where |
|---|---|
| Database DSN | Kubernetes `Secret` |
| Logo image | Kubernetes `Secret` |
| Provider URL, TLP policy, branding, paths | `ConfigMap` |

The DSN is consumed via `secretKeyRef`; it is never placed in a `ConfigMap` or
logged verbatim.

### Database

| Option | When to use |
|---|---|
| `postgresql.enabled=true` | Dev / demo — Bitnami subchart |
| `externalDatabase.existingSecret` | Production — pre-create the Secret |
| `externalDatabase.dsn` | Production — let Helm generate the Secret |

External PostgreSQL is strongly recommended for production (HA, backups,
connection pooling).

### Migrations — hook Job (external DB) or initContainer (bundled DB)

The approach depends on the database mode:

**External database (`postgresql.enabled=false`, recommended for production):**
A `batch/v1 Job` runs `securityportal-api migrate` as a `pre-install,pre-upgrade`
hook before the Deployments are updated.  The external database (and its Secret)
is pre-existing, so the Job can connect immediately.  It runs exactly once per
Helm operation and its outcome is surfaced in `helm status`.

**Bundled Bitnami PostgreSQL (`postgresql.enabled=true`, dev/demo only):**
Migration runs in an **initContainer** on the api Deployment instead.  A
pre-install hook would fail here because it runs before Helm creates any
non-hook resources — including the bundled PostgreSQL StatefulSet and its
Secret.  The initContainer runs after the pod env is resolved and blocks the
api container from starting until `securityportal-api migrate` succeeds.  The
`migrate` command has built-in retry with exponential backoff (up to 5 min)
so it waits for the bundled PostgreSQL pod to accept connections.

`securityportal-api migrate` is idempotent (forward-only, no-op when the
schema is already up to date), so the initContainer is safe to re-run on pod
restarts and rolling updates.

### Legal content and logo mounts

The web app reads legal Markdown from `SECURITYPORTAL_LEGAL_DIR` and the logo
from `SECURITYPORTAL_LOGO_PATH` at request time.  These are mounted into the
web pod:

- **Legal files** — from a ConfigMap (generated from `legalContent.files.*`
  or referenced via `legalContent.existingConfigMap`).
- **Logo** — from a Secret (generated from `logo.data` or referenced via
  `logo.existingSecret`).  Logos are stored in a Secret because they may be
  proprietary assets.

When neither is configured the web app renders built-in placeholder text
(Impressum / Datenschutz), which is the correct OQ-4 default for deployments
that have not yet provided legal texts.

---

## values.yaml reference (key knobs)

| Key | Default | Description |
|---|---|---|
| `nameOverride` | `""` | Override the chart name component of resource names |
| `fullnameOverride` | `""` | Override the full release-prefixed resource name |
| `api.image.tag` | `0.1.0` | api image tag |
| `web.image.tag` | `0.1.0` | web image tag |
| `api.replicaCount` | `1` | api replicas |
| `web.replicaCount` | `1` | web replicas |
| `ingress.host` | `portal.example.com` | Public hostname |
| `ingress.tls.enabled` | `false` | Enable TLS on the Ingress |
| `ingress.tls.secretName` | `""` | TLS Secret name; defaults to `<fullname>-tls` when empty |
| `ingress.annotations` | `{}` | Ingress controller annotations |
| `provider.url` | `https://provider.example.com` | CSAF provider URL |
| `provider.publishableTLP` | `WHITE,UNLABELED` | Publishable TLP labels |
| `provider.pollInterval` | `15m` | Ingestion poll interval |
| `branding.name` | `""` | UI brand name override |
| `branding.themePrimary` | `""` | Primary color (`#rrggbb` or `R G B`) |
| `postgresql.enabled` | `false` | Bundle Bitnami PostgreSQL (dev only) |
| `externalDatabase.dsn` | `""` | DSN for generated Secret |
| `externalDatabase.existingSecret` | `""` | Pre-existing DSN Secret name |
| `legalContent.files.*` | `""` | Inline legal Markdown |
| `legalContent.existingConfigMap` | `""` | Operator-provided legal ConfigMap |
| `logo.data` | `""` | Base64 logo bytes |
| `logo.existingSecret` | `""` | Operator-provided logo Secret |
| `migration.enabled` | `true` | Run migration Job on install/upgrade |
