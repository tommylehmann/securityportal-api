<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Tommy Lehmann
-->

# Releasing securityportal-api

This document explains how versions work, how to cut and publish a release, how
to consume and verify the published artifacts, and how to re-enable everything
in a fork. The companion guide for the frontend lives in
`securityportal-web/RELEASING.md`.

## What gets published

A release is driven by **pushing a Git tag**. The
[`release.yml`](.github/workflows/release.yml) workflow then produces:

| Artifact | Where | Notes |
|---|---|---|
| Container image | `ghcr.io/<owner>/securityportal-api` | Primary artifact. Tags: `vX.Y.Z`, `X.Y`, `X`, `latest`, `sha-<commit>`. Consumed by `docker/docker-compose.yml` and the Helm chart. |
| Helm chart (OCI) | `oci://ghcr.io/<owner>/charts/securityportal` | Packaged from `deploy/helm/securityportal` at version `X.Y.Z` (tag with the leading `v` stripped). Installable with `helm install` — no `helm repo add` needed. |
| Build-provenance attestation | attached to the image in GHCR | SLSA provenance, keyless (OIDC). Proves which workflow/commit built the image. |
| SBOM attestation | attached to the image in GHCR | SPDX SBOM bound to the image digest. |
| GitHub Release | the repo's Releases page | `securityportal-api-<version>-linux-amd64.tar.gz` (versioned binary + README/LICENSE/CHANGELOG + SBOMs) plus standalone `*-sbom.spdx.json` and `*-sbom.cdx.json`. |

> The image targets `linux/amd64` (the compose/Helm deployment target). To also
> publish `linux/arm64`, see the commented `platforms:` note in `release.yml`
> (the Dockerfile must cross-compile via `$TARGETARCH` first).

## Versioning — Semantic Versioning, derived from Git

We follow [SemVer](https://semver.org/): `MAJOR.MINOR.PATCH`.

- **The Git tag is the source of truth.** Tag `v1.4.2` ⇒ image/binaries are
  version `v1.4.2`. The version is injected into the binary at build time via
  `-ldflags "-X main.version=…"` and logged on startup (`starting
  securityportal-api version=…`).
- **Untagged / local builds** derive a version from `git describe --tags
  --always --dirty` (e.g. `v1.4.2-3-gabc1234`), with the patch bumped so the dev
  build sorts *after* the tag it descends from. Run `make version` to see it.
- Bump **MAJOR** for breaking API/CLI/config changes, **MINOR** for backward-
  compatible features, **PATCH** for fixes.

## Cutting a release

1. Make sure `main`/`master` is green (the [`ci.yml`](.github/workflows/ci.yml)
   build/test gate and [`security.yml`](.github/workflows/security.yml) pass).
2. Update [`CHANGELOG.md`](CHANGELOG.md): move items from *Unreleased* into a new
   `## [X.Y.Z] - YYYY-MM-DD` section.
3. Commit and push that to the default branch.
4. Tag and push:

   ```sh
   git tag -a vX.Y.Z -m "securityportal-api vX.Y.Z"
   git push origin vX.Y.Z
   ```

5. Watch the **Release** workflow in the Actions tab. When it's green you have a
   GHCR image and a GitHub Release with assets + attestations.

### Dry run (no release)

Trigger **Release** manually (Actions → Release → *Run workflow*). It builds and
pushes an image tagged from `git describe` and records attestations, but does
**not** create a GitHub Release. Useful for validating the pipeline before the
first real tag.

### Build locally (parity check)

```sh
make version            # show the version that will be stamped in
make dist               # binary + CycloneDX SBOM + tarball under dist/
docker build -f docker/api/Dockerfile -t securityportal-api:dev \
  --build-arg BUILD_VERSION="$(make -s version | awk '{print $1}')" .
```

## Consuming & verifying a release

```sh
# Pull (pin to a digest in production):
docker pull ghcr.io/<owner>/securityportal-api:vX.Y.Z

# Verify build provenance and SBOM (needs gh >= 2.49):
gh attestation verify oci://ghcr.io/<owner>/securityportal-api:vX.Y.Z \
  --owner <owner>

# Install the Helm chart straight from GHCR (no `helm repo add`):
helm install my-portal oci://ghcr.io/<owner>/charts/securityportal \
  --version X.Y.Z -n securityportal -f my-values.yaml
```

SBOMs are also attached to each GitHub Release (`*-sbom.spdx.json`,
`*-sbom.cdx.json`) and uploaded as a CI artifact by `security.yml`.

## Supply-chain hygiene

- **Pinning.** Every third-party GitHub Action is pinned to a full commit SHA
  (the trailing `# vX.Y.Z` comment is human-readable only); the Docker base
  image is pinned by digest. This blocks "moved tag" attacks.
- **Staying current.** [`dependabot.yml`](.github/dependabot.yml) opens weekly
  PRs for Go modules, Actions, and the base-image digest. Turn on **Dependabot
  security updates** (repo *Settings → Code security*) so vulnerable deps get
  fast-tracked PRs. Review and merge these like any change — CI re-validates.
- **Monitoring.** [`supply-chain-monitor.yml`](.github/workflows/supply-chain-monitor.yml)
  runs weekly: Trivy scans the source tree and the latest published image,
  uploads results to **Security → Code scanning**, and opens/updates a single
  `supply-chain`-labelled issue on new HIGH/CRITICAL findings (auto-closed when
  clean). Run it on demand via *Run workflow*.
- **Re-pinning a base image by hand** (if you can't wait for Dependabot):

  ```sh
  docker buildx imagetools inspect library/golang:1.26.4-alpine \
    --format '{{.Manifest.Digest}}'
  ```

  then update the `@sha256:…` in `docker/api/Dockerfile`.

## Setting this up in a fork

The pipeline is written to need **no secrets** beyond the automatic
`GITHUB_TOKEN`, and it never hardcodes an owner — images publish to
`ghcr.io/<your-namespace>/…` automatically. After forking:

1. **Actions** → enable workflows in the fork (GitHub disables them on forks by
   default).
2. **Settings → Actions → General → Workflow permissions** → select
   **Read and write permissions** (lets the release job push to GHCR and the
   monitor job file issues).
3. **Settings → Code security** → enable **Dependabot alerts**, **Dependabot
   security updates**, and **Code scanning** (all free on public repos; the
   monitor's SARIF upload needs Code scanning).
4. (First release only) push a tag — the first push creates the GHCR package.
   Then set the package visibility to public under your profile's *Packages* if
   you want anonymous pulls.

No personal access tokens, signing keys, or registry credentials are required:
GHCR auth uses `GITHUB_TOKEN`, and attestations use keyless OIDC signing.
