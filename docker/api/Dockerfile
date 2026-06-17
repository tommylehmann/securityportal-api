# This file is Free Software under the Apache-2.0 License
# without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
#
# SPDX-License-Identifier: Apache-2.0
#
# SPDX-FileCopyrightText: 2026 Tommy Lehmann

# Build the securityportal-api binary.
# Base image is pinned by digest (supply-chain hardening); the tag in the
# comment is the human-readable version. Dependabot (docker ecosystem, see
# .github/dependabot.yml) bumps the digest. Keep the tag aligned with the
# go.mod toolchain when it advances.
# library/golang:1.26.4-alpine
FROM library/golang:1.26.4-alpine@sha256:f1ddd9fe14fffc091dd98cb4bfa999f32c5fc77d2f2305ea9f0e2595c5437c14 AS build
# CA certificates are needed to pull advisories from the HTTPS Trusted Provider.
RUN apk add -U --no-cache ca-certificates && update-ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY cmd cmd
COPY pkg pkg

ARG BUILD_VERSION=v0.0.0
RUN go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${BUILD_VERSION}" \
      -o /app/securityportal-api ./cmd/securityportal-api


FROM scratch

# Re-declare to consume the build-time version in the final stage's label. For
# CI builds the release workflow's metadata-action also stamps the full OCI
# label set (source, revision, created, …); this keeps a sensible version label
# on plain local `docker build` too.
ARG BUILD_VERSION=v0.0.0
LABEL org.opencontainers.image.title="securityportal-api" \
      org.opencontainers.image.version="${BUILD_VERSION}"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /app/securityportal-api /app/securityportal-api

WORKDIR /app
EXPOSE 8081

ENTRYPOINT ["/app/securityportal-api"]
