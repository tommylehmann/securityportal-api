# This file is Free Software under the Apache-2.0 License
# without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
#
# SPDX-License-Identifier: Apache-2.0
#
# SPDX-FileCopyrightText: 2026 Tommy Lehmann

# Build the securityportal-api binary.
FROM library/golang:1.26.0-alpine AS build
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

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /app/securityportal-api /app/securityportal-api

WORKDIR /app
EXPOSE 8081

ENTRYPOINT ["/app/securityportal-api"]
