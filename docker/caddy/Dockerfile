# This file is Free Software under the Apache-2.0 License
# without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
#
# SPDX-License-Identifier: Apache-2.0
#
# SPDX-FileCopyrightText: 2026 Tommy Lehmann

# Custom Caddy image with the caddy-ratelimit module (SA-26 / C-14 / ADR-0011).
#
# xcaddy compiles Caddy from source with the additional module baked in.
# The final image is based on the same caddy:2.9 release so its TLS
# and reverse-proxy behaviour is identical to the stock image; only the
# rate-limit module is added.
#
# To rebuild after a Caddy release update, bump both FROM tags together.

FROM caddy:2.9-builder AS builder

RUN xcaddy build \
    --with github.com/mholt/caddy-ratelimit

# ------------------------------------------------------------------
# Final image: copy the custom binary over the stock one.
# ------------------------------------------------------------------
FROM caddy:2.9

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
