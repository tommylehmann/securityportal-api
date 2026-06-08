// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package web

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// requestLogger emits one structured slog line per request once it completes,
// recording method, path, status, latency, and client IP. It is a small local
// middleware rather than a third-party dependency: the API has only a handful of
// read-only routes and this keeps the dependency surface minimal.
func requestLogger() gin.HandlerFunc {
	logger := slog.Default()
	return func(ctx *gin.Context) {
		start := time.Now()
		ctx.Next()

		attrs := []any{
			"method", ctx.Request.Method,
			"path", ctx.Request.URL.Path,
			"status", ctx.Writer.Status(),
			"latency", time.Since(start).String(),
			"client_ip", ctx.ClientIP(),
		}
		if len(ctx.Errors) > 0 {
			attrs = append(attrs, "errors", ctx.Errors.String())
		}

		// Surface server errors at a higher level so they are not lost in request
		// noise; everything else is informational.
		if ctx.Writer.Status() >= http.StatusInternalServerError {
			logger.Error("request", attrs...)
		} else {
			logger.Info("request", attrs...)
		}
	}
}

// securityHeaders applies the baseline security headers to every API response
// (threat model control C-4 / SA-18).
//
//   - X-Content-Type-Options: nosniff prevents browsers from MIME-sniffing an
//     API JSON response away from the declared Content-Type. This is important for
//     /api/documents/:id: the CSAF JSON is served with application/json and must
//     never be re-interpreted as text/html, which could allow script execution if
//     the stored content happened to contain HTML.
//
// Note: HSTS is the reverse proxy's responsibility and is not set here (see
// threat model §1 and decisions/0006-content-security-policy.md).
func securityHeaders() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Header("X-Content-Type-Options", "nosniff")
		ctx.Next()
	}
}

// NOTE — rate limiting (threat model C-7 / R-4):
//
// IP-level rate limiting is the reverse proxy's responsibility and is not
// implemented here. The in-process DoS guards are:
//   1. offset cap (maxOffset = 10000 in handlers.go) — expensive deep-page requests
//      are rejected with a 400 before they reach the database.
//   2. statement timeout (cfg.QueryTimeout, default 5 s) — any SQL query that
//      runs past the deadline is cancelled by Postgres; the handler returns a 500.
//
// Operators should configure their reverse proxy (nginx, Caddy, Traefik, etc.) to
// enforce per-IP request-rate limits and to set an overall connection limit before
// requests reach this service. Those controls live outside the application and are
// not duplicated here to avoid adding a stateful in-memory data structure that
// would require additional care in a multi-process deployment.

// corsMiddleware returns a handler that permits cross-origin GET requests from
// the configured origins. Because the API is read-only, only simple GET/HEAD
// requests and the corresponding preflight are allowed; no credentials, no
// mutating methods. It returns nil when no origins are configured, so the API
// emits no CORS headers at all in that case.
func corsMiddleware(allowed []string) gin.HandlerFunc {
	if len(allowed) == 0 {
		return nil
	}
	// Index the allow-list for O(1) origin checks and to support a "*" wildcard.
	wildcard := false
	set := make(map[string]struct{}, len(allowed))
	for _, origin := range allowed {
		if origin == "*" {
			wildcard = true
		}
		set[origin] = struct{}{}
	}

	return func(ctx *gin.Context) {
		origin := ctx.GetHeader("Origin")
		if origin != "" {
			if wildcard {
				ctx.Header("Access-Control-Allow-Origin", "*")
			} else if _, ok := set[origin]; ok {
				ctx.Header("Access-Control-Allow-Origin", origin)
				// Vary so caches do not serve one origin's response to another.
				ctx.Header("Vary", "Origin")
			}
		}
		ctx.Header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		ctx.Header("Access-Control-Allow-Headers", "Content-Type")

		// Short-circuit the preflight request.
		if ctx.Request.Method == http.MethodOptions {
			ctx.AbortWithStatus(http.StatusNoContent)
			return
		}
		ctx.Next()
	}
}
