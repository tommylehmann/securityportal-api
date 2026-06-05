// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 SecurityPortal contributors

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
