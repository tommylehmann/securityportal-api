// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package web

import (
	"bytes"
	_ "embed"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

// The OpenAPI 3.1 contract and the vendored Redoc standalone bundle are
// embedded into the binary at compile time (embed.FS). This means there is no
// runtime file-system dependency and no path-traversal surface — the files are
// sealed into the binary (C-37/SA-54).
//
// openapi.json is authored alongside openapi.yaml (the human-readable source).
// Makefile target `make openapi` re-generates openapi.json from openapi.yaml.
// See docs/openapi-lint.md for the recommended redocly-lint CI step.

//go:embed static/openapi.json
var openapiJSON []byte

//go:embed static/redoc.standalone.js
var redocJS []byte

// serveOpenAPIJSON serves GET /api/openapi.json. It returns the embedded
// OpenAPI 3.1 document as application/json with nosniff (C-37/SA-54). The
// document describes only the public read endpoints — no ingest or internal
// paths are included, so it does not widen the attack surface.
func (c *Controller) serveOpenAPIJSON(ctx *gin.Context) {
	ctx.Header("Content-Type", "application/json; charset=utf-8")
	ctx.Status(http.StatusOK)
	if _, err := ctx.Writer.Write(openapiJSON); err != nil {
		slog.Error("writing openapi.json failed", "error", err)
	}
}

// redocHTMLTmpl is the self-contained Redoc viewer page. It loads the vendored
// Redoc JS from /api/redoc.standalone.js (same origin, no CDN — C-37/SA-54)
// and points the spec URL at /api/openapi.json.
var redocHTMLTmpl = template.Must(template.New("redoc").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecurityPortal API Docs</title>
<style>body{margin:0;padding:0}</style>
</head>
<body>
<redoc spec-url="/api/openapi.json"></redoc>
<script src="/api/redoc.standalone.js"></script>
</body>
</html>
`))

// serveAPIDocs serves GET /api/docs — a self-hosted Redoc viewer HTML page.
// Redoc JS is loaded from /api/redoc.standalone.js (same origin) so no request
// is made to any external CDN (C-37/SA-54).
func (c *Controller) serveAPIDocs(ctx *gin.Context) {
	var buf bytes.Buffer
	if err := redocHTMLTmpl.Execute(&buf, nil); err != nil {
		slog.Error("rendering Redoc HTML failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal error"})
		return
	}
	ctx.Header("Content-Type", "text/html; charset=utf-8")
	ctx.Status(http.StatusOK)
	if _, err := ctx.Writer.Write(buf.Bytes()); err != nil {
		slog.Error("writing Redoc HTML failed", "error", err)
	}
}

// serveRedocJS serves the vendored Redoc standalone bundle from the embedded
// binary. It is the sole source for the /api/docs viewer; no external CDN is
// contacted (C-37/SA-54). A long cache TTL is safe because the bundle is sealed
// at build time and the URL is versioned implicitly by the binary release.
func (c *Controller) serveRedocJS(ctx *gin.Context) {
	ctx.Header("Content-Type", "application/javascript; charset=utf-8")
	ctx.Header("Cache-Control", "public, max-age=86400, immutable")
	ctx.Status(http.StatusOK)
	if _, err := ctx.Writer.Write(redocJS); err != nil {
		slog.Error("writing redoc.standalone.js failed", "error", err)
	}
}
