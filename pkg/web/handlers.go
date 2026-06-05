// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 SecurityPortal contributors

package web

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/securityportal/securityportal-api/pkg/database"
)

// Pagination bounds for the advisory list.
const (
	defaultLimit = 25
	maxLimit     = 100
)

// healthResponse is the body of GET /api/health. Status is "ok" when the
// database is reachable and "unavailable" otherwise; last_ingest is the time of
// the most recent successful ingestion cycle, omitted before the first poll.
type healthResponse struct {
	Status     string     `json:"status"`
	Database   string     `json:"database"`
	LastIngest *time.Time `json:"last_ingest,omitempty"`
	Version    string     `json:"version,omitempty"`
}

// health reports liveness/readiness: 200 when the database answers a ping, 503
// when it does not. The last successful ingest time is included when available
// so an operator can spot a stalled poll loop.
func (c *Controller) health(ctx *gin.Context) {
	rctx := ctx.Request.Context()

	if err := c.db.Ping(rctx); err != nil {
		slog.Warn("health check: database unreachable", "error", err)
		ctx.JSON(http.StatusServiceUnavailable, healthResponse{
			Status:   "unavailable",
			Database: "unreachable",
		})
		return
	}

	resp := healthResponse{Status: "ok", Database: "reachable"}
	if last, ok, err := c.db.LastIngest(rctx); err != nil {
		// A reachable database that cannot answer the ingest query is degraded but
		// still "up"; report reachable without a last-ingest time.
		slog.Warn("health check: reading last ingest time failed", "error", err)
	} else if ok {
		resp.LastIngest = &last
	}

	ctx.JSON(http.StatusOK, resp)
}

// listAdvisories serves GET /api/advisories: a paged, sorted list of the latest
// revision per advisory, filtered to publishable TLP in SQL and excluding
// withdrawn advisories. Facet filters (q/cve/severity/...) are a later phase;
// the handler is structured so they slot into ListOptions and the query without
// reshaping the response.
func (c *Controller) listAdvisories(ctx *gin.Context) {
	opts, ok := parseListOptions(ctx)
	if !ok {
		return
	}

	list, err := c.db.ListAdvisories(ctx.Request.Context(), opts, c.publishableTLP)
	if err != nil {
		slog.Error("listing advisories failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"advisories": list.Advisories,
		"total":      list.Total,
		"limit":      opts.Limit,
		"offset":     opts.Offset,
	})
}

// parseListOptions reads and validates the pagination/sort query parameters,
// writing a 400 and returning ok=false on a malformed value.
func parseListOptions(ctx *gin.Context) (database.ListOptions, bool) {
	opts := database.ListOptions{
		Limit:      defaultLimit,
		Offset:     0,
		Sort:       database.SortCurrentReleaseDate,
		Descending: true, // newest first by default (spec §8).
	}

	if raw := ctx.Query("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 0 {
			badRequest(ctx, "invalid limit")
			return opts, false
		}
		if limit == 0 || limit > maxLimit {
			limit = maxLimit
		}
		opts.Limit = limit
	}

	if raw := ctx.Query("offset"); raw != "" {
		offset, err := strconv.Atoi(raw)
		if err != nil || offset < 0 {
			badRequest(ctx, "invalid offset")
			return opts, false
		}
		opts.Offset = offset
	}

	// sort accepts a whitelisted column with an optional direction suffix, e.g.
	// "current_release_date" (defaults desc) or "critical:asc". Anything outside
	// the whitelist is rejected so the column never comes from raw input.
	if raw := ctx.Query("sort"); raw != "" {
		column, descending, ok := parseSort(raw)
		if !ok {
			badRequest(ctx, "invalid sort")
			return opts, false
		}
		opts.Sort = column
		opts.Descending = descending
	}

	return opts, true
}

// parseSort maps a sort query value to a whitelisted column and direction. The
// default direction is descending (newest/highest first); an explicit ":asc" or
// ":desc" suffix overrides it.
func parseSort(raw string) (database.ListSort, bool, bool) {
	name := raw
	descending := true
	if idx := strings.IndexByte(raw, ':'); idx >= 0 {
		name = raw[:idx]
		switch raw[idx+1:] {
		case "asc":
			descending = false
		case "desc":
			descending = true
		default:
			return "", false, false
		}
	}

	switch database.ListSort(name) {
	case database.SortCurrentReleaseDate:
		return database.SortCurrentReleaseDate, descending, true
	case database.SortCritical:
		return database.SortCritical, descending, true
	default:
		return "", false, false
	}
}

// getDocument serves GET /api/documents/:id: the stored CSAF JSON for one
// revision, verbatim, with Content-Type application/json. This is what the
// frontend feeds to convertToDocModel; it replaces the csaf_webview proxy. A
// missing id or a non-publishable-TLP document is a 404 (a withdrawn advisory's
// document is still served — permalink stability).
func (c *Controller) getDocument(ctx *gin.Context) {
	id, err := strconv.ParseInt(ctx.Param("id"), 10, 64)
	if err != nil || id < 0 {
		badRequest(ctx, "invalid document id")
		return
	}

	raw, err := c.db.GetDocument(ctx.Request.Context(), id, c.publishableTLP)
	switch {
	case err == nil:
		// Serve the JSONB bytes verbatim. Data (not JSON) avoids re-encoding the
		// already-serialised document.
		ctx.Data(http.StatusOK, "application/json; charset=utf-8", raw)
	case errors.Is(err, database.ErrDocumentNotFound):
		ctx.JSON(http.StatusNotFound, gin.H{"error": "document not found"})
	default:
		slog.Error("fetching document failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}

// badRequest writes a uniform 400 error body.
func badRequest(ctx *gin.Context, message string) {
	ctx.JSON(http.StatusBadRequest, gin.H{"error": message})
}
