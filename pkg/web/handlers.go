// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package web

import (
	"errors"
	"fmt"
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
	// maxOffset is the maximum pagination offset accepted by the list endpoints.
	// Deep offsets (e.g. OFFSET 999999) force Postgres to scan and discard a large
	// number of rows even on indexed queries, making them an effective DoS vector
	// on a public API. Requests exceeding this bound are rejected with a 400 rather
	// than silently clamped so callers receive an unambiguous signal to use
	// cursor-based pagination instead (threat model C-7 / R-4).
	maxOffset = 10000
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

// listAdvisories serves GET /api/advisories (and the /api/advisories/search
// alias): a paged, sorted list of the latest revision per advisory, filtered to
// publishable TLP in SQL, excluding withdrawn advisories, and narrowed by the
// combinable facet/search filters (q/cve/severity/...). Each row carries its
// aggregated CVE list.
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

// facets serves GET /api/facets: the distinct facet values and their counts over
// the currently filtered set, for building the WID-style filter sidebar. It
// accepts the same filter params as listAdvisories and applies them all
// (standard drill-down), so the counts always match the filtered result list.
func (c *Controller) facets(ctx *gin.Context) {
	filters, ok := parseFilters(ctx)
	if !ok {
		return
	}

	result, err := c.db.ComputeFacets(ctx.Request.Context(), filters, c.publishableTLP)
	if err != nil {
		slog.Error("computing facets failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	ctx.JSON(http.StatusOK, result)
}

// parseListOptions reads and validates the pagination/sort parameters and the
// facet filters, writing a 400 and returning ok=false on a malformed value.
func parseListOptions(ctx *gin.Context) (database.ListOptions, bool) {
	filters, ok := parseFilters(ctx)
	if !ok {
		return database.ListOptions{}, false
	}

	opts := database.ListOptions{
		Filters:    filters,
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
		// Reject deep offsets rather than silently clamping: a caller that sends
		// offset=999999 needs to know to switch to cursor/keyset pagination, not
		// silently receive results from the clamped boundary.
		if offset > maxOffset {
			badRequest(ctx, fmt.Sprintf("offset exceeds maximum (%d); use cursor pagination for deep pages", maxOffset))
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

// parseFilters reads and validates the combinable search/facet query parameters
// shared by the list and facets endpoints (spec §8/§13). It is the single point
// where caller input is validated: a malformed date, number, or severity band is
// rejected with a 400 (ok=false) rather than being silently dropped or surfacing
// as a 500 from the database. All accepted values flow into the query as bound
// parameters; none is interpolated into SQL.
func parseFilters(ctx *gin.Context) (database.Filters, bool) {
	var f database.Filters

	f.Query = ctx.Query("q")
	f.CVE = ctx.Query("cve")
	f.Publisher = ctx.Query("publisher")
	f.Product = ctx.Query("product")
	f.Vendor = ctx.Query("vendor")
	f.Category = ctx.Query("category")
	f.Lang = ctx.Query("lang")

	// severity: repeatable and/or comma-separated; each value must be a known band.
	if severities := multiValue(ctx, "severity"); len(severities) > 0 {
		for _, s := range severities {
			if !database.IsSeverityBand(s) {
				badRequest(ctx, "invalid severity")
				return database.Filters{}, false
			}
		}
		f.Severity = severities
	}

	// tlp: repeatable and/or comma-separated. The query layer intersects these
	// with the publishable set, so an unpublishable label here simply matches
	// nothing — no validation against a label whitelist is required for safety.
	if tlps := multiValue(ctx, "tlp"); len(tlps) > 0 {
		f.TLP = tlps
	}

	var ok bool
	if f.ScoreMin, ok = parseOptionalFloat(ctx, "score_min"); !ok {
		return database.Filters{}, false
	}
	if f.ScoreMax, ok = parseOptionalFloat(ctx, "score_max"); !ok {
		return database.Filters{}, false
	}

	if f.From, ok = parseOptionalDate(ctx, "from"); !ok {
		return database.Filters{}, false
	}
	if f.To, ok = parseOptionalDate(ctx, "to"); !ok {
		return database.Filters{}, false
	}

	return f, true
}

// multiValue collects a repeatable query parameter, additionally splitting each
// occurrence on commas, so "severity=high&severity=critical" and
// "severity=high,critical" are equivalent. Whitespace is trimmed and empties
// dropped.
func multiValue(ctx *gin.Context, name string) []string {
	out := make([]string, 0)
	for _, raw := range ctx.QueryArray(name) {
		for _, part := range strings.Split(raw, ",") {
			if v := strings.TrimSpace(part); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// parseOptionalFloat reads a numeric query parameter. An absent parameter yields
// (nil, true); a present but malformed one yields a 400 and ok=false.
func parseOptionalFloat(ctx *gin.Context, name string) (*float64, bool) {
	raw := ctx.Query(name)
	if raw == "" {
		return nil, true
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		badRequest(ctx, "invalid "+name)
		return nil, false
	}
	return &v, true
}

// parseOptionalDate reads a date/time query parameter. An absent parameter
// yields (zero, true); a present but malformed one yields a 400 and ok=false.
// Both a full RFC 3339 timestamp and a bare YYYY-MM-DD date (interpreted as UTC
// midnight) are accepted, so the UI can send either a calendar date or an exact
// instant.
func parseOptionalDate(ctx *gin.Context, name string) (time.Time, bool) {
	raw := strings.TrimSpace(ctx.Query(name))
	if raw == "" {
		return time.Time{}, true
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, true
	}
	if t, err := time.Parse("2006-01-02", raw); err == nil {
		return t.UTC(), true
	}
	badRequest(ctx, "invalid "+name)
	return time.Time{}, false
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
