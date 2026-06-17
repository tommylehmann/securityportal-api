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

	"github.com/securityportal/securityportal-api/pkg/auth"
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

	// maxSegmentBytes is the maximum byte length of any dynamic URL path segment
	// (publisher or tracking_id) before any DB call. Inputs exceeding this bound are
	// rejected with 400. This is a defense-in-depth guard against oversized inputs
	// reaching the query layer (C-27/C-20/SA-43).
	maxSegmentBytes = 256
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

// AdvisoryListResponse is the body of GET /api/advisories and
// GET /api/advisories/{publisher}. It carries a paginated page of advisory
// rows plus the total count of rows matching the current filter (before
// limit/offset), HATEOAS _links for pagination, and per-row _links.self for
// the canonical publisher-scoped permalink (ADR-0015/C-34/SA-50).
type AdvisoryListResponse struct {
	Advisories []AdvisoryRow   `json:"advisories"`
	Total      int64           `json:"total"`
	Limit      int             `json:"limit"`
	Offset     int             `json:"offset"`
	Links      CollectionLinks `json:"_links"`
}

// FacetsResponse is the body of GET /api/facets. It wraps the facet counts
// computed by the database layer so the handler does not need to re-encode
// the struct via gin.H and both are in sync.
type FacetsResponse = database.Facets

// ErrorResponse is the uniform error body returned on 4xx and 5xx responses.
// Every error-producing handler uses this type so clients can rely on a
// consistent {"error": "..."} shape.
type ErrorResponse struct {
	Error string `json:"error"`
}

// WithdrawnEnvelope is the exact 3-key body returned with HTTP 410 Gone when a
// permalink resolves to a withdrawn advisory (ADR-0015/ADR-0016, C-35/SA-51).
// The envelope carries only the stored tracking_id, the withdrawn flag, and the
// tombstone timestamp; no internal ids or document fields are included so the
// response gives no information beyond what the URL already implies.
type WithdrawnEnvelope struct {
	Withdrawn   bool       `json:"withdrawn"`
	TrackingID  string     `json:"tracking_id"`
	WithdrawnAt *time.Time `json:"withdrawn_at"`
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
// revision per advisory, filtered to publishable TLP in SQL, excluding withdrawn
// advisories, and narrowed by the combinable facet/search filters
// (q/cve/severity/...). Each row carries its aggregated CVE list.
//
// When format=csv the same result set is streamed as RFC-4180 CSV with OWASP
// CSV-injection cell-prefixing (C-33/SA-48/SA-49). The format param is read here
// only; the CSV path diverges before any response is written.
func (c *Controller) listAdvisories(ctx *gin.Context) {
	opts, ok := parseListOptions(ctx)
	if !ok {
		return
	}

	// SA-36/C-24: source the TLP allow-list from the per-request principal, not
	// from a static controller field. The SQL gate is unchanged; only the source
	// of the []string parameter changes (ADR-0019/task 53).
	principal := auth.PrincipalFromContext(ctx.Request.Context())
	list, err := c.db.ListAdvisories(ctx.Request.Context(), opts, principal.AllowedTLP())
	if err != nil {
		slog.Error("listing advisories failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal error"})
		return
	}

	// SA-49/C-33: format=csv is only honoured on list endpoints; the document
	// endpoint ignores it (verbatim JSON is always returned there).
	if ctx.Query("format") == "csv" {
		writeAdvisoryCSV(ctx, list.Advisories)
		return
	}

	// Build pagination _links from the TLP-gated total (C-34/SA-50: links are
	// computed from the gated total so no link implies a non-publishable row).
	baseURL := paginationBaseURL(ctx.Request.URL.Path, ctx.Request.URL.Query())
	links := buildCollectionLinks(baseURL, list.Total, opts.Limit, opts.Offset)

	ctx.JSON(http.StatusOK, AdvisoryListResponse{
		Advisories: addLinks(list.Advisories),
		Total:      list.Total,
		Limit:      opts.Limit,
		Offset:     opts.Offset,
		Links:      links,
	})
}

// listAdvisoriesByPublisher serves GET /api/advisories/:publisher: the same
// paged list as listAdvisories but scoped to a single publisher. The publisher
// segment is URL-decoded by Gin and bound into the filter as a parameter (no SQL
// interpolation — C-27/SA-39). A 256-byte cap is applied before any DB call
// (C-27/SA-43); unknown/empty-result publishers yield an empty page (not 404).
func (c *Controller) listAdvisoriesByPublisher(ctx *gin.Context) {
	pub := ctx.Param("publisher")

	// C-27/SA-43: reject overlong publisher segment before any DB call.
	if len(pub) > maxSegmentBytes {
		badRequest(ctx, "publisher segment too long")
		return
	}
	if pub == "" {
		badRequest(ctx, "missing publisher")
		return
	}

	opts, ok := parseListOptions(ctx)
	if !ok {
		return
	}
	// Scope the list to this publisher by setting the Publisher filter. The filter
	// layer already supports this (Filters.Publisher → publisher_name = $N bound
	// parameter). A caller-supplied publisher filter param is ignored in favour of
	// the path segment — the path is the canonical scope.
	opts.Filters.Publisher = pub

	// SA-36/C-24: same principal source as listAdvisories.
	principal := auth.PrincipalFromContext(ctx.Request.Context())
	list, err := c.db.ListAdvisories(ctx.Request.Context(), opts, principal.AllowedTLP())
	if err != nil {
		slog.Error("listing advisories by publisher failed", "publisher", pub, "error", err)
		ctx.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal error"})
		return
	}

	if ctx.Query("format") == "csv" {
		writeAdvisoryCSV(ctx, list.Advisories)
		return
	}

	baseURL := paginationBaseURL(ctx.Request.URL.Path, ctx.Request.URL.Query())
	links := buildCollectionLinks(baseURL, list.Total, opts.Limit, opts.Offset)

	ctx.JSON(http.StatusOK, AdvisoryListResponse{
		Advisories: addLinks(list.Advisories),
		Total:      list.Total,
		Limit:      opts.Limit,
		Offset:     opts.Offset,
		Links:      links,
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

	// SA-36/C-24: same principal source as listAdvisories.
	principal := auth.PrincipalFromContext(ctx.Request.Context())
	result, err := c.db.ComputeFacets(ctx.Request.Context(), filters, principal.AllowedTLP())
	if err != nil {
		slog.Error("computing facets failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal error"})
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
	var out []string
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

	// SA-36/C-24: source TLP from the per-request principal.
	principal := auth.PrincipalFromContext(ctx.Request.Context())
	raw, err := c.db.GetDocument(ctx.Request.Context(), id, principal.AllowedTLP())
	switch {
	case err == nil:
		// Serve the JSONB bytes verbatim. Data (not JSON) avoids re-encoding the
		// already-serialised document.
		ctx.Data(http.StatusOK, "application/json; charset=utf-8", raw)
	case errors.Is(err, database.ErrDocumentNotFound):
		ctx.JSON(http.StatusNotFound, ErrorResponse{Error: "document not found"})
	default:
		slog.Error("fetching document failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal error"})
	}
}

// getAdvisoryByPublisherTrackingID serves
// GET /api/advisories/:publisher/:trackingid: the canonical public advisory
// permalink (ADR-0016). It resolves the (publisher, tracking_id) pair to the
// advisory's latest publishable document revision and returns the CSAF JSON
// verbatim, or HTTP 410 Gone for a withdrawn advisory.
//
// Security controls applied here:
//   - C-27/SA-43: empty or >256-byte publisher or trackingid → 400 before any
//     DB call.
//   - C-27/SA-39: both segments reach Postgres only as bound parameters via
//     GetByPublisherTrackingID; no fmt.Sprintf/concat of either value into SQL.
//   - C-35/SA-51: on withdrawn=true the 410 envelope is written and the handler
//     returns immediately — raw document bytes are never read; a withdrawn
//     advisory whose latest doc is non-publishable returns 404 (not 410) because
//     the JOIN in GetByPublisherTrackingID filters it out, so ErrDocumentNotFound
//     is returned and the handler emits 404 (the non-publishable 404 wins over
//     410, preserving the no-restricted-existence-oracle invariant — SA-41).
//   - C-27/SA-40: GetByPublisherTrackingID unconditionally constrains the latest
//     doc to upper(d.tlp)=ANY($publishable); missing or non-publishable → 404
//     identical in shape to the existing 404 (no oracle — SA-41).
//   - C-28/SA-42: routing precedence documented in server.go.
func (c *Controller) getAdvisoryByPublisherTrackingID(ctx *gin.Context) {
	pub := ctx.Param("publisher")
	id := ctx.Param("trackingid")

	// C-27/SA-43: reject empty or overlong segments before any DB call.
	if pub == "" {
		badRequest(ctx, "missing publisher")
		return
	}
	if len(pub) > maxSegmentBytes {
		badRequest(ctx, "publisher segment too long")
		return
	}
	if id == "" {
		badRequest(ctx, "missing tracking id")
		return
	}
	if len(id) > maxSegmentBytes {
		badRequest(ctx, "tracking id too long")
		return
	}

	// SA-36/C-24: source TLP from the per-request principal.
	principal := auth.PrincipalFromContext(ctx.Request.Context())
	raw, withdrawn, withdrawnAt, err := c.db.GetByPublisherTrackingID(
		ctx.Request.Context(), pub, id, principal.AllowedTLP())
	switch {
	case err == nil:
		// C-35/SA-51: check withdrawn before touching raw bytes.
		if withdrawn {
			// Emit the exact 3-key envelope with HTTP 410 Gone (ADR-0015/ADR-0016).
			// The tracking_id echoes the value the handler received (the URL-decoded
			// path segment), which is the same value stored in the DB.
			ctx.JSON(http.StatusGone, WithdrawnEnvelope{
				Withdrawn:   true,
				TrackingID:  id,
				WithdrawnAt: withdrawnAt,
			})
			return
		}
		// Serve the CSAF JSON verbatim — mirror getDocument.
		ctx.Data(http.StatusOK, "application/json; charset=utf-8", raw)
	case errors.Is(err, database.ErrDocumentNotFound):
		// C-27/SA-41: same 404 shape for missing AND non-publishable — no oracle
		// for restricted documents, and no oracle for existence of a withdrawn doc
		// with non-publishable latest revision (SA-51: 404 wins over 410 here).
		ctx.JSON(http.StatusNotFound, ErrorResponse{Error: "document not found"})
	default:
		slog.Error("fetching advisory by publisher+tracking_id failed",
			"publisher", pub, "tracking_id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal error"})
	}
}

// badRequest writes a uniform 400 error body.
func badRequest(ctx *gin.Context, message string) {
	ctx.JSON(http.StatusBadRequest, ErrorResponse{Error: message})
}
