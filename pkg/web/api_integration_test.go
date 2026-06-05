// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 SecurityPortal contributors

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/securityportal/securityportal-api/internal/dbtest"
	"github.com/securityportal/securityportal-api/pkg/config"
	"github.com/securityportal/securityportal-api/pkg/database"
)

// These tests wire the REAL Gin handlers to a REAL *database.DB backed by a live
// postgres:16-alpine (docker-in-docker), seeded with CSAF-shaped fixtures, and
// drive them end-to-end over httptest. They complement the fake-Querier handler
// tests in handlers_test.go: those pin the HTTP plumbing, these prove the wired
// handler + SQL stack behaves against real data. They skip cleanly without docker.

// apiHarness brings up a seeded database and a handler bound to it.
type apiHarness struct {
	db      *database.DB
	pool    *pgxpool.Pool
	ctx     context.Context
	handler http.Handler
}

// newAPIHarness starts postgres, migrates, opens a *database.DB on the same DSN,
// and builds the controller with the default publishable-TLP policy.
func newAPIHarness(t *testing.T) *apiHarness {
	t.Helper()
	pool, dsn, ctx := dbtest.StartPostgres(t)
	if err := database.Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	db, err := database.NewDB(ctx, dsn)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(db.Close)

	cfg := &config.Config{
		PublishableTLP: []csaf.TLPLabel{csaf.TLPLabelWhite, csaf.TLPLabelUnlabeled},
	}
	return &apiHarness{
		db:      db,
		pool:    pool,
		ctx:     ctx,
		handler: NewController(cfg, db).Handler(),
	}
}

// seedDoc inserts one revision via the real StoreDocument path.
func (h *apiHarness) seedDoc(t *testing.T, trackingID, publisher, version, releaseDate, tlp string, revLen int) {
	t.Helper()
	doc := apiCSAFDoc(trackingID, publisher, version, releaseDate, tlp, revLen)
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshaling fixture: %v", err)
	}
	if _, err := h.db.StoreDocument(h.ctx, trackingID, publisher, doc, b); err != nil {
		t.Fatalf("StoreDocument %s: %v", trackingID, err)
	}
}

// docID returns the latest revision's document id for an advisory.
func (h *apiHarness) docID(t *testing.T, trackingID, publisher string) int64 {
	t.Helper()
	var id int64
	err := h.pool.QueryRow(h.ctx, `
		SELECT d.id FROM documents d JOIN advisories a ON a.id = d.advisories_id
		WHERE a.tracking_id = $1 AND a.publisher = $2 AND d.latest`,
		trackingID, publisher).Scan(&id)
	if err != nil {
		t.Fatalf("finding document id for %s: %v", trackingID, err)
	}
	return id
}

func (h *apiHarness) get(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	h.handler.ServeHTTP(rec, req)
	return rec
}

// apiCSAFDoc is a CSAF-shaped fixture with a CVSS score so the critical facet is
// populated.
func apiCSAFDoc(trackingID, publisher, version, releaseDate, tlp string, revLen int) map[string]any {
	history := make([]any, revLen)
	for i := range history {
		history[i] = map[string]any{"number": itoaAPI(i + 1)}
	}
	return map[string]any{
		"document": map[string]any{
			"category": "csaf_security_advisory",
			"title":    "Advisory " + trackingID + " " + version,
			"lang":     "en",
			"publisher": map[string]any{
				"name":      publisher,
				"namespace": "https://example.test",
			},
			"distribution": map[string]any{
				"tlp": map[string]any{"label": tlp},
			},
			"tracking": map[string]any{
				"id":                   trackingID,
				"version":              version,
				"status":               "final",
				"current_release_date": releaseDate,
				"initial_release_date": "2026-01-01T00:00:00Z",
				"revision_history":     history,
			},
		},
		"vulnerabilities": []any{
			map[string]any{
				"scores": []any{
					map[string]any{
						"cvss_v3": map[string]any{"baseScore": 9.8},
					},
				},
			},
		},
	}
}

func itoaAPI(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// listResponse mirrors the JSON body of GET /api/advisories.
type listResponse struct {
	Advisories []struct {
		ID         int64   `json:"id"`
		TrackingID string  `json:"tracking_id"`
		TLP        *string `json:"tlp"`
		Version    *string `json:"version"`
	} `json:"advisories"`
	Total  int64 `json:"total"`
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
}

func decodeList(t *testing.T, rec *httptest.ResponseRecorder) listResponse {
	t.Helper()
	var body listResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding list body: %v\n%s", err, rec.Body.String())
	}
	return body
}

func (l listResponse) ids() []string {
	out := make([]string, len(l.Advisories))
	for i, a := range l.Advisories {
		out[i] = a.TrackingID
	}
	return out
}

// TestAPIHealthReportsReachableWithIngestTime drives GET /api/health against a
// live database and an ingest-state row.
func TestAPIHealthReportsReachableWithIngestTime(t *testing.T) {
	h := newAPIHarness(t)

	before := time.Now().Add(-time.Minute)
	if err := h.db.SetWatermark(h.ctx, "https://provider.example.test/white/feed.json",
		time.Date(2026, 6, 5, 10, 16, 6, 0, time.UTC)); err != nil {
		t.Fatalf("SetWatermark: %v", err)
	}

	rec := h.get(t, "/api/health")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\n%s", rec.Code, rec.Body.String())
	}
	var body healthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding health body: %v", err)
	}
	if body.Status != "ok" || body.Database != "reachable" {
		t.Errorf("health body = %+v, want ok/reachable", body)
	}
	// last_ingest is the write time of the ingest_state row, not the watermark.
	if body.LastIngest == nil {
		t.Fatal("expected a last_ingest time once an ingest_state row exists")
	}
	if body.LastIngest.Before(before) {
		t.Errorf("last_ingest = %v, want a recent ingest write time (>= %v)", body.LastIngest, before)
	}
}

// TestAPIListReturnsLatestPublishablePerAdvisory exercises the full list flow:
// latest revision per advisory, withdrawn excluded, restricted TLP excluded.
func TestAPIListReturnsLatestPublishablePerAdvisory(t *testing.T) {
	h := newAPIHarness(t)

	const pub = "Acme Security Team"
	// ADV-A: two revisions; the latest (v2) must be the only row.
	h.seedDoc(t, "ADV-A", pub, "1.0.0", "2026-02-01T00:00:00Z", "WHITE", 1)
	h.seedDoc(t, "ADV-A", pub, "2.0.0", "2026-03-01T00:00:00Z", "WHITE", 2)
	// ADV-D: CLEAR (WHITE alias) -> published; older date than ADV-A v2.
	h.seedDoc(t, "ADV-D", pub, "1.0.0", "2026-01-15T00:00:00Z", "CLEAR", 1)
	// ADV-C: GREEN -> never published.
	h.seedDoc(t, "ADV-C", pub, "1.0.0", "2026-04-01T00:00:00Z", "GREEN", 1)
	// ADV-B: WHITE but withdrawn -> excluded from list.
	h.seedDoc(t, "ADV-B", pub, "1.0.0", "2026-05-01T00:00:00Z", "WHITE", 1)
	if _, err := h.db.TombstoneAbsent(h.ctx, []database.AdvisoryKey{
		{TrackingID: "ADV-A", Publisher: pub},
		{TrackingID: "ADV-D", Publisher: pub},
		{TrackingID: "ADV-C", Publisher: pub},
	}); err != nil {
		t.Fatalf("withdrawing ADV-B: %v", err)
	}

	rec := h.get(t, "/api/advisories")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\n%s", rec.Code, rec.Body.String())
	}
	body := decodeList(t, rec)

	if body.Total != 2 {
		t.Errorf("total = %d, want 2 (ADV-A latest + ADV-D)", body.Total)
	}
	ids := body.ids()
	if !contains(ids, "ADV-A") || !contains(ids, "ADV-D") {
		t.Errorf("ids = %v, want ADV-A and ADV-D", ids)
	}
	if contains(ids, "ADV-C") {
		t.Error("GREEN advisory ADV-C must never appear")
	}
	if contains(ids, "ADV-B") {
		t.Error("withdrawn advisory ADV-B must not appear")
	}
	// Default sort is current_release_date desc: ADV-A (Mar) before ADV-D (Jan).
	if ids[0] != "ADV-A" {
		t.Errorf("default order = %v, want ADV-A (newer) first", ids)
	}
	// The single ADV-A row must be the latest revision (v2.0.0).
	for _, a := range body.Advisories {
		if a.TrackingID == "ADV-A" && (a.Version == nil || *a.Version != "2.0.0") {
			t.Errorf("ADV-A version = %v, want latest 2.0.0", a.Version)
		}
	}
}

// TestAPIListPaginationAndBadParams covers paging through HTTP and 400 on bad
// query params (end-to-end, not the fake).
func TestAPIListPaginationAndBadParams(t *testing.T) {
	h := newAPIHarness(t)

	const pub = "Acme Security Team"
	for i := 0; i < 5; i++ {
		id := "PAGE-" + itoaAPI(i)
		date := time.Date(2026, 1, 1+i, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
		h.seedDoc(t, id, pub, "1.0.0", date, "WHITE", 1)
	}

	rec := h.get(t, "/api/advisories?limit=2&offset=0")
	body := decodeList(t, rec)
	if body.Total != 5 {
		t.Errorf("total = %d, want 5 (full set, not the page)", body.Total)
	}
	if len(body.Advisories) != 2 {
		t.Errorf("page size = %d, want 2", len(body.Advisories))
	}
	if body.Limit != 2 || body.Offset != 0 {
		t.Errorf("echoed limit/offset = %d/%d, want 2/0", body.Limit, body.Offset)
	}

	// limit over the cap is clamped to maxLimit.
	rec = h.get(t, "/api/advisories?limit=9999")
	body = decodeList(t, rec)
	if body.Limit != maxLimit {
		t.Errorf("limit = %d, want clamped to %d", body.Limit, maxLimit)
	}

	for _, bad := range []string{
		"/api/advisories?limit=-5",
		"/api/advisories?offset=foo",
		"/api/advisories?sort=document",
		// A SQL-injection payload smuggled into sort (no ';' which would be eaten by
		// query-string parsing): it reaches the handler, fails the whitelist, 400.
		"/api/advisories?sort=critical%27%20OR%201=1--",
		"/api/advisories?sort=critical:up",
	} {
		if r := h.get(t, bad); r.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", bad, r.Code)
		}
	}

	// After every hostile sort attempt the documents table must be intact and the
	// list must still serve — proving the payloads never reached SQL.
	r := h.get(t, "/api/advisories")
	if r.Code != http.StatusOK {
		t.Fatalf("list after hostile sort attempts = %d, want 200", r.Code)
	}
	if got := decodeList(t, r).Total; got != 5 {
		t.Errorf("total after hostile sort attempts = %d, want 5 (table intact)", got)
	}
}

// TestAPIGetDocument covers verbatim JSON, 404 for missing/restricted, 400 for a
// malformed id, and a withdrawn advisory's document still being served.
func TestAPIGetDocument(t *testing.T) {
	h := newAPIHarness(t)

	const pub = "Acme Security Team"
	h.seedDoc(t, "DOC-WHITE", pub, "1.0.0", "2026-02-01T00:00:00Z", "WHITE", 1)
	h.seedDoc(t, "DOC-AMBER", pub, "1.0.0", "2026-02-01T00:00:00Z", "AMBER", 1)
	h.seedDoc(t, "DOC-WD", pub, "1.0.0", "2026-02-01T00:00:00Z", "WHITE", 1)
	if _, err := h.db.TombstoneAbsent(h.ctx, []database.AdvisoryKey{
		{TrackingID: "DOC-WHITE", Publisher: pub},
		{TrackingID: "DOC-AMBER", Publisher: pub},
	}); err != nil {
		t.Fatalf("withdrawing DOC-WD: %v", err)
	}

	whiteID := h.docID(t, "DOC-WHITE", pub)
	amberID := h.docID(t, "DOC-AMBER", pub)
	wdID := h.docID(t, "DOC-WD", pub)

	// Publishable document -> 200, JSON content type, valid CSAF body.
	rec := h.get(t, "/api/documents/"+itoa64(whiteID))
	if rec.Code != http.StatusOK {
		t.Fatalf("white doc status = %d, want 200\n%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("content-type = %q, want application/json; charset=utf-8", ct)
	}
	var parsed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("served document is not valid JSON: %v", err)
	}
	if _, ok := parsed["document"]; !ok {
		t.Error("served document missing /document object")
	}

	// Restricted (AMBER) -> 404 (never confirm a restricted doc exists).
	if rec := h.get(t, "/api/documents/"+itoa64(amberID)); rec.Code != http.StatusNotFound {
		t.Errorf("AMBER doc status = %d, want 404", rec.Code)
	}

	// Missing id -> 404.
	if rec := h.get(t, "/api/documents/987654"); rec.Code != http.StatusNotFound {
		t.Errorf("missing doc status = %d, want 404", rec.Code)
	}

	// Malformed id -> 400.
	if rec := h.get(t, "/api/documents/not-a-number"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad id status = %d, want 400", rec.Code)
	}

	// Withdrawn advisory's document is STILL served (permalink stability).
	if rec := h.get(t, "/api/documents/"+itoa64(wdID)); rec.Code != http.StatusOK {
		t.Errorf("withdrawn doc status = %d, want 200 (permalink stays resolvable)", rec.Code)
	}
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + byte(n%10))
		n /= 10
	}
	return string(buf[i:])
}
