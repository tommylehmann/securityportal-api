// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gocsaf/csaf/v3/csaf"

	"github.com/securityportal/securityportal-api/pkg/config"
	"github.com/securityportal/securityportal-api/pkg/database"
)

// fakeQuerier is an in-memory Querier so the handlers can be exercised without a
// real database. Each field lets a test pin the behaviour of one method.
type fakeQuerier struct {
	pingErr        error
	lastIngest     time.Time
	lastIngestOK   bool
	lastIngestErr  error
	list           database.AdvisoryList
	listErr        error
	gotOpts        database.ListOptions
	gotPublishable []string
	facets         database.Facets
	facetsErr      error
	gotFilters     database.Filters
	doc            []byte
	docErr         error
	gotDocID       int64
	// Fields used by GetByPublisherTrackingID (and shared by tests that previously
	// exercised the now-removed flat GetByTrackingID route).
	trackingDoc         []byte
	trackingWithdrawn   bool
	trackingWithdrawnAt *time.Time
	trackingErr         error
	gotTrackingID       string
}

func (f *fakeQuerier) Ping(context.Context) error { return f.pingErr }

func (f *fakeQuerier) LastIngest(context.Context) (time.Time, bool, error) {
	return f.lastIngest, f.lastIngestOK, f.lastIngestErr
}

func (f *fakeQuerier) ListAdvisories(
	_ context.Context, opts database.ListOptions, publishable []string,
) (database.AdvisoryList, error) {
	f.gotOpts = opts
	f.gotPublishable = publishable
	return f.list, f.listErr
}

func (f *fakeQuerier) ComputeFacets(
	_ context.Context, filters database.Filters, publishable []string,
) (database.Facets, error) {
	f.gotFilters = filters
	f.gotPublishable = publishable
	return f.facets, f.facetsErr
}

func (f *fakeQuerier) GetDocument(
	_ context.Context, id int64, publishable []string,
) ([]byte, error) {
	f.gotDocID = id
	f.gotPublishable = publishable
	return f.doc, f.docErr
}

func (f *fakeQuerier) GetByPublisherTrackingID(
	_ context.Context, publisher, trackingID string, publishable []string,
) ([]byte, bool, *time.Time, error) {
	// Reuse the same tracking fields so existing handler tests can drive both
	// the flat and the publisher-scoped handler through the same fakeQuerier.
	f.gotTrackingID = trackingID
	f.gotPublishable = publishable
	return f.trackingDoc, f.trackingWithdrawn, f.trackingWithdrawnAt, f.trackingErr
}

// testConfig is a minimal config with the default publishable-TLP policy.
func testConfig() *config.Config {
	return &config.Config{
		PublishableTLP: []csaf.TLPLabel{csaf.TLPLabelWhite, csaf.TLPLabelUnlabeled},
	}
}

func doRequest(t *testing.T, q Querier, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	handler := NewController(testConfig(), q).Handler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, target, nil)
	handler.ServeHTTP(rec, req)
	return rec
}

func TestHealthOK(t *testing.T) {
	ingest := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)
	rec := doRequest(t, &fakeQuerier{lastIngest: ingest, lastIngestOK: true}, http.MethodGet, "/api/health")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body healthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body.Status != "ok" || body.Database != "reachable" {
		t.Errorf("unexpected health body: %+v", body)
	}
	if body.LastIngest == nil || !body.LastIngest.Equal(ingest) {
		t.Errorf("last ingest = %v, want %v", body.LastIngest, ingest)
	}
}

func TestHealthDBDown(t *testing.T) {
	rec := doRequest(t, &fakeQuerier{pingErr: errors.New("connection refused")}, http.MethodGet, "/api/health")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestListAdvisoriesPassesBoundedOptions(t *testing.T) {
	q := &fakeQuerier{list: database.AdvisoryList{Total: 0, Advisories: nil}}
	rec := doRequest(t, q, http.MethodGet, "/api/advisories?limit=500&offset=10&sort=critical:asc")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if q.gotOpts.Limit != maxLimit {
		t.Errorf("limit = %d, want clamped to %d", q.gotOpts.Limit, maxLimit)
	}
	if q.gotOpts.Offset != 10 {
		t.Errorf("offset = %d, want 10", q.gotOpts.Offset)
	}
	if q.gotOpts.Sort != database.SortCritical || q.gotOpts.Descending {
		t.Errorf("sort = %v desc=%v, want critical asc", q.gotOpts.Sort, q.gotOpts.Descending)
	}
	// Defense-in-depth: the publishable TLP set must reach the query, with WHITE
	// expanded to also accept the TLP 2.0 CLEAR spelling.
	if !contains(q.gotPublishable, "WHITE") || !contains(q.gotPublishable, "CLEAR") {
		t.Errorf("publishable set %v must contain WHITE and CLEAR", q.gotPublishable)
	}
}

func TestListAdvisoriesDefaults(t *testing.T) {
	q := &fakeQuerier{}
	doRequest(t, q, http.MethodGet, "/api/advisories")
	if q.gotOpts.Limit != defaultLimit {
		t.Errorf("default limit = %d, want %d", q.gotOpts.Limit, defaultLimit)
	}
	if q.gotOpts.Sort != database.SortCurrentReleaseDate || !q.gotOpts.Descending {
		t.Errorf("default sort = %v desc=%v, want current_release_date desc",
			q.gotOpts.Sort, q.gotOpts.Descending)
	}
}

func TestListAdvisoriesRejectsBadParams(t *testing.T) {
	cases := []string{
		"/api/advisories?limit=-1",
		"/api/advisories?offset=abc",
		"/api/advisories?sort=document",
		"/api/advisories?sort=critical:sideways",
	}
	for _, target := range cases {
		rec := doRequest(t, &fakeQuerier{}, http.MethodGet, target)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", target, rec.Code)
		}
	}
}

func TestGetDocumentVerbatim(t *testing.T) {
	raw := []byte(`{"document":{"title":"x"}}`)
	q := &fakeQuerier{doc: raw}
	rec := doRequest(t, q, http.MethodGet, "/api/documents/42")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	if got := rec.Body.String(); got != string(raw) {
		t.Errorf("body = %q, want verbatim %q", got, raw)
	}
	if q.gotDocID != 42 {
		t.Errorf("doc id = %d, want 42", q.gotDocID)
	}
}

func TestGetDocumentNotFound(t *testing.T) {
	q := &fakeQuerier{docErr: database.ErrDocumentNotFound}
	rec := doRequest(t, q, http.MethodGet, "/api/documents/7")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestGetDocumentBadID(t *testing.T) {
	rec := doRequest(t, &fakeQuerier{}, http.MethodGet, "/api/documents/not-a-number")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func contains(s []string, v string) bool {
	for _, item := range s {
		if item == v {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// C-4 / SA-18 — API security headers (task 22 hardening)
// securityHeaders() middleware must be present on every response produced by
// the wired handler (NewController(...).Handler()), not just in isolation.
// ---------------------------------------------------------------------------

func TestSecurityHeaderNosniffOnHealth(t *testing.T) {
	rec := doRequest(t, &fakeQuerier{lastIngestOK: false}, http.MethodGet, "/api/health")
	got := rec.Header().Get("X-Content-Type-Options")
	if got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want %q", got, "nosniff")
	}
}

func TestSecurityHeaderNosniffOnAdvisoryList(t *testing.T) {
	q := &fakeQuerier{list: database.AdvisoryList{Total: 0}}
	rec := doRequest(t, q, http.MethodGet, "/api/advisories")
	got := rec.Header().Get("X-Content-Type-Options")
	if got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want %q", got, "nosniff")
	}
}

func TestSecurityHeaderNosniffOnDocumentEndpoint(t *testing.T) {
	raw := []byte(`{"document":{"title":"test"}}`)
	q := &fakeQuerier{doc: raw}
	rec := doRequest(t, q, http.MethodGet, "/api/documents/1")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// SA-18: nosniff must be present on the document endpoint — CSAF JSON must
	// never be re-interpreted as text/html by a browser, which could enable XSS
	// if the content happened to include HTML-like text.
	got := rec.Header().Get("X-Content-Type-Options")
	if got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want %q", got, "nosniff")
	}
	// The Content-Type must be application/json (never text/html).
	ct := rec.Header().Get("Content-Type")
	if ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json; charset=utf-8")
	}
}

func TestSecurityHeaderNosniffOnNotFound(t *testing.T) {
	// Even 404 responses must carry the header — the middleware fires before
	// any response is written and must not be bypassed by early returns.
	q := &fakeQuerier{docErr: database.ErrDocumentNotFound}
	rec := doRequest(t, q, http.MethodGet, "/api/documents/999")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	got := rec.Header().Get("X-Content-Type-Options")
	if got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want %q", got, "nosniff")
	}
}
