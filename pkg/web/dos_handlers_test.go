// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package web

// Task-26 (C-7 / R-4) — offset-cap guard for the advisory list endpoints.
//
// These are fast, no-docker handler-level tests using the fakeQuerier harness
// already established in handlers_test.go. They pin the boundary semantics
// documented in handlers.go (maxOffset = 10000):
//
//   offset > maxOffset  → 400 with the documented error message
//   offset = maxOffset  → 200 (boundary is inclusive)
//   normal small offset → 200
//
// Both the primary list route (/api/advisories) and the search alias
// (/api/advisories/search) are covered because they share parseListOptions
// and must behave identically.

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestOffsetCapRejectsAboveMaxOnListEndpoint asserts that offset=10001
// (one above the documented maxOffset of 10000) is rejected with 400 and
// the exact error message the handler is specified to emit.
func TestOffsetCapRejectsAboveMaxOnListEndpoint(t *testing.T) {
	rec := doRequest(t, &fakeQuerier{}, http.MethodGet,
		"/api/advisories?offset=10001")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("offset=10001: status = %d, want 400", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding error body: %v", err)
	}
	want := "offset exceeds maximum (10000); use cursor pagination for deep pages"
	if body["error"] != want {
		t.Errorf("error = %q, want %q", body["error"], want)
	}
}

// TestOffsetCapRejectsLargeOffsetOnListEndpoint asserts that a very large
// offset (999999) — a recognisable DoS pattern — is also rejected.
func TestOffsetCapRejectsLargeOffsetOnListEndpoint(t *testing.T) {
	rec := doRequest(t, &fakeQuerier{}, http.MethodGet,
		"/api/advisories?offset=999999")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("offset=999999: status = %d, want 400", rec.Code)
	}
}

// TestOffsetCapAllowsBoundaryOnListEndpoint asserts that offset=10000 (at
// the documented boundary: > maxOffset is the rejection condition, not >=)
// is accepted and the query is forwarded to the store.
func TestOffsetCapAllowsBoundaryOnListEndpoint(t *testing.T) {
	q := &fakeQuerier{}
	rec := doRequest(t, q, http.MethodGet,
		"/api/advisories?offset=10000")
	if rec.Code != http.StatusOK {
		t.Fatalf("offset=10000: status = %d, want 200 (boundary is inclusive)", rec.Code)
	}
	if q.gotOpts.Offset != 10000 {
		t.Errorf("forwarded offset = %d, want 10000", q.gotOpts.Offset)
	}
}

// TestOffsetCapAllowsNormalOffsetOnListEndpoint asserts that a small,
// ordinary offset (e.g. offset=25, second page) is accepted normally.
func TestOffsetCapAllowsNormalOffsetOnListEndpoint(t *testing.T) {
	q := &fakeQuerier{}
	rec := doRequest(t, q, http.MethodGet,
		"/api/advisories?offset=25")
	if rec.Code != http.StatusOK {
		t.Fatalf("offset=25: status = %d, want 200", rec.Code)
	}
	if q.gotOpts.Offset != 25 {
		t.Errorf("forwarded offset = %d, want 25", q.gotOpts.Offset)
	}
}

// TestOffsetCapRejectsAboveMaxOnSearchAlias verifies that the
// /api/advisories/search alias (which shares parseListOptions) enforces
// the same offset cap — offset=10001 on the alias must also be 400.
func TestOffsetCapRejectsAboveMaxOnSearchAlias(t *testing.T) {
	rec := doRequest(t, &fakeQuerier{}, http.MethodGet,
		"/api/advisories/search?offset=10001")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("/search offset=10001: status = %d, want 400", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding error body: %v", err)
	}
	want := "offset exceeds maximum (10000); use cursor pagination for deep pages"
	if body["error"] != want {
		t.Errorf("error = %q, want %q", body["error"], want)
	}
}

// TestOffsetCapRejectsLargeOffsetOnSearchAlias verifies that 999999 on the
// search alias is also rejected.
func TestOffsetCapRejectsLargeOffsetOnSearchAlias(t *testing.T) {
	rec := doRequest(t, &fakeQuerier{}, http.MethodGet,
		"/api/advisories/search?offset=999999")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("/search offset=999999: status = %d, want 400", rec.Code)
	}
}

// TestOffsetCapAllowsBoundaryOnSearchAlias asserts that offset=10000 on
// the search alias is accepted, mirroring the list endpoint boundary test.
func TestOffsetCapAllowsBoundaryOnSearchAlias(t *testing.T) {
	q := &fakeQuerier{}
	rec := doRequest(t, q, http.MethodGet,
		"/api/advisories/search?offset=10000")
	if rec.Code != http.StatusOK {
		t.Fatalf("/search offset=10000: status = %d, want 200 (boundary inclusive)", rec.Code)
	}
	if q.gotOpts.Offset != 10000 {
		t.Errorf("forwarded offset = %d, want 10000", q.gotOpts.Offset)
	}
}

// TestOffsetCapAllowsNormalOffsetOnSearchAlias confirms a normal offset on
// the search alias is forwarded unchanged to the store.
func TestOffsetCapAllowsNormalOffsetOnSearchAlias(t *testing.T) {
	q := &fakeQuerier{}
	rec := doRequest(t, q, http.MethodGet,
		"/api/advisories/search?offset=0")
	if rec.Code != http.StatusOK {
		t.Fatalf("/search offset=0: status = %d, want 200", rec.Code)
	}
	if q.gotOpts.Offset != 0 {
		t.Errorf("forwarded offset = %d, want 0", q.gotOpts.Offset)
	}
}
