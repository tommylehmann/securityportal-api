// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package web

import (
	"fmt"
	"net/url"

	"github.com/securityportal/securityportal-api/pkg/database"
)

// CollectionLinks is the HATEOAS _links object carried by every collection
// response (GET /api/advisories and GET /api/advisories/{publisher}). It
// contains the self link and the adjacent pagination links derived from
// total/limit/offset (ADR-0015/C-34/SA-50).
//
// prev and next are omitted (nil) at the first and last page respectively so
// clients can detect the page boundaries without parsing counts themselves.
// All URLs are relative to /api.
type CollectionLinks struct {
	// Self is the URL of the current page (with its limit/offset).
	Self string `json:"self"`
	// First is the URL of the first page (offset=0, same limit).
	First string `json:"first"`
	// Prev is the URL of the previous page, or nil when this is the first page.
	Prev *string `json:"prev,omitempty"`
	// Next is the URL of the next page, or nil when this is the last page.
	Next *string `json:"next,omitempty"`
}

// RowLinks is the _links object attached to each advisory row in a collection
// response. It carries the canonical publisher-scoped permalink for that row
// so consumers never need to reconstruct the permalink from fields (C-34/SA-50).
type RowLinks struct {
	// Self is the canonical publisher-scoped permalink for this advisory:
	// /api/advisories/{publisher}/{trackingid}. Both segments are URL-encoded.
	// The numeric documents.id/advisories.id is NEVER exposed here (C-34/SA-50).
	Self string `json:"self"`
}

// AdvisoryRow is database.Advisory augmented with the computed HATEOAS _links.
// This type is used in the API wire format; the database.Advisory type remains
// DB-layer-only without HTTP concerns.
type AdvisoryRow struct {
	database.Advisory
	Links RowLinks `json:"_links"`
}

// advisoryPermalink builds the canonical publisher-scoped permalink for an
// advisory row. Both the publisher name and the tracking_id are URL-encoded so
// the resulting path is a valid, absolute-path URI segment that round-trips
// through Gin's URL-decoding without ambiguity (C-34/SA-50).
//
// A nil or empty publisher_name falls back to an empty segment; the URL is still
// valid but will not resolve via the router (the advisory is not accessible
// without a publisher name, which should not happen for a correctly ingested doc).
func advisoryPermalink(adv database.Advisory) string {
	pub := ""
	if adv.PublisherName != nil {
		pub = *adv.PublisherName
	}
	return fmt.Sprintf("/api/advisories/%s/%s",
		url.PathEscape(pub),
		url.PathEscape(adv.TrackingID))
}

// buildCollectionLinks computes the pagination _links for a collection response.
// The links are relative to /api and use the same limit as the request; offset
// is derived from total, limit, and the current offset (C-34/SA-50).
//
// baseURL is the path (and raw query) of the request URL stripped of any existing
// limit/offset parameters, so the constructed links only append the pagination
// params. It is the responsibility of the caller to strip those params first via
// paginationBaseURL.
func buildCollectionLinks(baseURL string, total int64, limit, offset int) CollectionLinks {
	self := fmt.Sprintf("%s?limit=%d&offset=%d", baseURL, limit, offset)
	first := fmt.Sprintf("%s?limit=%d&offset=%d", baseURL, limit, 0)

	var prev *string
	if offset > 0 {
		// Floor to the nearest lower multiple of limit so `prev` lands on a
		// page boundary even when the caller supplied a non-aligned offset.
		// For example: limit=25, offset=30 → prevOffset=25 (not 5).
		prevOffset := offset - limit
		if prevOffset < 0 {
			prevOffset = 0
		}
		// Align down to the page grid.
		if limit > 0 {
			prevOffset = (prevOffset / limit) * limit
		}
		s := fmt.Sprintf("%s?limit=%d&offset=%d", baseURL, limit, prevOffset)
		prev = &s
	}

	var next *string
	nextOffset := int64(offset) + int64(limit)
	if nextOffset < total {
		s := fmt.Sprintf("%s?limit=%d&offset=%d", baseURL, limit, nextOffset)
		next = &s
	}

	return CollectionLinks{
		Self:  self,
		First: first,
		Prev:  prev,
		Next:  next,
	}
}

// paginationBaseURL returns the /api-relative path of the request suitable for
// constructing pagination links. It strips the limit and offset query params
// (which the buildCollectionLinks call adds back) and preserves all other params
// (filters, sort, format) so the paginated links respect the current filter state.
func paginationBaseURL(requestPath string, rawQuery url.Values) string {
	q := make(url.Values)
	for k, vs := range rawQuery {
		if k == "limit" || k == "offset" {
			continue
		}
		q[k] = vs
	}
	if len(q) == 0 {
		return requestPath
	}
	return requestPath + "?" + q.Encode()
}

// addLinks wraps each database.Advisory row with a computed _links.self, building
// the AdvisoryRow slice for the wire response.
func addLinks(advisories []database.Advisory) []AdvisoryRow {
	rows := make([]AdvisoryRow, len(advisories))
	for i, adv := range advisories {
		rows[i] = AdvisoryRow{
			Advisory: adv,
			Links:    RowLinks{Self: advisoryPermalink(adv)},
		}
	}
	return rows
}
