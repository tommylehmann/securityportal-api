// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package web

import (
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/securityportal/securityportal-api/pkg/auth"
	"github.com/securityportal/securityportal-api/pkg/database"
)

// feedDefaultLimit is the default number of entries in an Atom feed (ADR-0017).
// feedMaxLimit is the upper bound; requests above this are clamped.
const (
	feedDefaultLimit = 25
	feedMaxLimit     = 100
)

// atomFeed is the top-level Atom 1.0 feed document. All text content is
// marshalled via encoding/xml so every advisory-derived value is XML-escaped
// automatically (C-30/SA-44 — no manual string concatenation of XML).
type atomFeed struct {
	XMLName xml.Name    `xml:"feed"`
	XMLNS   string      `xml:"xmlns,attr"`
	ID      string      `xml:"id"`
	Title   atomText    `xml:"title"`
	Updated string      `xml:"updated"`
	Link    []atomLink  `xml:"link"`
	Entries []atomEntry `xml:"entry"`
}

// atomEntry is one Atom <entry> element. The content field is deliberately
// absent — no advisory free text or HTML is included (C-30/SA-45).
type atomEntry struct {
	ID        string     `xml:"id"`
	Title     atomText   `xml:"title"`
	Updated   string     `xml:"updated"`
	Published string     `xml:"published"`
	Link      []atomLink `xml:"link"`
	Summary   atomText   `xml:"summary"`
}

// atomText carries an Atom text construct. type="text" means the value is
// plain text; encoding/xml escapes <, &, > automatically so no advisory text
// can break out of the element (C-30/SA-44).
type atomText struct {
	Type  string `xml:"type,attr,omitempty"`
	Value string `xml:",chardata"`
}

// atomLink is an Atom link element (rel + href).
type atomLink struct {
	Rel  string `xml:"rel,attr,omitempty"`
	Href string `xml:"href,attr"`
	Type string `xml:"type,attr,omitempty"`
}

// globalFeed serves GET /api/feed.atom — the global Atom 1.0 feed of the most
// recent publishable non-withdrawn advisories, sourced through the same gated
// query path as the list endpoint (C-31/SA-46).
func (c *Controller) globalFeed(ctx *gin.Context) {
	c.serveFeed(ctx, "")
}

// publisherFeed serves GET /api/advisories/:publisher/feed.atom — an Atom feed
// scoped to one publisher (ADR-0017). An unknown publisher yields an empty but
// valid feed (ADR-0017 §2 / OQ-17 choice — not 404).
func (c *Controller) publisherFeed(ctx *gin.Context) {
	pub := ctx.Param("publisher")
	// C-27/SA-43: reject overlong publisher segment before any DB call.
	if len(pub) > maxSegmentBytes {
		badRequest(ctx, "publisher segment too long")
		return
	}
	c.serveFeed(ctx, pub)
}

// serveFeed is the shared Atom feed builder. When publisher is non-empty the
// query is scoped to that publisher; otherwise it covers the full corpus.
//
// Security controls applied here:
//   - C-31/SA-46: uses ListAdvisories with the same principal.AllowedTLP() /
//     newFilteredWhere invariants as the list endpoint — latest, not withdrawn,
//     publishable TLP. No hand-rolled query that could bypass the gate.
//   - C-30/SA-44: all feed text marshalled via encoding/xml (struct tags +
//     chardata), never string-concatenated into XML. Title/CVEs/publisher
//     containing <, &, ]], control chars are automatically escaped.
//   - C-30/SA-45: no <content> element; <summary> carries only
//     title + CVE list + severity — no advisory free text.
//   - C-32/SA-47: served as application/atom+xml; charset=utf-8, nosniff,
//     entry count bounded to feedMaxLimit.
func (c *Controller) serveFeed(ctx *gin.Context, publisher string) {
	limit := feedDefaultLimit
	if raw := ctx.Query("limit"); raw != "" {
		var l int
		if _, err := fmt.Sscanf(raw, "%d", &l); err != nil || l <= 0 {
			badRequest(ctx, "invalid limit")
			return
		}
		if l > feedMaxLimit {
			l = feedMaxLimit
		}
		limit = l
	}

	opts := database.ListOptions{
		Filters:    database.Filters{Publisher: publisher},
		Limit:      limit,
		Offset:     0,
		Sort:       database.SortCurrentReleaseDate,
		Descending: true,
	}

	// C-31/SA-46: source TLP from the per-request principal — same gate as the
	// list endpoint. The feed must never include non-publishable or withdrawn rows.
	principal := auth.PrincipalFromContext(ctx.Request.Context())
	list, err := c.db.ListAdvisories(ctx.Request.Context(), opts, principal.AllowedTLP())
	if err != nil {
		slog.Error("building Atom feed failed", "publisher", publisher, "error", err)
		ctx.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal error"})
		return
	}

	feed := buildAtomFeed(ctx.Request.Host, publisher, list.Advisories)

	// Marshal to XML via encoding/xml — never manual string concatenation
	// (C-30/SA-44). The xml.Header constant adds the <?xml ...?> declaration.
	out, err := xml.MarshalIndent(feed, "", "  ")
	if err != nil {
		slog.Error("marshalling Atom feed failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal error"})
		return
	}

	// C-32/SA-47: correct content-type + nosniff (nosniff already set by the
	// global securityHeaders middleware; explicit here for clarity).
	ctx.Header("Content-Type", "application/atom+xml; charset=utf-8")

	// Last-Modified = max entry updated (the most recent current_release_date
	// in the feed). Omitted when the feed is empty.
	if lastMod := feedLastModified(list.Advisories); !lastMod.IsZero() {
		ctx.Header("Last-Modified", lastMod.UTC().Format(http.TimeFormat))
	}

	// Short cache window — advisories are published at most every few hours.
	ctx.Header("Cache-Control", "public, max-age=300")

	ctx.Status(http.StatusOK)
	if _, err := ctx.Writer.WriteString(xml.Header); err != nil {
		slog.Error("writing XML header failed", "error", err)
		return
	}
	if _, err := ctx.Writer.Write(out); err != nil {
		slog.Error("writing Atom feed body failed", "error", err)
	}
}

// buildAtomFeed constructs the in-memory atomFeed struct from the advisory list.
// host is used to build absolute URIs for feed id and entry ids; it is taken
// from the incoming request, not from advisory content, so it is trusted.
//
// All advisory-derived text (title, CVEs, publisher) is placed into struct
// fields that encoding/xml marshals with automatic character escaping
// (C-30/SA-44). No fmt.Sprintf builds XML text containing advisory values.
func buildAtomFeed(host, publisher string, advisories []database.Advisory) atomFeed {
	scheme := "https"
	feedPath := "/api/feed.atom"
	if publisher != "" {
		feedPath = fmt.Sprintf("/api/advisories/%s/feed.atom", url.PathEscape(publisher))
	}
	feedURI := fmt.Sprintf("%s://%s%s", scheme, host, feedPath)

	title := "SecurityPortal advisories"
	if publisher != "" {
		// The publisher name is placed into a chardata field; encoding/xml handles
		// any <, &, etc. automatically.
		title = "SecurityPortal advisories — " + publisher
	}

	updated := time.Now().UTC().Format(time.RFC3339)
	if t := feedLastModified(advisories); !t.IsZero() {
		updated = t.UTC().Format(time.RFC3339)
	}

	entries := make([]atomEntry, 0, len(advisories))
	for _, adv := range advisories {
		entries = append(entries, buildAtomEntry(scheme, host, adv))
	}

	return atomFeed{
		XMLNS:   "http://www.w3.org/2005/Atom",
		ID:      feedURI,
		Title:   atomText{Type: "text", Value: title},
		Updated: updated,
		Link: []atomLink{
			{Rel: "self", Href: feedURI, Type: "application/atom+xml"},
		},
		Entries: entries,
	}
}

// buildAtomEntry constructs one <entry> from an Advisory row.
//
// SA-45/C-30: <summary type="text"> contains only the advisory title, the CVE
// list, and the severity bucket — no advisory free text (notes, remediation,
// acknowledgements). The entire body of the advisory is excluded.
//
// All advisory-derived strings go into chardata fields; encoding/xml escapes
// them. url.PathEscape is applied to the path segments before they are
// interpolated into the href attribute (which encoding/xml then also escapes
// as an attribute value), but the critical guarantee is the struct-marshal path:
// advisory titles containing < or & or " never appear unescaped in the output.
func buildAtomEntry(scheme, host string, adv database.Advisory) atomEntry {
	// Canonical publisher-scoped permalink is the Atom entry id (ADR-0016).
	// C-34/SA-50: the numeric documents.id is never used.
	pub := ""
	if adv.PublisherName != nil {
		pub = *adv.PublisherName
	}
	permalink := fmt.Sprintf("%s://%s/api/advisories/%s/%s",
		scheme, host,
		url.PathEscape(pub),
		url.PathEscape(adv.TrackingID))

	// Web detail permalink points at the web app (same host, /advisories path).
	// ADR-0016/ADR-0017: the web route is /advisories/{publisher}/{trackingId} —
	// both segments percent-escaped, no /api/ prefix. This is the canonical web
	// URL that the SvelteKit detail route src/routes/advisories/[publisher]/[trackingId]
	// responds on. The Atom <id> (above) uses /api/...; the <link rel="alternate">
	// uses /advisories/... — same host, same two segments, differ only by /api prefix.
	// Verified against task 55 (plan §E): the web route arity and encoding are aligned.
	webPermalink := fmt.Sprintf("%s://%s/advisories/%s/%s",
		scheme, host,
		url.PathEscape(pub),
		url.PathEscape(adv.TrackingID))

	title := adv.TrackingID
	if adv.Title != nil && *adv.Title != "" {
		title = *adv.Title
	}

	updated := ""
	if adv.CurrentReleaseDate != nil {
		updated = adv.CurrentReleaseDate.UTC().Format(time.RFC3339)
	}
	published := ""
	if adv.InitialReleaseDate != nil {
		published = adv.InitialReleaseDate.UTC().Format(time.RFC3339)
	}

	// SA-45/C-30: summary = title + CVEs + severity only.
	summary := buildEntrySummary(adv)

	return atomEntry{
		ID:        permalink,
		Title:     atomText{Type: "text", Value: title},
		Updated:   updated,
		Published: published,
		Link: []atomLink{
			{Rel: "alternate", Href: webPermalink, Type: "text/html"},
		},
		Summary: atomText{Type: "text", Value: summary},
	}
}

// buildEntrySummary constructs the plain-text <summary> for one entry.
// It contains only the advisory title, the CVE ids, and the CVSS severity
// bucket — no free text from the advisory body (SA-45/C-30).
func buildEntrySummary(adv database.Advisory) string {
	var parts []string

	if adv.Title != nil && *adv.Title != "" {
		parts = append(parts, *adv.Title)
	} else {
		parts = append(parts, adv.TrackingID)
	}

	if len(adv.CVEs) > 0 {
		parts = append(parts, "CVEs: "+strings.Join(adv.CVEs, ", "))
	}

	severity := severityLabel(adv.Critical)
	if severity != "" {
		parts = append(parts, "Severity: "+severity)
	}

	return strings.Join(parts, " | ")
}

// severityLabel maps a nullable critical (effective CVSS) score to a severity
// label using the same band thresholds as the database severity facet.
func severityLabel(critical *float64) string {
	if critical == nil {
		return ""
	}
	switch {
	case *critical == 0:
		return "None"
	case *critical < 4.0:
		return "Low"
	case *critical < 7.0:
		return "Medium"
	case *critical < 9.0:
		return "High"
	default:
		return "Critical"
	}
}

// feedLastModified returns the maximum current_release_date across all entries,
// for use as the feed's Last-Modified and <updated> values. Returns the zero
// time when the slice is empty or all dates are nil.
func feedLastModified(advisories []database.Advisory) time.Time {
	var max time.Time
	for _, adv := range advisories {
		if adv.CurrentReleaseDate != nil && adv.CurrentReleaseDate.After(max) {
			max = *adv.CurrentReleaseDate
		}
	}
	return max
}
