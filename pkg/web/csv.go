// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package web

import (
	"encoding/csv"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/securityportal/securityportal-api/pkg/database"
)

// csvGuardChars is the set of leading characters that spreadsheet applications
// (Excel, LibreOffice Calc, Google Sheets) interpret as formula triggers. Any
// CSV cell whose value begins with one of these characters is prefixed with a
// single quote to force literal treatment (C-33/SA-48). TAB (0x09) and CR
// (0x0D) are also triggering at position 0.
//
// Reference: OWASP CSV-Injection (CWE-1236).
const csvGuardChars = "=+-@\x09\x0D"

// csvHeaders lists the columns emitted in the advisory CSV export, in order.
// These correspond to the Advisory projection columns from the database layer.
// No _links, no document body — list columns only (SA-49/C-33).
var csvHeaders = []string{
	"tracking_id",
	"publisher_name",
	"title",
	"current_release_date",
	"initial_release_date",
	"tlp",
	"category",
	"critical",
	"cvss_v2_score",
	"cvss_v3_score",
	"lang",
	"tracking_status",
	"version",
	"cves",
}

// writeAdvisoryCSV streams the advisory list as RFC-4180 CSV to the response.
// It applies OWASP CSV-injection cell-prefixing (C-33/SA-48) and serves the
// response as text/csv with a Content-Disposition: attachment header.
//
// CSV is offered ONLY on the list/publisher-collection endpoints (SA-49).
// Verbatim CSAF document endpoints always ignore format=csv and return JSON;
// this function is never called from those handlers.
func writeAdvisoryCSV(ctx *gin.Context, advisories []database.Advisory) {
	ctx.Header("Content-Type", "text/csv; charset=utf-8")
	ctx.Header("Content-Disposition", "attachment; filename=\"advisories.csv\"")
	ctx.Status(http.StatusOK)

	w := csv.NewWriter(ctx.Writer)

	if err := w.Write(csvHeaders); err != nil {
		slog.Error("writing CSV header failed", "error", err)
		return
	}

	for _, adv := range advisories {
		row := advisoryToCSVRow(adv)
		if err := w.Write(row); err != nil {
			slog.Error("writing CSV row failed", "tracking_id", adv.TrackingID, "error", err)
			return
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		slog.Error("flushing CSV writer failed", "error", err)
	}
}

// advisoryToCSVRow converts one Advisory to a slice of strings in the same
// column order as csvHeaders. Nullable fields are serialised as an empty string
// when nil. The CVE list is joined with a semicolon so it fits a single cell.
func advisoryToCSVRow(adv database.Advisory) []string {
	return []string{
		guardCSVCell(adv.TrackingID),
		guardCSVCell(csvDerefString(adv.PublisherName)),
		guardCSVCell(csvDerefString(adv.Title)),
		guardCSVCell(csvFormatTime(adv.CurrentReleaseDate)),
		guardCSVCell(csvFormatTime(adv.InitialReleaseDate)),
		guardCSVCell(csvDerefString(adv.TLP)),
		guardCSVCell(csvDerefString(adv.Category)),
		guardCSVCell(csvFormatFloat(adv.Critical)),
		guardCSVCell(csvFormatFloat(adv.CVSSv2Score)),
		guardCSVCell(csvFormatFloat(adv.CVSSv3Score)),
		guardCSVCell(csvDerefString(adv.Lang)),
		guardCSVCell(csvDerefString(adv.TrackingStatus)),
		guardCSVCell(csvDerefString(adv.Version)),
		guardCSVCell(strings.Join(adv.CVEs, ";")),
	}
}

// guardCSVCell applies OWASP CSV-injection neutralisation: any cell value that
// begins with a formula-triggering character (`=`, `+`, `-`, `@`) or a TAB or
// CR byte is prefixed with a single quote so spreadsheets treat it as text
// (C-33/SA-48). The encoding/csv writer handles RFC-4180 quoting for commas,
// double-quotes, and embedded newlines within the cell value.
func guardCSVCell(v string) string {
	if v == "" || !strings.ContainsRune(csvGuardChars, rune(v[0])) {
		return v
	}
	return "'" + v
}

// csvDerefString returns the pointed-to string or "" for a nil pointer.
func csvDerefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// csvFormatTime formats a time pointer as RFC 3339, or "" when nil.
func csvFormatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

// csvFormatFloat formats a float64 pointer with minimal decimal representation,
// or "" when nil.
func csvFormatFloat(f *float64) string {
	if f == nil {
		return ""
	}
	return strconv.FormatFloat(*f, 'f', -1, 64)
}
