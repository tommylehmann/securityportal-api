// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 SecurityPortal contributors

// Package ingest pulls CSAF advisories from the Trusted Provider, verifies
// their integrity, applies the TLP publish policy, and persists publishable
// documents. It reuses the gocsaf consumer libraries for ROLIE enumeration,
// download, and signature verification.
package ingest
