-- SPDX-License-Identifier: Apache-2.0
-- SPDX-FileCopyrightText: 2026 Tommy Lehmann
--
-- Seed fixture for the e2e stack test.  Inserts three advisory documents
-- directly into a migrated securityportal database so assertions can run
-- without a live CSAF Trusted Provider:
--
--   1. DE-2026-0001 (TLP WHITE, de-DE, CVSS v3 8.8 HIGH, 1 CVE) — WHITE advisory
--   2. BSI-2022-0001 (TLP WHITE, en-US, CVSS v3 5.3 MEDIUM, 1 CVE) — WHITE advisory
--   3. SEC-AMBER-0001 (TLP AMBER) — MUST NOT appear in any public API response
--
-- The generated columns (title, tlp, category, publisher_name, critical, lang,
-- version, etc.) are populated automatically by Postgres from the jsonb.
-- The insert_document trigger maintains advisories.latest_document_id.
-- The extract_cves / extract_products / extract_tsv triggers populate the facet
-- tables and the FTS vector.

-- Advisory 1 — WHITE, German, High severity
WITH a1 AS (
    INSERT INTO advisories (tracking_id, publisher)
    VALUES ('DE-2026-0001', 'Example AG')
    ON CONFLICT (tracking_id, publisher) DO UPDATE
        SET withdrawn = false, withdrawn_at = NULL
    RETURNING id
)
INSERT INTO documents (advisories_id, document)
SELECT id, '{
  "document": {
    "aggregate_severity": {"text": "Hoch"},
    "category": "csaf_security_advisory",
    "csaf_version": "2.0",
    "distribution": {"tlp": {"label": "WHITE","url": "https://www.first.org/tlp/"}},
    "lang": "de-DE",
    "notes": [
      {"category": "summary",
       "text": "Eine kritische Schwachstelle wurde in der ExampleApp gefunden.\nEin entfernter Angreifer kann beliebigen Code ausfuehren.",
       "title": "Zusammenfassung"}
    ],
    "publisher": {"category": "vendor","name": "Example AG","namespace": "https://www.example.test"},
    "title": "ExampleApp: Schwachstelle ermoeglicht Codeausfuehrung",
    "tracking": {
      "current_release_date": "2026-05-20T10:00:00.000Z",
      "id": "DE-2026-0001",
      "initial_release_date": "2026-05-20T10:00:00.000Z",
      "revision_history": [{"date": "2026-05-20T10:00:00.000Z","number": "1","summary": "Erstveroeffentlichung"}],
      "status": "final",
      "version": "1"
    }
  },
  "product_tree": {
    "branches": [
      {"category": "vendor","name": "Example AG",
       "branches": [
         {"category": "product_name","name": "ExampleApp",
          "branches": [
            {"category": "product_version","name": "2.0.0",
             "product": {"name": "ExampleApp 2.0.0","product_id": "CSAFPID-0001"}}
          ]}
       ]}
    ]
  },
  "vulnerabilities": [
    {"cve": "CVE-2026-12345",
     "notes": [{"category": "description","text": "Unzureichende Eingabevalidierung.","title": "Beschreibung"}],
     "product_status": {"known_affected": ["CSAFPID-0001"]},
     "scores": [
       {"cvss_v3": {"baseScore": 8.8,"baseSeverity": "HIGH",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H","version": "3.1"},
        "products": ["CSAFPID-0001"]}
     ]}
  ]
}'::jsonb
FROM a1;

-- Advisory 2 — WHITE, English, Medium severity
WITH a2 AS (
    INSERT INTO advisories (tracking_id, publisher)
    VALUES ('BSI-2022-0001', 'Bundesamt fuer Sicherheit in der Informationstechnik')
    ON CONFLICT (tracking_id, publisher) DO UPDATE
        SET withdrawn = false, withdrawn_at = NULL
    RETURNING id
)
INSERT INTO documents (advisories_id, document)
SELECT id, '{
  "document": {
    "aggregate_severity": {"text": "Moderate"},
    "category": "csaf_security_advisory",
    "csaf_version": "2.0",
    "distribution": {"tlp": {"label": "WHITE","url": "https://www.first.org/tlp/"}},
    "lang": "en-US",
    "publisher": {
      "category": "coordinator",
      "name": "Bundesamt fuer Sicherheit in der Informationstechnik",
      "namespace": "https://www.bsi.bund.de"
    },
    "title": "CVRF-CSAF-Converter: XML External Entities Vulnerability",
    "tracking": {
      "current_release_date": "2022-04-06T10:00:00.000Z",
      "id": "BSI-2022-0001",
      "initial_release_date": "2022-04-06T10:00:00.000Z",
      "revision_history": [{"date": "2022-04-06T10:00:00.000Z","number": "1","summary": "Initial revision"}],
      "status": "final",
      "version": "1"
    }
  },
  "product_tree": {
    "branches": [
      {"category": "vendor","name": "CSAF Tools",
       "branches": [
         {"category": "product_name","name": "CVRF-CSAF-Converter",
          "branches": [
            {"category": "product_version","name": "1.0.0",
             "product": {"name": "CVRF-CSAF-Converter 1.0.0","product_id": "CSAFPID-0002"}}
          ]}
       ]}
    ]
  },
  "vulnerabilities": [
    {"cve": "CVE-2022-27193",
     "notes": [{"category": "description","text": "XXE vulnerability in the converter.","title": "Description"}],
     "product_status": {"known_affected": ["CSAFPID-0002"]},
     "scores": [
       {"cvss_v3": {"baseScore": 5.3,"baseSeverity": "MEDIUM",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","version": "3.1"},
        "products": ["CSAFPID-0002"]}
     ]}
  ]
}'::jsonb
FROM a2;

-- Advisory 3 — AMBER (restricted).  The ingestion TLP gate would never store
-- this, but we insert it directly to exercise the SQL-layer belt-and-suspenders
-- defense: the API must NOT return it through any endpoint.
WITH a3 AS (
    INSERT INTO advisories (tracking_id, publisher)
    VALUES ('SEC-AMBER-0001', 'Internal Security Team')
    ON CONFLICT (tracking_id, publisher) DO UPDATE
        SET withdrawn = false, withdrawn_at = NULL
    RETURNING id
)
INSERT INTO documents (advisories_id, document)
SELECT id, '{
  "document": {
    "category": "csaf_security_advisory",
    "csaf_version": "2.0",
    "distribution": {"tlp": {"label": "AMBER","url": "https://www.first.org/tlp/"}},
    "lang": "en-US",
    "publisher": {"category": "vendor","name": "Internal Security Team","namespace": "https://internal.example.test"},
    "title": "RESTRICTED: Internal vulnerability — must not be publicly visible",
    "tracking": {
      "current_release_date": "2026-06-01T10:00:00.000Z",
      "id": "SEC-AMBER-0001",
      "initial_release_date": "2026-06-01T10:00:00.000Z",
      "revision_history": [{"date": "2026-06-01T10:00:00.000Z","number": "1","summary": "Initial"}],
      "status": "final",
      "version": "1"
    }
  },
  "product_tree": {"branches": []},
  "vulnerabilities": []
}'::jsonb
FROM a3;
