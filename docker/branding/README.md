<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Tommy Lehmann
-->

# Branding directory

This directory is bind-mounted read-only into the `web` container at
`/srv/branding` by the Docker Compose stack.

When all files here are absent (the default), the portal renders its built-in
icon glyph and i18n placeholder text for the legal pages — no error is raised.
Drop files here (or point `SP_BRANDING_DIR` at another host path in `.env`) to
override the defaults without rebuilding any image.

These knobs are identical to the Helm chart's `branding`, `legalContent`, and
`logo` values in `values.yaml` (ADR-0012: all three deployment targets share the
same `SECURITYPORTAL_*` env-var and mount contract).

## Directory layout

```
branding/
├── README.md               (this file)
├── legal/
│   ├── .gitkeep            (keeps the directory in git; delete when adding real files)
│   ├── impressum.de.md     (German Impressum — drop here and remove .gitkeep)
│   ├── impressum.en.md     (English imprint)
│   ├── datenschutz.de.md   (German Datenschutzerklärung)
│   └── datenschutz.en.md   (English privacy policy)
└── logo.svg                (or logo.png / logo.webp — set SECURITYPORTAL_LOGO_PATH in .env)
```

## Legal Markdown files

File naming: `<page>.<locale>.md` where:
- `<page>` is `impressum` or `datenschutz`
- `<locale>` is `de` or `en`

The web app reads the file matching the visitor's locale, then falls back to the
other locale, then falls back to the built-in i18n placeholder.  A missing file
is never an error.

Content is sanitized at render time per ADR-0010: only block/inline text elements,
tables, and `<a href>` links are allowed.  Inline HTML, `<script>`, `<iframe>`,
`<img>`, `<svg>`, and `<object>` tags are stripped.  Link `href` values are
validated against an allow-list of safe URL schemes (ADR-0007).

Example files are provided as `*.md.example` — copy and rename to get started:

```bash
cp legal/impressum.de.md.example legal/impressum.de.md
```

Maximum file size: 512 KiB.  Files larger than this are silently ignored and the
placeholder is shown.

## Logo

Place an SVG, PNG, or WebP file in this directory, then set in `.env`:

```dotenv
SECURITYPORTAL_LOGO_PATH=/srv/branding/logo.svg
```

The path must be the **container-internal** path (`/srv/branding/…`), not the
host path.  When unset (default), the built-in icon glyph is shown.

Supported formats: `.svg`, `.png`, `.webp`.  Other formats (JPEG, GIF, ICO) are
not served.  SVG files are delivered as `image/svg+xml` via `<img>` (not
`innerHTML`), which neutralizes any inline JavaScript in the SVG.
