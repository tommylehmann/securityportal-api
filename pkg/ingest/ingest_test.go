// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package ingest

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/util"
)

// minimalCSAF is a tiny but schema-valid CSAF 2.0 advisory used as a download
// fixture. It is the verbatim body the provider serves; its hashes and
// signature are computed over these exact bytes.
const minimalCSAF = `{
  "document": {
    "category": "csaf_security_advisory",
    "csaf_version": "2.0",
    "publisher": {
      "category": "vendor",
      "name": "ACME Inc",
      "namespace": "https://example.com"
    },
    "title": "ACME Test Advisory",
    "tracking": {
      "current_release_date": "2026-01-01T00:00:00Z",
      "id": "ACME-2026-0001",
      "initial_release_date": "2026-01-01T00:00:00Z",
      "revision_history": [
        {
          "date": "2026-01-01T00:00:00Z",
          "number": "1",
          "summary": "Initial release"
        }
      ],
      "status": "final",
      "version": "1"
    }
  }
}`

// testProvider is an in-memory CSAF Trusted Provider served via httptest. It
// signs the advisory with a freshly generated key whose public half is exposed
// through the provider-metadata.json, mirroring a real provider layout.
type testProvider struct {
	server   *httptest.Server
	signKey  *crypto.KeyRing // private key ring used to sign advisories
	pubArmor string          // armored public key served at /openpgp/pubkey.asc
	advisory string          // advisory body served at the ROLIE "self" URL
	sigArmor string          // armored detached signature served at the ".asc" URL
	// tamperHash, when true, makes the served .sha256/.sha512 not match the body.
	tamperHash bool
	// breakSig, when true, serves a signature over different bytes than the body.
	breakSig bool
	// wrongKeySigner, when non-nil, is used to sign the advisory instead of
	// signKey. The provider still publishes signKey's public half in its PMD, so
	// the signature is valid in isolation but made by a key the consumer does not
	// trust.
	wrongKeySigner *crypto.KeyRing
	// sigStatus, when non-zero, overrides the HTTP status returned for the
	// ".asc" signature file (e.g. 404 to simulate a missing signature).
	sigStatus int
	// hashStatus, when non-zero, overrides the HTTP status returned for the
	// hash files (e.g. 404 to simulate a missing checksum).
	hashStatus int
	// sha256Only, when true, omits the sha512 hash link from the ROLIE feed so
	// the consumer must fall back to sha256.
	sha256Only bool
	// breakSHA256, when true, serves a deliberately wrong sha256 digest while
	// keeping sha512 correct. With both offered, a successful verify proves the
	// consumer preferred sha512.
	breakSHA256 bool
}

func newTestProvider(t *testing.T) *testProvider {
	t.Helper()

	key, err := crypto.GenerateKey("Test Provider", "security@example.com", "rsa", 2048)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	signRing, err := crypto.NewKeyRing(key)
	if err != nil {
		t.Fatalf("building sign key ring: %v", err)
	}
	pub, err := key.GetArmoredPublicKey()
	if err != nil {
		t.Fatalf("exporting public key: %v", err)
	}

	tp := &testProvider{
		signKey:  signRing,
		pubArmor: pub,
		advisory: minimalCSAF,
	}
	// A TLS server is required because the gocsaf PMD loader only loads a URL
	// directly when it starts with "https://"; otherwise it probes well-known
	// and security.txt paths.
	tp.server = httptest.NewTLSServer(http.HandlerFunc(tp.handle))
	t.Cleanup(tp.server.Close)
	return tp
}

func (tp *testProvider) url() string { return tp.server.URL }

// client returns a util.Client that trusts the test server's TLS certificate.
func (tp *testProvider) client() util.Client {
	return tp.server.Client()
}

func (tp *testProvider) handle(w http.ResponseWriter, r *http.Request) {
	base := tp.server.URL
	switch r.URL.Path {
	case "/provider-metadata.json":
		fmt.Fprintf(w, providerMetadataTemplate, base, base, base)
	case "/openpgp/pubkey.asc":
		fmt.Fprint(w, tp.pubArmor)
	case "/white/feed.json":
		tmpl := rolieFeedTemplate
		if tp.sha256Only {
			tmpl = rolieFeedSHA256OnlyTemplate
		}
		fmt.Fprintf(w, tmpl, base)
	case "/white/advisory.json":
		fmt.Fprint(w, tp.advisory)
	case "/white/advisory.json.sha256":
		if tp.hashStatus != 0 {
			w.WriteHeader(tp.hashStatus)
			return
		}
		body := tp.advisory
		if tp.tamperHash || tp.breakSHA256 {
			body = "tampered"
		}
		sum := sha256.Sum256([]byte(body))
		fmt.Fprintf(w, "%s  advisory.json\n", hex.EncodeToString(sum[:]))
	case "/white/advisory.json.sha512":
		if tp.hashStatus != 0 {
			w.WriteHeader(tp.hashStatus)
			return
		}
		body := tp.advisory
		if tp.tamperHash {
			body = "tampered"
		}
		sum := sha512.Sum512([]byte(body))
		fmt.Fprintf(w, "%s  advisory.json\n", hex.EncodeToString(sum[:]))
	case "/white/advisory.json.asc":
		if tp.sigStatus != 0 {
			w.WriteHeader(tp.sigStatus)
			return
		}
		signed := tp.advisory
		if tp.breakSig {
			signed = tp.advisory + " "
		}
		// The signature is computed lazily so tests can flip breakSig first.
		fmt.Fprint(w, tp.signOnce(signed))
	default:
		http.NotFound(w, r)
	}
}

// signOnce signs body, caching the result for repeated requests. When the
// provider is configured with a wrongKeySigner, that key signs the body instead
// of the key whose public half the PMD publishes.
func (tp *testProvider) signOnce(body string) string {
	if tp.sigArmor != "" {
		return tp.sigArmor
	}
	signer := tp.signKey
	if tp.wrongKeySigner != nil {
		signer = tp.wrongKeySigner
	}
	sig, err := signer.SignDetached(crypto.NewPlainMessage([]byte(body)))
	if err != nil {
		return ""
	}
	armored, err := sig.GetArmored()
	if err != nil {
		return ""
	}
	tp.sigArmor = armored
	return armored
}

const providerMetadataTemplate = `{
  "canonical_url": "%s/provider-metadata.json",
  "distributions": [
    {
      "rolie": {
        "feeds": [
          {
            "summary": "TLP:WHITE advisories",
            "tlp_label": "WHITE",
            "url": "%s/white/feed.json"
          }
        ]
      }
    }
  ],
  "last_updated": "2026-01-01T00:00:00Z",
  "list_on_CSAF_aggregators": true,
  "metadata_version": "2.0",
  "mirror_on_CSAF_aggregators": true,
  "public_openpgp_keys": [
    {
      "url": "%s/openpgp/pubkey.asc"
    }
  ],
  "publisher": {
    "category": "vendor",
    "name": "ACME Inc",
    "namespace": "https://example.com",
    "contact_details": "mailto:security@example.com"
  },
  "role": "csaf_trusted_provider"
}`

const rolieFeedTemplate = `{
  "feed": {
    "id": "white",
    "title": "TLP:WHITE advisories",
    "link": [{"rel": "self", "href": "%[1]s/white/feed.json"}],
    "category": [{"scheme": "urn:ietf:params:rolie:category:information-type", "term": "csaf"}],
    "updated": "2026-01-01T00:00:00Z",
    "entry": [
      {
        "id": "ACME-2026-0001",
        "title": "ACME Test Advisory",
        "published": "2026-01-01T00:00:00Z",
        "updated": "2026-01-01T00:00:00Z",
        "link": [
          {"rel": "self", "href": "%[1]s/white/advisory.json"},
          {"rel": "hash", "href": "%[1]s/white/advisory.json.sha256"},
          {"rel": "hash", "href": "%[1]s/white/advisory.json.sha512"},
          {"rel": "signature", "href": "%[1]s/white/advisory.json.asc"}
        ],
        "format": {"schema": "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json", "version": "2.0"},
        "content": {"type": "application/json", "src": "%[1]s/white/advisory.json"}
      }
    ]
  }
}`

// rolieFeedSHA256OnlyTemplate is a ROLIE feed that lists only a sha256 hash
// link (no sha512), so the consumer must verify against sha256.
const rolieFeedSHA256OnlyTemplate = `{
  "feed": {
    "id": "white",
    "title": "TLP:WHITE advisories",
    "link": [{"rel": "self", "href": "%[1]s/white/feed.json"}],
    "category": [{"scheme": "urn:ietf:params:rolie:category:information-type", "term": "csaf"}],
    "updated": "2026-01-01T00:00:00Z",
    "entry": [
      {
        "id": "ACME-2026-0001",
        "title": "ACME Test Advisory",
        "published": "2026-01-01T00:00:00Z",
        "updated": "2026-01-01T00:00:00Z",
        "link": [
          {"rel": "self", "href": "%[1]s/white/advisory.json"},
          {"rel": "hash", "href": "%[1]s/white/advisory.json.sha256"},
          {"rel": "signature", "href": "%[1]s/white/advisory.json.asc"}
        ],
        "format": {"schema": "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json", "version": "2.0"},
        "content": {"type": "application/json", "src": "%[1]s/white/advisory.json"}
      }
    ]
  }
}`

func TestLoadProviderMetadata(t *testing.T) {
	tp := newTestProvider(t)
	client := tp.client()

	lpmd, pmd, err := LoadProviderMetadata(client, tp.url()+"/provider-metadata.json")
	if err != nil {
		t.Fatalf("LoadProviderMetadata: %v", err)
	}
	if !lpmd.Valid() {
		t.Fatal("expected a valid PMD")
	}
	if len(pmd.PGPKeys) != 1 {
		t.Fatalf("expected 1 PGP key, got %d", len(pmd.PGPKeys))
	}
	if len(pmd.Distributions) != 1 {
		t.Fatalf("expected 1 distribution, got %d", len(pmd.Distributions))
	}
}

func TestLoadProviderMetadataInvalidURL(t *testing.T) {
	client := newHTTPClient()
	if _, _, err := LoadProviderMetadata(client, "https://127.0.0.1:1/provider-metadata.json"); err == nil {
		t.Fatal("expected an error for an unreachable provider")
	}
}

// collect runs a full fetch-and-verify pass against a test provider and returns
// the verified advisories plus the summary.
func collect(t *testing.T, tp *testProvider) ([]VerifiedAdvisory, Summary) {
	t.Helper()
	client := tp.client()

	lpmd, pmd, err := LoadProviderMetadata(client, tp.url()+"/provider-metadata.json")
	if err != nil {
		t.Fatalf("LoadProviderMetadata: %v", err)
	}

	var got []VerifiedAdvisory
	dl, err := NewDownloader(client, lpmd, pmd, func(va VerifiedAdvisory) error {
		got = append(got, va)
		return nil
	})
	if err != nil {
		t.Fatalf("NewDownloader: %v", err)
	}
	sum, err := dl.Run(context.Background(), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return got, sum
}

func TestDownloadAndVerifyGoodAdvisory(t *testing.T) {
	tp := newTestProvider(t)
	got, sum := collect(t, tp)

	if sum.Verified != 1 || sum.Skipped != 0 {
		t.Fatalf("expected 1 verified / 0 skipped, got %+v", sum)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 verified advisory, got %d", len(got))
	}
	va := got[0]
	if va.TLP != csaf.TLPLabel(csaf.TLPLabelWhite) {
		t.Errorf("expected WHITE TLP, got %q", va.TLP)
	}
	if string(va.Raw) != minimalCSAF {
		t.Errorf("raw bytes do not match the served advisory")
	}
	if va.Document == nil {
		t.Error("expected a parsed document")
	}
	if !strings.Contains(va.URL, "/white/advisory.json") {
		t.Errorf("unexpected advisory URL %q", va.URL)
	}
}

func TestDownloadRejectsTamperedHash(t *testing.T) {
	tp := newTestProvider(t)
	tp.tamperHash = true
	got, sum := collect(t, tp)

	if sum.Verified != 0 || sum.Skipped != 1 {
		t.Fatalf("expected 0 verified / 1 skipped, got %+v", sum)
	}
	if len(got) != 0 {
		t.Fatalf("tampered advisory must not be handed downstream, got %d", len(got))
	}
}

func TestDownloadRejectsBadSignature(t *testing.T) {
	tp := newTestProvider(t)
	tp.breakSig = true
	got, sum := collect(t, tp)

	if sum.Verified != 0 || sum.Skipped != 1 {
		t.Fatalf("expected 0 verified / 1 skipped, got %+v", sum)
	}
	if len(got) != 0 {
		t.Fatalf("advisory with a bad signature must not be handed downstream, got %d", len(got))
	}
}

func TestNewDownloaderRejectsProviderWithoutKeys(t *testing.T) {
	tp := newTestProvider(t)
	tp.pubArmor = "" // serve an empty key body so no key is added to the ring
	client := tp.client()

	lpmd, pmd, err := LoadProviderMetadata(client, tp.url()+"/provider-metadata.json")
	if err != nil {
		t.Fatalf("LoadProviderMetadata: %v", err)
	}
	if _, err := NewDownloader(client, lpmd, pmd, func(VerifiedAdvisory) error { return nil }); err == nil {
		t.Fatal("expected NewDownloader to reject a provider with no usable keys")
	}
}

// TestDownloadRejectsWrongSigningKey covers the case where the advisory hash is
// valid and the signature is internally valid, but it was made by a key the
// provider does not vouch for (it is not in the PMD-derived key ring). This must
// be rejected — a valid signature by an untrusted key is not acceptance.
func TestDownloadRejectsWrongSigningKey(t *testing.T) {
	tp := newTestProvider(t)

	// Generate an entirely separate key and sign with it. The PMD still publishes
	// only the original (trusted) key's public half.
	rogue, err := crypto.GenerateKey("Rogue", "rogue@example.com", "rsa", 2048)
	if err != nil {
		t.Fatalf("generating rogue key: %v", err)
	}
	rogueRing, err := crypto.NewKeyRing(rogue)
	if err != nil {
		t.Fatalf("building rogue key ring: %v", err)
	}
	tp.wrongKeySigner = rogueRing

	got, sum := collect(t, tp)
	if sum.Verified != 0 || sum.Skipped != 1 {
		t.Fatalf("expected 0 verified / 1 skipped, got %+v", sum)
	}
	if len(got) != 0 {
		t.Fatalf("advisory signed by an untrusted key must not be handed downstream, got %d", len(got))
	}
}

// TestDownloadRejectsMissingSignature covers a provider that lists a signature
// in its ROLIE feed but serves a 404 for the ".asc" file. Verification must fail
// closed: a missing signature is a rejection, never a silent acceptance.
func TestDownloadRejectsMissingSignature(t *testing.T) {
	tp := newTestProvider(t)
	tp.sigStatus = http.StatusNotFound

	got, sum := collect(t, tp)
	if sum.Verified != 0 || sum.Skipped != 1 {
		t.Fatalf("expected 0 verified / 1 skipped, got %+v", sum)
	}
	if len(got) != 0 {
		t.Fatalf("advisory with a missing signature must not be handed downstream, got %d", len(got))
	}
}

// TestDownloadRejectsMissingChecksum covers a provider that lists a hash in its
// ROLIE feed but serves a 404 for the hash file. Verification must fail closed.
func TestDownloadRejectsMissingChecksum(t *testing.T) {
	tp := newTestProvider(t)
	tp.hashStatus = http.StatusNotFound

	got, sum := collect(t, tp)
	if sum.Verified != 0 || sum.Skipped != 1 {
		t.Fatalf("expected 0 verified / 1 skipped, got %+v", sum)
	}
	if len(got) != 0 {
		t.Fatalf("advisory with a missing checksum must not be handed downstream, got %d", len(got))
	}
}

// TestDownloadPrefersSHA512 serves a correct sha512 alongside a deliberately
// wrong sha256. Both are offered, so a successful verify proves the consumer
// chose the stronger sha512 digest. (If it had used sha256 the run would skip.)
func TestDownloadPrefersSHA512(t *testing.T) {
	tp := newTestProvider(t)
	tp.breakSHA256 = true

	got, sum := collect(t, tp)
	if sum.Verified != 1 || sum.Skipped != 0 {
		t.Fatalf("expected 1 verified / 0 skipped (sha512 preferred), got %+v", sum)
	}
	if len(got) != 1 {
		t.Fatalf("expected the advisory to verify via sha512, got %d", len(got))
	}
}

// TestDownloadVerifiesWithSHA256Only covers a provider that offers only a sha256
// hash (no sha512). The consumer must fall back to sha256 and still verify.
func TestDownloadVerifiesWithSHA256Only(t *testing.T) {
	tp := newTestProvider(t)
	tp.sha256Only = true

	got, sum := collect(t, tp)
	if sum.Verified != 1 || sum.Skipped != 0 {
		t.Fatalf("expected 1 verified / 0 skipped (sha256-only), got %+v", sum)
	}
	if len(got) != 1 {
		t.Fatalf("expected the sha256-only advisory to verify, got %d", len(got))
	}
}

// TestRawBytesAreExactDownloadedBytes guards the integrity-critical contract
// that the bytes handed to the handler are byte-for-byte the bytes that were
// hashed and signature-verified — including any trailing bytes that the JSON
// decoder does not consume. A document body with a trailing newline catches a
// tee/drain bug where the stored copy would diverge from the verified bytes.
func TestRawBytesAreExactDownloadedBytes(t *testing.T) {
	tp := newTestProvider(t)
	// Trailing newline lives outside the top-level JSON object; the decoder stops
	// at the closing brace, so only the explicit drain captures it.
	tp.advisory = minimalCSAF + "\n"

	got, sum := collect(t, tp)
	if sum.Verified != 1 || sum.Skipped != 0 {
		t.Fatalf("expected 1 verified / 0 skipped, got %+v", sum)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 verified advisory, got %d", len(got))
	}
	if string(got[0].Raw) != tp.advisory {
		t.Errorf("raw bytes (%d) differ from the downloaded body (%d); tee/drain corruption",
			len(got[0].Raw), len(tp.advisory))
	}
}
