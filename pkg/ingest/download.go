// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/gocsaf/csaf/v3/util"
)

// defaultMaxAdvisoryBytes bounds the size of a single advisory download so a
// malicious or misbehaving provider cannot exhaust memory by streaming an
// arbitrarily large body (the body is fully buffered to be hashed and stored).
// A file exceeding the cap is skipped and logged — fail-closed. 32 MiB is far
// above any realistic CSAF document yet small enough to be safe.
const defaultMaxAdvisoryBytes = 32 << 20

// errAdvisoryTooLarge is returned by fetchDocument when the download exceeds the
// configured size cap. It is downgraded to a skip-and-log, not a fatal error.
var errAdvisoryTooLarge = errors.New("advisory exceeds maximum allowed size")

// VerifiedAdvisory is a single CSAF advisory that passed integrity and
// signature verification. It carries the feed TLP label (needed by the
// task-7 publish gate) alongside the raw bytes and the parsed document. It is
// deliberately persistence-agnostic: this package only fetches and verifies,
// the caller decides what to store.
type VerifiedAdvisory struct {
	// TLP is the TLP label of the ROLIE feed the advisory was listed in.
	TLP csaf.TLPLabel
	// URL is the canonical location the advisory was downloaded from.
	URL string
	// Raw is the exact bytes downloaded, after they were verified against the
	// provider hashes and signature. Stored verbatim so the document can be
	// served back byte-for-byte.
	Raw []byte
	// Document is the parsed CSAF document.
	Document map[string]any
}

// AdvisoryHandler consumes a verified advisory. Returning an error aborts the
// ingestion run. Task 7 plugs persistence in here; the enumeration/verify code
// never touches the database itself.
type AdvisoryHandler func(VerifiedAdvisory) error

// Downloader enumerates the advisory files of a provider's ROLIE feeds,
// downloads each advisory, verifies its checksum and OpenPGP signature, and
// passes the verified result to a handler. Files that fail any integrity or
// signature check are skipped and logged; unverified content is never handed
// downstream.
type Downloader struct {
	client  util.Client
	keys    *crypto.KeyRing
	expr    *util.PathEval
	pmdURL  *url.URL
	pmd     any
	handler AdvisoryHandler

	// publishable reports whether a feed's TLP label may be ingested. When set,
	// non-publishable feeds are skipped before any download (defense in depth:
	// the persistence handler also gates on TLP). A nil value accepts all feeds,
	// which keeps the verification-only tests unchanged.
	publishable func(csaf.TLPLabel) bool
	// maxBytes caps the size of a single advisory download (fail-closed).
	maxBytes int64
}

// NewDownloader builds a Downloader from a loaded provider metadata. It fetches
// the provider's public OpenPGP keys (referenced from the PMD) up front so each
// advisory signature can be verified against them. A provider that lists no
// usable key yields a downloader with an empty key ring, in which case
// verification of any advisory fails and the advisory is rejected.
func NewDownloader(
	client util.Client,
	lpmd *csaf.LoadedProviderMetadata,
	pmd *csaf.ProviderMetadata,
	handler AdvisoryHandler,
) (*Downloader, error) {
	pmdURL, err := url.Parse(lpmd.URL)
	if err != nil {
		return nil, fmt.Errorf("parsing provider-metadata.json URL %q: %w", lpmd.URL, err)
	}

	keys, err := loadOpenPGPKeys(client, pmd, pmdURL)
	if err != nil {
		return nil, fmt.Errorf("loading provider OpenPGP keys: %w", err)
	}
	if keys.CountEntities() == 0 {
		// Without a key the signature of every advisory is unverifiable; refuse
		// to run rather than silently importing unverified documents.
		return nil, fmt.Errorf("provider %q exposes no usable OpenPGP keys", lpmd.URL)
	}

	return &Downloader{
		client:   client,
		keys:     keys,
		expr:     util.NewPathEval(),
		pmdURL:   pmdURL,
		pmd:      lpmd.Document,
		handler:  handler,
		maxBytes: defaultMaxAdvisoryBytes,
	}, nil
}

// SetPublishable installs a predicate that decides whether a feed's TLP label
// may be ingested. Feeds whose label is not publishable are skipped before any
// advisory is downloaded. This is an early, feed-level filter; the persistence
// handler performs the authoritative per-document TLP gate.
func (d *Downloader) SetPublishable(fn func(csaf.TLPLabel) bool) {
	d.publishable = fn
}

// Run enumerates the ROLIE feeds and processes every advisory file. The context
// cancels the run between files (the underlying gocsaf client is URL-only and
// cannot itself carry a context, so cancelation takes effect at file
// boundaries). When ageAccept is non-nil it is handed to the gocsaf file
// processor so files older than the watermark are not enumerated, turning a full
// pull into an incremental one; a nil ageAccept performs a complete enumeration.
//
// Run never skips an advisory because of its feed TLP here unless a publishable
// predicate was installed via SetPublishable; that early filter avoids
// downloading restricted feeds at all.
func (d *Downloader) Run(ctx context.Context, ageAccept func(time.Time) bool) (Summary, error) {
	sum := Summary{Complete: ageAccept == nil}

	processor := csaf.NewAdvisoryFileProcessor(d.client, d.expr, d.pmd, d.pmdURL)
	processor.AgeAccept = ageAccept

	err := processor.Process(func(label csaf.TLPLabel, files []csaf.AdvisoryFile) error {
		// Feed-level TLP gate: never download a restricted feed at all. The
		// per-document gate in the handler is still authoritative.
		if d.publishable != nil && !d.publishable(label) {
			slog.Info("skipping non-publishable feed", "tlp", label, "files", len(files))
			sum.SkippedFeed += len(files)
			return nil
		}
		for _, file := range files {
			if err := ctx.Err(); err != nil {
				return err
			}
			ok, err := d.processFile(ctx, label, file)
			if err != nil {
				return err
			}
			if ok {
				sum.Verified++
			} else {
				sum.Skipped++
			}
		}
		return nil
	})
	if err != nil {
		return sum, fmt.Errorf("enumerating advisory files: %w", err)
	}
	return sum, nil
}

// Summary counts the outcome of an ingestion run.
type Summary struct {
	// Verified is the number of advisories that passed all checks and were
	// handed to the handler.
	Verified int
	// Skipped is the number of advisories rejected for failing a checksum or
	// signature check (or that could not be downloaded).
	Skipped int
	// SkippedFeed is the number of advisories that were not downloaded because
	// their entire feed had a non-publishable TLP label.
	SkippedFeed int
	// Complete reports whether the enumeration covered every current feed file
	// (true) or was filtered by an incremental watermark (false). It is necessary
	// but NOT sufficient for the deletion sweep: it only means ageAccept was nil,
	// not that any feed actually loaded (see Health).
	Complete bool
	// Health is positive evidence that every publishable ROLIE feed loaded
	// cleanly this cycle. Only Health.EnumeratedAll proves the present-set is an
	// authoritative view of the provider; the deletion sweep keys off it.
	Health FeedHealth
}

// processFile downloads a single advisory, verifies it, and on success invokes
// the handler. It returns whether the file was verified and accepted. A
// non-nil error is reserved for fatal conditions (e.g. the handler failing);
// integrity failures are reported as a false result and logged, not as errors,
// so one bad advisory does not abort the whole run.
func (d *Downloader) processFile(
	ctx context.Context,
	label csaf.TLPLabel,
	file csaf.AdvisoryFile,
) (bool, error) {
	docURL := file.URL()

	// Pick the strongest hash the provider offers. ROLIE entries that lack any
	// hash are filtered out by the file processor, but guard anyway.
	var (
		checksum hash.Hash
		hashURL  string
	)
	switch {
	case file.SHA512URL() != "":
		checksum, hashURL = sha512.New(), file.SHA512URL()
	case file.SHA256URL() != "":
		checksum, hashURL = sha256.New(), file.SHA256URL()
	default:
		slog.Warn("skipping advisory without a hash file", "url", docURL)
		return false, nil
	}

	// Download the advisory, teeing the bytes into the hash as we read so we do
	// not have to buffer twice.
	var data bytes.Buffer
	doc, err := d.fetchDocument(docURL, io.MultiWriter(&data, checksum))
	if err != nil {
		if errors.Is(err, errAdvisoryTooLarge) {
			slog.Warn("skipping advisory: exceeds size cap",
				"url", docURL, "max_bytes", d.maxBytes)
			return false, nil
		}
		slog.Warn("skipping advisory: download failed", "url", docURL, "error", err)
		return false, nil
	}

	// Verify the checksum against the provider's hash file.
	remoteHash, err := d.loadHash(hashURL)
	if err != nil {
		slog.Warn("skipping advisory: fetching hash failed",
			"url", docURL, "hash_url", hashURL, "error", err)
		return false, nil
	}
	if !bytes.Equal(checksum.Sum(nil), remoteHash) {
		slog.Warn("skipping advisory: checksum mismatch", "url", docURL, "hash_url", hashURL)
		return false, nil
	}

	// Verify the OpenPGP signature over the exact downloaded bytes.
	if file.SignURL() == "" {
		slog.Warn("skipping advisory without a signature file", "url", docURL)
		return false, nil
	}
	if err := d.verifySignature(file.SignURL(), data.Bytes()); err != nil {
		slog.Warn("skipping advisory: signature verification failed",
			"url", docURL, "signature_url", file.SignURL(), "error", err)
		return false, nil
	}

	advisory := VerifiedAdvisory{
		TLP:      label,
		URL:      docURL,
		Raw:      bytes.Clone(data.Bytes()),
		Document: doc,
	}
	if err := d.handler(advisory); err != nil {
		return false, fmt.Errorf("handling advisory %q: %w", docURL, err)
	}
	return true, nil
}

// fetchDocument GETs the advisory JSON, copying the raw bytes into extra while
// decoding them into a map. The raw copy is what gets hash- and
// signature-verified, so it must be the unmodified response body. The body is
// read through an io.LimitReader so an oversized response is rejected rather than
// buffered without bound.
func (d *Downloader) fetchDocument(docURL string, extra io.Writer) (map[string]any, error) {
	resp, err := d.client.Get(docURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s (%d)", http.StatusText(resp.StatusCode), resp.StatusCode)
	}

	// Read at most maxBytes+1 so we can distinguish "exactly at the cap" from
	// "over the cap". The body is teed into extra (the hash + stored buffer) so
	// both see the identical bytes the decoder consumes.
	limited := io.LimitReader(resp.Body, d.maxBytes+1)
	counter := &countingReader{r: limited}
	tee := io.TeeReader(counter, extra)
	var doc map[string]any
	if err := json.NewDecoder(tee).Decode(&doc); err != nil {
		if counter.n > d.maxBytes {
			return nil, errAdvisoryTooLarge
		}
		return nil, fmt.Errorf("decoding JSON: %w", err)
	}
	// Drain any trailing bytes so the hash and the stored copy cover the full
	// response, not just the part the JSON decoder consumed.
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}
	if counter.n > d.maxBytes {
		return nil, errAdvisoryTooLarge
	}
	return doc, nil
}

// countingReader counts the bytes read through it so fetchDocument can tell when
// the size cap has been exceeded (the LimitReader stops one byte past the cap).
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// loadHash fetches a hash file and decodes its hex digest.
func (d *Downloader) loadHash(hashURL string) ([]byte, error) {
	resp, err := d.client.Get(hashURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s (%d)", http.StatusText(resp.StatusCode), resp.StatusCode)
	}
	return util.HashFromReader(resp.Body)
}

// verifySignature fetches the detached armored signature and verifies it
// against the provider's key ring over data.
func (d *Downloader) verifySignature(signURL string, data []byte) error {
	resp, err := d.client.Get(signURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s (%d)", http.StatusText(resp.StatusCode), resp.StatusCode)
	}
	armored, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	signature, err := crypto.NewPGPSignatureFromArmored(string(armored))
	if err != nil {
		return fmt.Errorf("parsing signature: %w", err)
	}
	message := crypto.NewPlainMessage(data)
	if err := d.keys.VerifyDetached(message, signature, crypto.GetUnixTime()); err != nil {
		return err
	}
	return nil
}

// loadOpenPGPKeys builds a key ring from the public OpenPGP keys referenced by
// the provider metadata, mirroring ISDuBA's source key loading: relative key
// URLs are resolved against the PMD URL, fetched, armored-decoded, and (when
// the PMD pins a fingerprint) checked against it before being added.
func loadOpenPGPKeys(
	client util.Client,
	pmd *csaf.ProviderMetadata,
	pmdURL *url.URL,
) (*crypto.KeyRing, error) {
	keys, err := crypto.NewKeyRing(nil)
	if err != nil {
		return nil, err
	}

	for i := range pmd.PGPKeys {
		key := &pmd.PGPKeys[i]
		if key.URL == nil {
			continue
		}
		keyURL, err := url.Parse(*key.URL)
		if err != nil {
			slog.Warn("invalid OpenPGP key URL", "url", *key.URL, "error", err)
			continue
		}
		if !keyURL.IsAbs() {
			keyURL = pmdURL.ResolveReference(keyURL)
		}

		resp, err := client.Get(keyURL.String())
		if err != nil {
			slog.Warn("fetching OpenPGP key failed", "url", keyURL, "error", err)
			continue
		}
		ckey, err := func() (*crypto.Key, error) {
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("%s (%d)", http.StatusText(resp.StatusCode), resp.StatusCode)
			}
			return crypto.NewKeyFromArmoredReader(resp.Body)
		}()
		if err != nil {
			slog.Warn("reading OpenPGP key failed", "url", keyURL, "error", err)
			continue
		}

		// If the PMD pins a fingerprint, the fetched key must match it.
		if key.Fingerprint != "" &&
			!strings.EqualFold(ckey.GetFingerprint(), string(key.Fingerprint)) {
			slog.Warn("OpenPGP key fingerprint mismatch",
				"url", keyURL, "expected", key.Fingerprint, "got", ckey.GetFingerprint())
			continue
		}
		if err := keys.AddKey(ckey); err != nil {
			slog.Warn("adding OpenPGP key to ring failed", "url", keyURL, "error", err)
		}
	}

	return keys, nil
}
