// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 SecurityPortal contributors

package ingest

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/gocsaf/csaf/v3/util"

	"github.com/securityportal/securityportal-api/pkg/config"
	"github.com/securityportal/securityportal-api/pkg/database"
)

// These integration tests close the exact gap that let review finding F1 (the
// catastrophic deletion-sweep data-loss path) slip through. The earlier
// partial-poll tests in persist_integration_test.go only covered a TOTAL
// provider-metadata.json failure (RunOnce errors out before the sweep). They
// did NOT cover the subtler, real path the reviewer found: the PMD loads fine,
// but an individual ROLIE feed fetch fails. gocsaf's processROLIE swallows that
// per-feed error and returns success with zero (or partial) files, so the old
// code ran the sweep against an empty/partial present-set and tombstoned
// everything.
//
// The fix adds a feed-health probe (checkFeedHealth) plus a defence-in-depth
// guard (maybeSweep). These tests drive that real composition — a live
// httptest TLS provider whose feed(s) fail, the real download+persist path, the
// real checkFeedHealth probe, and the real maybeSweep gate — against a live
// postgres:16-alpine. They skip cleanly when docker is absent.
//
// Why not the full RunOnce here: RunOnce builds its own newHTTPClient()
// internally, which cannot trust the httptest TLS certificate. The feed-level
// failure that F1 hinges on therefore must be exercised one seam below RunOnce,
// composing exactly what RunOnce composes (FetchAndVerify's download + health
// probe, then maybeSweep) but with an injectable TLS-trusting client. The total
// PMD-failure path through the real RunOnce is already covered in
// persist_integration_test.go.

// feedProvider is an in-memory CSAF Trusted Provider served via httptest TLS
// that advertises one or more publishable ROLIE feeds, each carrying a single
// signed advisory. Individual feeds can be made to fail (HTTP 500) to reproduce
// the silent per-feed-fetch failure that F1 hinges on.
type feedProvider struct {
	server   *httptest.Server
	signKey  *crypto.KeyRing
	pubArmor string
	// feeds is the ordered list of feed ids served (e.g. "white-a", "white-b").
	// Each feed id N exposes a feed at /<N>/feed.json listing one advisory at
	// /<N>/advisory.json with tracking id "PORTAL-<N>".
	feeds []string
	// failFeeds[id] == true makes that feed's /<id>/feed.json return HTTP 500,
	// exactly the failure gocsaf swallows.
	failFeeds map[string]bool
}

func newFeedProvider(t *testing.T, feeds ...string) *feedProvider {
	t.Helper()
	key, err := crypto.GenerateKey("Feed Provider", "security@example.com", "rsa", 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	ring, err := crypto.NewKeyRing(key)
	if err != nil {
		t.Fatalf("building key ring: %v", err)
	}
	pub, err := key.GetArmoredPublicKey()
	if err != nil {
		t.Fatalf("exporting public key: %v", err)
	}
	fp := &feedProvider{
		signKey:   ring,
		pubArmor:  pub,
		feeds:     feeds,
		failFeeds: map[string]bool{},
	}
	fp.server = httptest.NewTLSServer(http.HandlerFunc(fp.handle))
	t.Cleanup(fp.server.Close)
	return fp
}

func (fp *feedProvider) url() string         { return fp.server.URL }
func (fp *feedProvider) client() util.Client { return fp.server.Client() }

// trackingID is the advisory tracking id served by a given feed.
func feedTrackingID(feed string) string { return "PORTAL-" + strings.ToUpper(feed) }

func (fp *feedProvider) handle(w http.ResponseWriter, r *http.Request) {
	base := fp.server.URL
	switch {
	case r.URL.Path == "/provider-metadata.json":
		fp.writePMD(w, base)
	case r.URL.Path == "/openpgp/pubkey.asc":
		fmt.Fprint(w, fp.pubArmor)
	default:
		fp.handleFeedPaths(w, r, base)
	}
}

func (fp *feedProvider) handleFeedPaths(w http.ResponseWriter, r *http.Request, base string) {
	for _, feed := range fp.feeds {
		switch r.URL.Path {
		case "/" + feed + "/feed.json":
			if fp.failFeeds[feed] {
				http.Error(w, "feed temporarily unavailable", http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, rolieOneEntryFeed, base, feed, feedTrackingID(feed))
			return
		case "/" + feed + "/advisory.json":
			fmt.Fprint(w, fp.advisoryBody(feed))
			return
		case "/" + feed + "/advisory.json.sha512":
			sum := sha512.Sum512([]byte(fp.advisoryBody(feed)))
			fmt.Fprintf(w, "%s  advisory.json\n", hex.EncodeToString(sum[:]))
			return
		case "/" + feed + "/advisory.json.asc":
			fmt.Fprint(w, fp.signOnce(fp.advisoryBody(feed)))
			return
		}
	}
	http.NotFound(w, r)
}

// advisoryBody returns a schema-valid TLP:WHITE CSAF advisory whose tracking id
// is derived from the feed, so each feed contributes a distinct advisory.
func (fp *feedProvider) advisoryBody(feed string) string {
	return fmt.Sprintf(whiteAdvisoryTemplate, feedTrackingID(feed))
}

func (fp *feedProvider) signOnce(body string) string {
	sig, err := fp.signKey.SignDetached(crypto.NewPlainMessage([]byte(body)))
	if err != nil {
		return ""
	}
	armored, err := sig.GetArmored()
	if err != nil {
		return ""
	}
	return armored
}

func (fp *feedProvider) writePMD(w http.ResponseWriter, base string) {
	var feedsJSON strings.Builder
	for i, feed := range fp.feeds {
		if i > 0 {
			feedsJSON.WriteString(",\n")
		}
		fmt.Fprintf(&feedsJSON, `          {
            "summary": "TLP:WHITE advisories (%[2]s)",
            "tlp_label": "WHITE",
            "url": "%[1]s/%[2]s/feed.json"
          }`, base, feed)
	}
	fmt.Fprintf(w, pmdMultiFeedTemplate, base, feedsJSON.String())
}

const pmdMultiFeedTemplate = `{
  "canonical_url": "%[1]s/provider-metadata.json",
  "distributions": [
    {
      "rolie": {
        "feeds": [
%[2]s
        ]
      }
    }
  ],
  "last_updated": "2026-01-01T00:00:00Z",
  "list_on_CSAF_aggregators": true,
  "metadata_version": "2.0",
  "mirror_on_CSAF_aggregators": true,
  "public_openpgp_keys": [
    {"url": "%[1]s/openpgp/pubkey.asc"}
  ],
  "publisher": {
    "category": "vendor",
    "name": "ACME Inc",
    "namespace": "https://example.com",
    "contact_details": "mailto:security@example.com"
  },
  "role": "csaf_trusted_provider"
}`

// rolieOneEntryFeed is a ROLIE feed (%[1]s base, %[2]s feed id, %[3]s tracking
// id) with a single advisory listing a sha512 hash and a signature.
const rolieOneEntryFeed = `{
  "feed": {
    "id": "%[2]s",
    "title": "TLP:WHITE advisories",
    "link": [{"rel": "self", "href": "%[1]s/%[2]s/feed.json"}],
    "category": [{"scheme": "urn:ietf:params:rolie:category:information-type", "term": "csaf"}],
    "updated": "2026-01-01T00:00:00Z",
    "entry": [
      {
        "id": "%[3]s",
        "title": "ACME Test Advisory",
        "published": "2026-01-01T00:00:00Z",
        "updated": "2026-01-01T00:00:00Z",
        "link": [
          {"rel": "self", "href": "%[1]s/%[2]s/advisory.json"},
          {"rel": "hash", "href": "%[1]s/%[2]s/advisory.json.sha512"},
          {"rel": "signature", "href": "%[1]s/%[2]s/advisory.json.asc"}
        ],
        "format": {"schema": "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json", "version": "2.0"},
        "content": {"type": "application/json", "src": "%[1]s/%[2]s/advisory.json"}
      }
    ]
  }
}`

// whiteAdvisoryTemplate is a schema-valid TLP:WHITE CSAF advisory whose tracking
// id is %[1]s.
const whiteAdvisoryTemplate = `{
  "document": {
    "category": "csaf_security_advisory",
    "csaf_version": "2.0",
    "distribution": {"tlp": {"label": "WHITE"}},
    "publisher": {
      "category": "vendor",
      "name": "ACME Inc",
      "namespace": "https://example.com"
    },
    "title": "ACME Test Advisory %[1]s",
    "tracking": {
      "current_release_date": "2026-01-01T00:00:00Z",
      "id": "%[1]s",
      "initial_release_date": "2026-01-01T00:00:00Z",
      "revision_history": [
        {"date": "2026-01-01T00:00:00Z", "number": "1", "summary": "Initial release"}
      ],
      "status": "final",
      "version": "1"
    }
  }
}`

// runCycleAgainst composes exactly what RunOnce composes — load PMD, download +
// persist via the real Persister -> *database.DB, probe feed health — but with
// the test provider's TLS-trusting client (which RunOnce's internal client
// cannot do). It returns the run Summary (including Health) and the present-set,
// ready to feed to the real maybeSweep gate.
func runCycleAgainst(t *testing.T, fp *feedProvider, db *database.DB, cfg *config.Config) (Summary, []database.AdvisoryKey) {
	t.Helper()
	client := fp.client()
	ctx := context.Background()

	lpmd, pmd, err := LoadProviderMetadata(client, fp.url()+"/provider-metadata.json")
	if err != nil {
		t.Fatalf("LoadProviderMetadata: %v", err)
	}

	persister := NewPersister(ctx, cfg, db)
	dl, err := NewDownloader(client, lpmd, pmd, persister.Handle)
	if err != nil {
		t.Fatalf("NewDownloader: %v", err)
	}
	dl.SetPublishable(cfg.IsPublishable)

	sum, err := dl.Run(ctx, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The same independent feed-health probe FetchAndVerify performs; this is the
	// positive evidence the fixed sweep keys off (never sum.Complete alone).
	sum.Health = checkFeedHealth(client, pmd, dl.pmdURL, cfg.IsPublishable)
	return sum, persister.Present()
}

// TestSilentFeedFetchFailureSkipsSweep is the F1 regression guard. The PMD loads
// fine but the single ROLIE feed returns HTTP 500, so gocsaf enumerates ZERO
// files and reports the run "complete" with no error — the exact trap that, on
// the old code, ran the sweep against an empty present-set and tombstoned the
// whole portal. The fixed code's feed-health probe must report EnumeratedAll
// false and maybeSweep must refuse to tombstone. This test FAILS on the old
// code (no health probe; empty present + Complete => mass withdrawal) and PASSES
// on the fixed code.
func TestSilentFeedFetchFailureSkipsSweep(t *testing.T) {
	db, pool, ctx := migratedStore(t)
	cfg := publishConfig()
	const publisher = "SecurityPortal Test Publisher"

	// Pre-seed advisories as if prior healthy cycles had stored them.
	seedAdvisories(t, ctx, db, publisher, "PRIOR-1", "PRIOR-2", "PRIOR-3")

	fp := newFeedProvider(t, "white")
	fp.failFeeds["white"] = true // the silent per-feed fetch failure

	sum, present := runCycleAgainst(t, fp, db, cfg)

	// The failing feed yields zero files, yet gocsaf reports the run complete.
	if !sum.Complete {
		t.Fatal("precondition: gocsaf reports the (empty) enumeration complete")
	}
	if len(present) != 0 {
		t.Fatalf("precondition: a failed feed yields an empty present-set, got %d", len(present))
	}
	// The fix: the health probe must catch the failed feed.
	if sum.Health.EnumeratedAll {
		t.Error("BLOCKER: feed health reported clean despite a failed feed fetch")
	}
	if sum.Health.Expected != 1 || sum.Health.Loaded != 0 {
		t.Errorf("feed health = %+v, want Expected=1 Loaded=0", sum.Health)
	}

	withdrawn, swept, err := maybeSweep(ctx, cfg, db, sum, present)
	if err != nil {
		t.Fatalf("maybeSweep: %v", err)
	}
	if swept || withdrawn != 0 {
		t.Errorf("BLOCKER: sweep ran on a failed feed (swept=%v withdrawn=%d)", swept, withdrawn)
	}
	for _, id := range []string{"PRIOR-1", "PRIOR-2", "PRIOR-3"} {
		if withdrawnState(t, ctx, pool, id, publisher) {
			t.Errorf("BLOCKER: %s was tombstoned by a failed-feed poll", id)
		}
	}
}

// TestPartialFeedFailurePersistsGoodDataButSkipsSweep covers the partial case:
// of several publishable feeds, one fails and the others succeed. The verified
// advisories from the healthy feeds must still be persisted, but because the
// enumeration was not provably complete, NO tombstoning happens this cycle.
func TestPartialFeedFailurePersistsGoodDataButSkipsSweep(t *testing.T) {
	db, pool, ctx := migratedStore(t)
	cfg := publishConfig()
	pubName := acmePublisher

	// Pre-seed the advisory the 'beta' feed served on a prior healthy cycle, under
	// the same (tracking_id, publisher) key the feed produces, so we can prove
	// this cycle's beta-feed failure does NOT tombstone it.
	seedAdvisories(t, ctx, db, pubName, feedTrackingID("beta"))
	if withdrawnState(t, ctx, pool, feedTrackingID("beta"), pubName) {
		t.Fatal("precondition: pre-seeded beta advisory must be published")
	}

	fp := newFeedProvider(t, "alpha", "beta", "gamma")
	fp.failFeeds["beta"] = true // one of three feeds fails

	sum, present := runCycleAgainst(t, fp, db, cfg)

	// Two healthy feeds contributed one advisory each.
	if sum.Verified != 2 {
		t.Errorf("expected 2 verified advisories from the healthy feeds, got %d", sum.Verified)
	}
	if len(present) != 2 {
		t.Errorf("present-set should hold the 2 good advisories, got %d", len(present))
	}
	// The good documents are persisted regardless of the sweep decision.
	if !advisoryStored(t, ctx, pool, feedTrackingID("alpha"), pubName) {
		t.Error("advisory from the healthy 'alpha' feed must be persisted")
	}
	if !advisoryStored(t, ctx, pool, feedTrackingID("gamma"), pubName) {
		t.Error("advisory from the healthy 'gamma' feed must be persisted")
	}

	// One of three publishable feeds failed -> enumeration is not provably
	// complete -> the sweep is skipped this cycle.
	if sum.Health.EnumeratedAll {
		t.Error("BLOCKER: feed health reported clean despite one failed feed")
	}
	if sum.Health.Expected != 3 || sum.Health.Loaded != 2 {
		t.Errorf("feed health = %+v, want Expected=3 Loaded=2", sum.Health)
	}

	withdrawn, swept, err := maybeSweep(ctx, cfg, db, sum, present)
	if err != nil {
		t.Fatalf("maybeSweep: %v", err)
	}
	if swept || withdrawn != 0 {
		t.Errorf("BLOCKER: sweep ran on a partial enumeration (swept=%v withdrawn=%d)", swept, withdrawn)
	}
	// The advisory whose feed failed must not be tombstoned even though it is
	// absent from the present-set.
	if withdrawnState(t, ctx, pool, feedTrackingID("beta"), pubName) {
		t.Error("BLOCKER: the advisory behind the failed feed was tombstoned")
	}
}

// TestHealthyCompletePollSweepsExactlyAbsent is the positive control: a fully
// healthy, complete poll where exactly one advisory in an active corpus is truly
// absent. The sweep must run, tombstone precisely that one, leave the rest
// active, and a later cycle in which it reappears must clear the marker. This
// proves the guards do not over-block a legitimate deletion.
func TestHealthyCompletePollSweepsExactlyAbsent(t *testing.T) {
	db, pool, ctx := migratedStore(t)
	cfg := publishConfig()
	const publisher = "SecurityPortal Test Publisher"

	// An active corpus large enough for the fraction guard to apply, plus the one
	// advisory we will retire.
	active := []string{"KEEP-01", "KEEP-02", "KEEP-03", "KEEP-04", "KEEP-05",
		"KEEP-06", "KEEP-07", "KEEP-08", "KEEP-09", "KEEP-10", "KEEP-11"}
	seedAdvisories(t, ctx, db, publisher, append(append([]string{}, active...), "RETIRE-ME")...)

	// A genuinely healthy, complete enumeration: the present-set covers every
	// active advisory except RETIRE-ME (truly gone from the provider).
	sum := Summary{Complete: true, Health: FeedHealth{Expected: 1, Loaded: 1, EnumeratedAll: true}}
	present := make([]database.AdvisoryKey, 0, len(active))
	for _, id := range active {
		present = append(present, database.AdvisoryKey{TrackingID: id, Publisher: publisher})
	}

	withdrawn, swept, err := maybeSweep(ctx, cfg, db, sum, present)
	if err != nil {
		t.Fatalf("maybeSweep: %v", err)
	}
	if !swept {
		t.Fatal("a healthy complete poll with a genuinely absent advisory must sweep")
	}
	if withdrawn != 1 {
		t.Errorf("expected exactly 1 advisory withdrawn, got %d", withdrawn)
	}
	if !withdrawnState(t, ctx, pool, "RETIRE-ME", publisher) {
		t.Error("the truly-absent advisory must be tombstoned")
	}
	for _, id := range active {
		if withdrawnState(t, ctx, pool, id, publisher) {
			t.Errorf("%s must remain published", id)
		}
	}

	// Reappearance clears the tombstone (un-withdraw on re-store).
	redoc := verifiedAdvisory("RETIRE-ME", publisher, "WHITE", "WHITE")
	if err := NewPersister(ctx, cfg, db).Handle(redoc); err != nil {
		t.Fatalf("re-storing reappeared advisory: %v", err)
	}
	if withdrawnState(t, ctx, pool, "RETIRE-ME", publisher) {
		t.Error("a reappearing advisory must be un-tombstoned")
	}
}

// TestEmptyPresentSetGuardSkipsSweep covers Layer 2a: even a "healthy" cycle
// (EnumeratedAll true) that legitimately yielded zero publishable documents must
// not withdraw the corpus — an empty present-set means "nothing reliably
// enumerated", never "everything is gone".
func TestEmptyPresentSetGuardSkipsSweep(t *testing.T) {
	db, pool, ctx := migratedStore(t)
	cfg := publishConfig()
	const publisher = "SecurityPortal Test Publisher"

	seedAdvisories(t, ctx, db, publisher, "STAY-1", "STAY-2")

	sum := Summary{Complete: true, Health: FeedHealth{Expected: 1, Loaded: 1, EnumeratedAll: true}}
	withdrawn, swept, err := maybeSweep(ctx, cfg, db, sum, nil)
	if err != nil {
		t.Fatalf("maybeSweep: %v", err)
	}
	if swept || withdrawn != 0 {
		t.Errorf("BLOCKER: sweep ran on an empty present-set (swept=%v withdrawn=%d)", swept, withdrawn)
	}
	for _, id := range []string{"STAY-1", "STAY-2"} {
		if withdrawnState(t, ctx, pool, id, publisher) {
			t.Errorf("BLOCKER: %s tombstoned despite an empty present-set", id)
		}
	}
}

// TestFractionGuardSkipsImplausibleMassWithdrawal covers Layer 2b: a healthy
// enumeration whose present-set would withdraw an implausibly large fraction
// (>50%) of an active corpus of at least minCorpusForFractionGuard advisories
// must be refused, withdrawing nobody, and exercising the operator-review
// warning path.
func TestFractionGuardSkipsImplausibleMassWithdrawal(t *testing.T) {
	db, pool, ctx := migratedStore(t)
	cfg := publishConfig()
	const publisher = "SecurityPortal Test Publisher"

	// 12 active advisories; a present-set covering only 1 would withdraw 11/12
	// (~92%), far past the 50% guard with the corpus above the floor.
	ids := make([]string, 12)
	for i := range ids {
		ids[i] = fmt.Sprintf("CORP-%02d", i+1)
	}
	seedAdvisories(t, ctx, db, publisher, ids...)

	if active, err := db.CountActiveAdvisories(ctx); err != nil || active != 12 {
		t.Fatalf("precondition: want 12 active advisories, got %d (err=%v)", active, err)
	}

	sum := Summary{Complete: true, Health: FeedHealth{Expected: 1, Loaded: 1, EnumeratedAll: true}}
	present := []database.AdvisoryKey{{TrackingID: ids[0], Publisher: publisher}}

	withdrawn, swept, err := maybeSweep(ctx, cfg, db, sum, present)
	if err != nil {
		t.Fatalf("maybeSweep: %v", err)
	}
	if swept || withdrawn != 0 {
		t.Errorf("BLOCKER: sweep withdrew an implausible fraction (swept=%v withdrawn=%d)", swept, withdrawn)
	}
	for _, id := range ids {
		if withdrawnState(t, ctx, pool, id, publisher) {
			t.Errorf("BLOCKER: %s tombstoned despite the fraction guard", id)
		}
	}
}

// seedAdvisories stores one publishable WHITE advisory per tracking id through
// the real persistence path, modelling the result of a prior healthy cycle.
func seedAdvisories(t *testing.T, ctx context.Context, db *database.DB, publisher string, trackingIDs ...string) {
	t.Helper()
	p := NewPersister(ctx, publishConfig(), db)
	for _, id := range trackingIDs {
		if err := p.Handle(verifiedAdvisory(id, publisher, "WHITE", "WHITE")); err != nil {
			t.Fatalf("seeding advisory %s: %v", id, err)
		}
	}
}

// acmePublisher is the publisher name embedded in whiteAdvisoryTemplate, so
// stored-advisory assertions key on the right parent.
const acmePublisher = "ACME Inc"
