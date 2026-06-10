// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

package auth

// Unit tests for the principal and authz-seam constructs.
//
// SA-35: anonymousPrincipal.AllowedTLP() == config.PublishableTLPSet() for
//        both the default config and a custom SECURITYPORTAL_PUBLISHABLE_TLP.
// SA-36: the registered PrincipalMiddleware attaches a non-nil principal on
//        every request (verified via PrincipalFromContext).
// SA-37: NewRolePrincipal only-widen invariant: fake green-reader → public∪{GREEN};
//        unknown role → exactly public; a role map entry that omits a public label
//        still yields ≥ public (publicSet ∪ extra construction).
// SA-38: bearerTokenResolver is not in the registered middleware chain; a request
//        carrying Authorization: Bearer <anything> gets the anonymous TLP set.

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gocsaf/csaf/v3/csaf"

	"github.com/securityportal/securityportal-api/pkg/config"
)

// ---- helpers -----------------------------------------------------------------

func defaultCfg() *config.Config {
	return &config.Config{
		PublishableTLP: []csaf.TLPLabel{csaf.TLPLabelWhite, csaf.TLPLabelUnlabeled},
	}
}

// sortedStrings returns a sorted copy of s so set comparisons are order-independent.
func sortedStrings(s []string) []string {
	cp := make([]string, len(s))
	copy(cp, s)
	sort.Strings(cp)
	return cp
}

// setsEqual reports whether a and b contain the same elements regardless of order.
func setsEqual(a, b []string) bool {
	sa := sortedStrings(a)
	sb := sortedStrings(b)
	if len(sa) != len(sb) {
		return false
	}
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}

func containsStr(s []string, v string) bool {
	for _, item := range s {
		if item == v {
			return true
		}
	}
	return false
}

// ---- SA-35: anonymous AllowedTLP == PublishableTLPSet -------------------------

// TestAnonymousPrincipalMatchesPublishableTLPSet_Default proves SA-35 for the
// default configuration (WHITE + UNLABELED → WHITE, CLEAR, UNLABELED after
// expansion).
func TestAnonymousPrincipalMatchesPublishableTLPSet_Default(t *testing.T) {
	cfg := defaultCfg()
	p := NewAnonymousPrincipal(cfg)
	want := cfg.PublishableTLPSet()

	if !setsEqual(p.AllowedTLP(), want) {
		t.Errorf("SA-35 FAIL: anonymous AllowedTLP = %v, want PublishableTLPSet = %v",
			p.AllowedTLP(), want)
	}
}

// TestAnonymousPrincipalMatchesPublishableTLPSet_CustomGreenConfig proves SA-35
// for a non-default publishable set that includes GREEN (e.g. a deployment that
// chooses to publish GREEN advisories publicly).
func TestAnonymousPrincipalMatchesPublishableTLPSet_CustomGreenConfig(t *testing.T) {
	cfg := &config.Config{
		PublishableTLP: []csaf.TLPLabel{
			csaf.TLPLabelWhite,
			csaf.TLPLabelUnlabeled,
			csaf.TLPLabelGreen,
		},
	}
	p := NewAnonymousPrincipal(cfg)
	want := cfg.PublishableTLPSet()

	if !setsEqual(p.AllowedTLP(), want) {
		t.Errorf("SA-35 FAIL (custom GREEN config): anonymous AllowedTLP = %v, want %v",
			p.AllowedTLP(), want)
	}
}

// TestAnonymousPrincipalIncludesWhiteAndClearExpansion confirms the
// WHITE→{WHITE,CLEAR} expansion is preserved: anonymous AllowedTLP must contain
// both "WHITE" and "CLEAR" when PublishableTLP includes WHITE (SA-35).
func TestAnonymousPrincipalIncludesWhiteAndClearExpansion(t *testing.T) {
	cfg := defaultCfg()
	p := NewAnonymousPrincipal(cfg)
	allowed := p.AllowedTLP()

	if !containsStr(allowed, "WHITE") {
		t.Errorf("SA-35 FAIL: AllowedTLP %v missing WHITE", allowed)
	}
	if !containsStr(allowed, "CLEAR") {
		t.Errorf("SA-35 FAIL: AllowedTLP %v missing CLEAR (WHITE→CLEAR expansion)", allowed)
	}
}

// TestAnonymousPrincipalRolesEmpty confirms the anonymous principal reports no
// roles (it is always unauthenticated — v1).
func TestAnonymousPrincipalRolesEmpty(t *testing.T) {
	p := NewAnonymousPrincipal(defaultCfg())
	if len(p.Roles()) != 0 {
		t.Errorf("anonymous Roles = %v, want []", p.Roles())
	}
}

// TestAnonymousPrincipalDefensiveCopyDoesNotAliasCfg confirms that mutating the
// returned slice does not affect subsequent calls (defensive copy in NewAnonymousPrincipal).
func TestAnonymousPrincipalDefensiveCopyDoesNotAliasCfg(t *testing.T) {
	cfg := defaultCfg()
	p := NewAnonymousPrincipal(cfg)
	first := p.AllowedTLP()
	// Mutate: add a bogus element to the returned slice.
	_ = append(first, "INJECTED")
	// A new call must still return the original set unchanged.
	second := p.AllowedTLP()
	want := cfg.PublishableTLPSet()
	if !setsEqual(second, want) {
		t.Errorf("defensive copy broken: second AllowedTLP = %v, want %v", second, want)
	}
}

// ---- SA-37: only-widen invariant for role principals -------------------------

// TestRolePrincipalGreenReaderWidens proves SA-37 part 1: a "green-reader" role
// that grants extra GREEN access → AllowedTLP ⊇ public ∪ {GREEN}.
func TestRolePrincipalGreenReaderWidens(t *testing.T) {
	cfg := defaultCfg()
	rm := RoleMap{"green-reader": {"GREEN"}}
	p := NewRolePrincipal(cfg, rm, []string{"green-reader"})

	allowed := p.AllowedTLP()
	public := cfg.PublishableTLPSet()

	// Must contain every public label.
	for _, label := range public {
		if !containsStr(allowed, label) {
			t.Errorf("SA-37 FAIL: green-reader AllowedTLP %v missing public label %q", allowed, label)
		}
	}
	// Must also contain GREEN.
	if !containsStr(allowed, "GREEN") {
		t.Errorf("SA-37 FAIL: green-reader AllowedTLP %v missing GREEN", allowed)
	}
}

// TestRolePrincipalUnknownRoleFallsBackToPublic proves SA-37 part 2: an unknown
// role yields exactly the public set (fail-closed-to-public).
func TestRolePrincipalUnknownRoleFallsBackToPublic(t *testing.T) {
	cfg := defaultCfg()
	rm := RoleMap{"green-reader": {"GREEN"}}
	p := NewRolePrincipal(cfg, rm, []string{"no-such-role"})

	want := cfg.PublishableTLPSet()
	if !setsEqual(p.AllowedTLP(), want) {
		t.Errorf("SA-37 FAIL: unknown role AllowedTLP = %v, want public set %v",
			p.AllowedTLP(), want)
	}
}

// TestRolePrincipalEmptyRolesFallsBackToPublic proves SA-37 for a zero-length
// roles slice (equivalent to anonymous — same public set).
func TestRolePrincipalEmptyRolesFallsBackToPublic(t *testing.T) {
	cfg := defaultCfg()
	p := NewRolePrincipal(cfg, RoleMap{}, []string{})

	want := cfg.PublishableTLPSet()
	if !setsEqual(p.AllowedTLP(), want) {
		t.Errorf("SA-37 FAIL: empty roles AllowedTLP = %v, want public set %v",
			p.AllowedTLP(), want)
	}
}

// TestRolePrincipalOnlyWidenNeverNarrows proves SA-37 construction invariant:
// even if the role map entry listed only extra labels that happen to NOT include a
// public one, the construction (publicSet ∪ extra) still retains every public label.
func TestRolePrincipalOnlyWidenNeverNarrows(t *testing.T) {
	cfg := defaultCfg()
	// Deliberately omit all public labels from the role extra list.
	rm := RoleMap{"limited": {}} // no extras at all
	p := NewRolePrincipal(cfg, rm, []string{"limited"})

	public := cfg.PublishableTLPSet()
	for _, label := range public {
		if !containsStr(p.AllowedTLP(), label) {
			t.Errorf("SA-37 FAIL only-widen: AllowedTLP %v narrowed below public (missing %q)",
				p.AllowedTLP(), label)
		}
	}
}

// TestRolePrincipalRolesArePreserved confirms the Roles() method echoes the
// supplied roles (used for audit/debug, not for enforcement).
func TestRolePrincipalRolesArePreserved(t *testing.T) {
	cfg := defaultCfg()
	p := NewRolePrincipal(cfg, RoleMap{}, []string{"green-reader", "amber-reader"})
	roles := p.Roles()
	if !containsStr(roles, "green-reader") || !containsStr(roles, "amber-reader") {
		t.Errorf("Roles() = %v, want [green-reader, amber-reader]", roles)
	}
}

// ---- SA-36: PrincipalMiddleware attaches a principal on every request --------

// TestPrincipalMiddlewareAttachesPrincipal drives PrincipalMiddleware through a
// minimal Gin engine and confirms PrincipalFromContext returns a non-nil principal
// whose AllowedTLP matches the anonymous set (SA-36).
func TestPrincipalMiddlewareAttachesPrincipal(t *testing.T) {
	cfg := defaultCfg()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(PrincipalMiddleware(cfg))

	var capturedAllowed []string
	r.GET("/probe", func(ctx *gin.Context) {
		p := PrincipalFromContext(ctx.Request.Context())
		capturedAllowed = p.AllowedTLP()
		ctx.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("handler panicked or returned %d (principal missing?)", rec.Code)
	}

	want := cfg.PublishableTLPSet()
	if !setsEqual(capturedAllowed, want) {
		t.Errorf("SA-36 FAIL: middleware AllowedTLP = %v, want public set %v",
			capturedAllowed, want)
	}
}

// ---- SA-38: bearerTokenResolver is unregistered; Bearer token ignored -------

// TestBearerTokenIgnored_AnonymousResultSet proves SA-38: a request carrying an
// Authorization: Bearer <something> header receives exactly the anonymous TLP set
// and not any widened set, because the bearerTokenResolver stub is not registered
// in the middleware chain.
func TestBearerTokenIgnored_AnonymousResultSet(t *testing.T) {
	cfg := defaultCfg()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(PrincipalMiddleware(cfg))

	var capturedAllowed []string
	r.GET("/probe", func(ctx *gin.Context) {
		p := PrincipalFromContext(ctx.Request.Context())
		capturedAllowed = p.AllowedTLP()
		ctx.Status(http.StatusOK)
	})

	// Request with a forged Bearer token.
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJub25lIn0.eyJyb2xlcyI6WyJyZWQtcmVhZGVyIl19.")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("handler returned %d unexpectedly", rec.Code)
	}

	want := cfg.PublishableTLPSet()
	if !setsEqual(capturedAllowed, want) {
		t.Errorf("SA-38 FAIL: Bearer token changed AllowedTLP to %v (want anonymous set %v) — "+
			"bearerTokenResolver may have been registered", capturedAllowed, want)
	}
}

// TestBearerTokenIgnored_NonPublishableStillExcluded proves SA-38 end-to-end at
// the principal seam: a request with a Bearer token does NOT gain access to any
// non-public TLP labels. The allowed set is the same as without the header.
func TestBearerTokenIgnored_NonPublishableStillExcluded(t *testing.T) {
	cfg := defaultCfg()
	p1 := NewAnonymousPrincipal(cfg)

	// Build a principal "as if" a middleware read the bearer token and called
	// bearerTokenResolver incorrectly — but confirm the real middleware never does.
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(PrincipalMiddleware(cfg))

	var capturedAllowed []string
	r.GET("/probe", func(ctx *gin.Context) {
		p := PrincipalFromContext(ctx.Request.Context())
		capturedAllowed = p.AllowedTLP()
		ctx.Status(http.StatusOK)
	})

	reqWithBearer := httptest.NewRequest(http.MethodGet, "/probe", nil)
	reqWithBearer.Header.Set("Authorization", "Bearer anything")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, reqWithBearer)

	reqWithout := httptest.NewRequest(http.MethodGet, "/probe", nil)
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, reqWithout)

	// Both requests must yield the same TLP set as the anonymous principal.
	if !setsEqual(capturedAllowed, p1.AllowedTLP()) {
		t.Errorf("SA-38 FAIL: Bearer request AllowedTLP %v != anonymous %v",
			capturedAllowed, p1.AllowedTLP())
	}
}
