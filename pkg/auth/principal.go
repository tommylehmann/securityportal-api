// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

// Package auth implements the authorization seam for the SecurityPortal API.
//
// In v1 the portal is public and unauthenticated (spec §2 / §13.3). This
// package defines the per-request Principal type and the two-resolver design
// described in ADR-0019:
//
//   - The only REGISTERED resolver in v1 is the anonymous resolver: every
//     request receives the anonymous principal whose AllowedTLP set equals the
//     operator-configured publishable TLP set byte-for-byte.
//
//   - A STUB bearerTokenResolver is defined here for documentation purposes
//     only. It is intentionally not registered in the middleware chain in v1
//     and no production code path calls it. The function signature and its
//     inline commentary describe exactly where a future OIDC access-token
//     validator would map validated JWT claims → roles → allowed-TLP set.
//     See bearerTokenResolver for details and the relevant security assumption
//     (SA-38 / C-26).
//
// # "Only-widen" invariant (ADR-0020, C-25, SA-37)
//
// Every principal's AllowedTLP set is computed as:
//
//	publicSet ∪ extraLabels(role)
//
// This construction makes it structurally impossible for a role-derived set to
// be narrower than the public set — a misconfigured role map cannot drop a
// caller below public. The anonymous principal is equivalent to a role with an
// empty extra set: it returns publicSet exactly.
package auth

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/securityportal/securityportal-api/pkg/config"
)

// contextKey is an unexported type for the principal context value. Using a
// package-level type prevents collisions with keys from other packages.
type contextKey struct{}

// principalKey is the key under which the Principal is stored in the request
// context. Callers outside this package use PrincipalFromContext.
var principalKey = contextKey{}

// Principal represents the identity (and its authorized TLP visibility) of the
// caller for a single request. In v1 this is always the anonymous principal.
// Future OIDC phases replace the resolution step without changing this
// interface or the handlers.
//
// Security note: the enforcement point for TLP visibility is the SQL gate
// (upper(d.tlp)=ANY($publishable)). AllowedTLP merely supplies the allow-list
// that the SQL gate consumes; it is not a bypass or a replacement.
type Principal interface {
	// AllowedTLP returns the set of TLP labels this caller is permitted to see,
	// as canonical upper-case strings (e.g. "WHITE", "CLEAR", "UNLABELED").
	// The slice is passed directly to the SQL publishable-TLP gate. For an
	// anonymous caller this always equals config.PublishableTLPSet() exactly.
	AllowedTLP() []string

	// Roles returns the role names associated with this caller. For the
	// anonymous principal this is always an empty slice. Future authenticated
	// principals carry the roles extracted from the validated OIDC token's
	// claims; those roles drive the only-widen TLP expansion.
	Roles() []string
}

// anonymousPrincipal is the concrete Principal for every v1 request. Its
// AllowedTLP is the configured public TLP set, unchanged.
type anonymousPrincipal struct {
	allowedTLP []string
}

// NewAnonymousPrincipal returns a Principal whose AllowedTLP is exactly
// cfg.PublishableTLPSet() — same elements, same canonical upper-casing, the
// same WHITE→{WHITE,CLEAR}/UNLABELED expansion the config already performs.
//
// This is the only valid way to create an anonymous principal. It derives the
// set from the single authoritative source (PublishableTLPSet) rather than
// recomputing it, so the two can never diverge.
func NewAnonymousPrincipal(cfg *config.Config) Principal {
	tlp := cfg.PublishableTLPSet()
	// Defensive copy: the returned slice must not alias cfg's internal slice,
	// as callers may hold references across request lifetimes.
	set := make([]string, len(tlp))
	copy(set, tlp)
	return &anonymousPrincipal{allowedTLP: set}
}

func (p *anonymousPrincipal) AllowedTLP() []string { return p.allowedTLP }
func (p *anonymousPrincipal) Roles() []string       { return nil }

// RoleMap is a config-driven mapping from role name to the extra TLP labels
// (beyond the public set) that principals carrying that role may see.
//
// The only-widen invariant (ADR-0020, C-25, SA-37) is enforced by construction
// in NewRolePrincipal: every role's effective TLP set is computed as
// publicSet ∪ extraLabels(role), so the public labels are always present
// regardless of what the map contains.
//
// v1 ships no real roles; the map is here so the invariant + construction are
// testable and so a future OIDC phase can populate it without handler changes.
type RoleMap map[string][]string

// NewRolePrincipal returns a Principal for a caller bearing the given roles.
// The resulting AllowedTLP set is the union of publicSet and all extra labels
// from every matching role in the map. Unknown roles contribute no extras (they
// fall back to just the public set — C-25/SA-37 fail-closed-to-public).
//
// This function is not called in v1 because the bearerTokenResolver is not
// registered, but its construction is unit-tested to prove the invariant.
func NewRolePrincipal(cfg *config.Config, roleMap RoleMap, roles []string) Principal {
	publicSet := cfg.PublishableTLPSet()

	// Build the union of publicSet and all extra labels from the caller's roles.
	// Using a map deduplicates entries while preserving the invariant that every
	// public label survives regardless of what the role map contains.
	merged := make(map[string]struct{}, len(publicSet)+4)
	for _, label := range publicSet {
		merged[label] = struct{}{}
	}
	for _, role := range roles {
		for _, extra := range roleMap[role] {
			merged[extra] = struct{}{}
		}
	}

	allowed := make([]string, 0, len(merged))
	for label := range merged {
		allowed = append(allowed, label)
	}

	return &rolePrincipal{allowedTLP: allowed, roles: roles}
}

// rolePrincipal is returned by NewRolePrincipal for authenticated callers.
// Not used in v1 (the bearerTokenResolver stub is never registered), but
// exercised by unit tests to prove the only-widen invariant.
type rolePrincipal struct {
	allowedTLP []string
	roles      []string
}

func (p *rolePrincipal) AllowedTLP() []string { return p.allowedTLP }
func (p *rolePrincipal) Roles() []string       { return p.roles }

// PrincipalFromContext retrieves the Principal stored by the resolver middleware.
// It panics if called outside a request context that went through the registered
// middleware, which should be impossible by construction: the middleware is global
// and applied before every API route group. The panic acts as a compile-time-like
// assertion that no handler bypasses the middleware chain.
func PrincipalFromContext(ctx context.Context) Principal {
	p, ok := ctx.Value(principalKey).(Principal)
	if !ok || p == nil {
		// This path should be unreachable in production because the anonymous
		// resolver middleware is registered globally before all API routes. A
		// panic here surfaces a middleware-registration bug immediately in tests
		// rather than silently falling back to an empty TLP set (which would be
		// a confidentiality regression — SA-36/SA-35).
		panic("auth: Principal missing from request context; " +
			"is the PrincipalMiddleware registered before the API group?")
	}
	return p
}

// PrincipalMiddleware is the REGISTERED middleware that attaches an anonymous
// Principal to every request context in v1. It is wired into the Gin router
// in server.go before all API route groups (SA-36/C-24).
//
// In a future OIDC phase this function is replaced by one that calls
// bearerTokenResolver first (if an Authorization header is present) and falls
// back to anonymousPrincipal otherwise. That change is localised to this
// middleware and server.go's registration call — no handler needs updating.
func PrincipalMiddleware(cfg *config.Config) gin.HandlerFunc {
	// The anonymous principal is immutable and stateless; creating it once at
	// middleware construction time is safe to share across requests.
	anon := NewAnonymousPrincipal(cfg)

	return func(ctx *gin.Context) {
		// Store in the standard library context so it survives ctx.Request.Context()
		// calls inside handlers (the gin.Context value is Gin-layer only).
		reqCtx := context.WithValue(ctx.Request.Context(), principalKey, anon)
		ctx.Request = ctx.Request.WithContext(reqCtx)
		ctx.Next()
	}
}

// bearerTokenResolver is an intentionally UNREGISTERED stub documenting the
// future OIDC integration seam (ADR-0019, SA-38, C-26).
//
// DO NOT register this function in the middleware chain in v1. It is defined
// here solely so:
//
//  1. The handler signature, role mapping, and only-widen construction are
//     designed and code-reviewed before an IdP is wired.
//  2. Unit tests can assert the stub exists but is never called on a live request.
//
// # Future implementation contract (for the OIDC phase)
//
// When this is eventually activated, the implementation must:
//   - Extract the raw JWT from the Authorization: Bearer header.
//   - Validate the token signature against the IdP's JWKS endpoint (generic
//     OIDC, Keycloak-compatible; key URL sourced from the IdP discovery document
//     pinned in operator config, never from the token itself).
//   - Extract the role claim(s) from the validated token payload.
//   - Call NewRolePrincipal(cfg, roleMap, roles) to build the principal, which
//     enforces the only-widen invariant by construction.
//   - If validation fails for any reason (malformed token, expired, bad sig,
//     missing claim), fall back to the anonymous principal — fail-closed.
//   - Add the token-validation library as a new ADR (out of scope here).
//
// The function is unexported and unreachable in v1; the linter should flag it
// as unused if accidentally called. Tests assert it is never invoked for
// ordinary requests (SA-38).
//
//nolint:unused
func bearerTokenResolver(
	_ *http.Request,
	_ *config.Config,
	_ RoleMap,
) Principal {
	// Stub body — never called in v1. Returning nil here would panic
	// PrincipalFromContext, which is the correct loud failure if this stub is
	// accidentally wired up. The future implementation replaces this body; the
	// function signature is the stable part.
	panic("auth: bearerTokenResolver is a v1 stub and must not be registered or called")
}
