// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 Tommy Lehmann

// Package web implements the read-only REST API served with Gin: advisory
// listing, single-document fetch, and the health endpoint. There is no
// authentication; the API is public and only ever serves publishable-TLP data.
package web

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/securityportal/securityportal-api/pkg/auth"
	"github.com/securityportal/securityportal-api/pkg/config"
	"github.com/securityportal/securityportal-api/pkg/database"
)

// Querier is the read-only persistence seam the handlers depend on. It is
// satisfied by *database.DB; defining it here keeps the web package testable
// with an in-memory fake (httptest) and free of a hard database dependency.
type Querier interface {
	Ping(ctx context.Context) error
	LastIngest(ctx context.Context) (time.Time, bool, error)
	ListAdvisories(ctx context.Context, opts database.ListOptions, publishableTLP []string) (database.AdvisoryList, error)
	ComputeFacets(ctx context.Context, f database.Filters, publishableTLP []string) (database.Facets, error)
	GetDocument(ctx context.Context, id int64, publishableTLP []string) ([]byte, error)
	// GetByPublisherTrackingID resolves the latest publishable document for the
	// canonical (publisher, tracking_id) permalink (ADR-0016, C-27/SA-39/SA-40).
	GetByPublisherTrackingID(ctx context.Context, publisher, trackingID string, publishableTLP []string) (raw []byte, withdrawn bool, withdrawnAt *time.Time, err error)
}

// Controller binds the HTTP endpoints to the persistence layer and the publish
// policy. It mirrors ISDuBA's controller pattern with all authentication
// removed: every route is public and read-only.
//
// The publishable-TLP set is no longer a cached field on Controller. In v1 each
// request reads it from the anonymous principal attached by PrincipalMiddleware
// via auth.PrincipalFromContext. This is the Task 52/53 authz seam (ADR-0019):
// only the source of the TLP set changes from a static field to a per-request
// principal; the SQL gate itself is untouched (SA-36/C-24).
type Controller struct {
	cfg *config.Config
	db  Querier
}

// NewController returns a controller bound to the configuration and store.
func NewController(cfg *config.Config, db Querier) *Controller {
	return &Controller{
		cfg: cfg,
		db:  db,
	}
}

// Handler builds the Gin engine with the public, read-only routes and the
// shared middleware stack (recovery, structured request logging, and — when
// configured — CORS for the web origin).
func (c *Controller) Handler() http.Handler {
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	// UseRawPath makes the trie router match on the raw (percent-encoded) path so
	// that an encoded slash (%2F) in a path segment is NOT treated as a path
	// separator at the routing layer. Without this, Gin's httprouter would decode
	// %2F → "/" before trie-matching, causing /advisories/a%2Fb to route to the
	// 2-segment resource handler (publisher=a, trackingid=b) instead of the
	// 1-segment publisher-collection handler (publisher="a/b"). This is the SA-42
	// / C-28 encoded-slash traversal fix.
	//
	// UnescapePathValues remains at its default of true (set by gin.New()), so
	// ctx.Param() still returns URL-decoded values — e.g. RHSA-2024%3A5101 →
	// "RHSA-2024:5101" and a%2Fb → "a/b". Routing (trie matching) uses the raw
	// path; parameter extraction uses the decoded value. Both behaviours are needed:
	// the former to prevent %2F from changing arity, the latter for the handlers to
	// receive human-readable values without further decoding.
	//
	// Edge case: when request.URL.RawPath is empty (no percent-encoding in the
	// path), Gin falls back to URL.Path, which is already decoded — this is the
	// correct behaviour and is handled transparently by Gin.
	router.UseRawPath = true
	router.Use(gin.Recovery())
	router.Use(requestLogger())
	router.Use(securityHeaders())
	if cors := corsMiddleware(c.cfg.CORSOrigins); cors != nil {
		router.Use(cors)
	}
	// PrincipalMiddleware attaches the per-request principal to the request
	// context. In v1 this always produces the anonymous principal whose
	// AllowedTLP equals the configured publishable-TLP set (C-24/SA-36). The
	// middleware is registered globally (before the API group) so there is no
	// request path that reaches a handler without a principal in context.
	//
	// The bearerTokenResolver stub in pkg/auth is intentionally NOT registered
	// here. No v1 code path honours an Authorization/Bearer header (C-26/SA-38).
	router.Use(auth.PrincipalMiddleware(c.cfg))

	api := router.Group("/api")
	api.GET("/health", c.health)
	api.GET("/advisories", c.listAdvisories)
	// Routing precedence (C-28/SA-42): Gin resolves static path segments before
	// dynamic wildcards. The static registrations below (/advisories/feed.atom,
	// /openapi.json, /docs, /redoc.standalone.js) therefore always win over the
	// :publisher wildcard — registration order is irrelevant for static vs wildcard;
	// static beats wildcard by Gin's trie router design.
	//
	// Arity disambiguation (ADR-0016, OQ-15):
	//   1 trailing segment  → publisher collection  (/advisories/:publisher)
	//   2 trailing segments → resource permalink     (/advisories/:publisher/:trackingid)
	//
	// Static sub-paths under /advisories (feed.atom): registered first; they will
	// never be shadowed by :publisher even though Gin resolves static before wildcard.
	// /advisories/feed.atom would only be reachable if a publisher was literally named
	// "feed.atom", which is impossible given the static segment registers first.
	//
	// There is NO flat /advisories/:trackingid route. A single segment after
	// /advisories/ is always treated as a publisher name (ADR-0016 — the flat form
	// was dropped; the publisher-scoped 2-segment form is the only permalink).
	//
	// Both Gin path parameters are URL-decoded before the handler sees them (e.g.
	// Red%20Hat → "Red Hat"; RHSA-2024%3A5101 → "RHSA-2024:5101"). Each handler
	// applies its own 256-byte cap before any DB call (C-27/SA-43).
	//
	// /advisories/{publisher}/feed.atom — static "feed.atom" beats :trackingid.
	api.GET("/advisories/:publisher/feed.atom", c.publisherFeed)
	api.GET("/advisories/:publisher", c.listAdvisoriesByPublisher)
	api.GET("/advisories/:publisher/:trackingid", c.getAdvisoryByPublisherTrackingID)
	api.GET("/facets", c.facets)
	api.GET("/documents/:id", c.getDocument)
	// Global Atom feed — registered before :publisher so the static "feed.atom"
	// sub-path under /api is unambiguous.
	api.GET("/feed.atom", c.globalFeed)
	// OpenAPI 3.1 document + Redoc viewer (C-37/SA-54). Static segments; they
	// do not collide with :publisher because they are registered directly under /api
	// rather than under /advisories/:publisher.
	api.GET("/openapi.json", c.serveOpenAPIJSON)
	api.GET("/docs", c.serveAPIDocs)
	api.GET("/redoc.standalone.js", c.serveRedocJS)

	return router
}

// Server wraps an http.Server serving the controller's handler, with graceful
// shutdown driven by a context.
type Server struct {
	srv *http.Server
}

// NewServer builds a Server listening on cfg.Listen and serving the read-only
// API backed by db.
func NewServer(cfg *config.Config, db Querier) *Server {
	ctrl := NewController(cfg, db)
	return &Server{
		srv: &http.Server{
			Addr:              cfg.Listen,
			Handler:           ctrl.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
		},
	}
}

// Run serves until ctx is cancelled, then drains in-flight requests within a
// short grace period before returning. It returns nil on a clean shutdown and a
// non-nil error only if the listener itself failed to start or serve.
func (s *Server) Run(ctx context.Context) error {
	errs := make(chan error, 1)
	go func() {
		if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
			return
		}
		errs <- nil
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		// Drain in-flight requests with a bounded grace period that is independent
		// of the (already cancelled) caller context.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return <-errs
	}
}
