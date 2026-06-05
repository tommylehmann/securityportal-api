// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 SecurityPortal contributors

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
	GetDocument(ctx context.Context, id int64, publishableTLP []string) ([]byte, error)
}

// Controller binds the HTTP endpoints to the persistence layer and the publish
// policy. It mirrors ISDuBA's controller pattern with all authentication
// removed: every route is public and read-only.
type Controller struct {
	cfg *config.Config
	db  Querier
	// publishableTLP is the canonical TLP allow-list passed to every query as the
	// SQL-layer publish gate; cached here so it is computed once.
	publishableTLP []string
}

// NewController returns a controller bound to the configuration and store.
func NewController(cfg *config.Config, db Querier) *Controller {
	return &Controller{
		cfg:            cfg,
		db:             db,
		publishableTLP: cfg.PublishableTLPSet(),
	}
}

// Handler builds the Gin engine with the public, read-only routes and the
// shared middleware stack (recovery, structured request logging, and — when
// configured — CORS for the web origin).
func (c *Controller) Handler() http.Handler {
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(requestLogger())
	if cors := corsMiddleware(c.cfg.CORSOrigins); cors != nil {
		router.Use(cors)
	}

	api := router.Group("/api")
	api.GET("/health", c.health)
	api.GET("/advisories", c.listAdvisories)
	api.GET("/documents/:id", c.getDocument)

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
