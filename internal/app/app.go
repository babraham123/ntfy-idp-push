// Package app assembles the shim: the store, core, the Duo API and web handlers, the HTTP server's
// timeouts and the background loops. serve and the integration harness both build from here, so
// tests run the handler that ships.
package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/core"
	"github.com/babraham123/ntfy-idp-push/internal/duoapi"
	"github.com/babraham123/ntfy-idp-push/internal/store"
	"github.com/babraham123/ntfy-idp-push/internal/web"
)

// App is one shim process's worth of wiring over an open store.
type App struct {
	Cfg     *config.Config
	Store   *store.Store
	Svc     *core.Service
	Handler http.Handler
	Log     *slog.Logger
}

// Build wires core and the handlers over an already open store.
func Build(cfg *config.Config, st *store.Store, log *slog.Logger) (*App, error) {
	svc, err := core.New(cfg, st, log)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	duoapi.New(svc, log).Register(mux)
	web.New(svc, log).Register(mux)
	return &App{Cfg: cfg, Store: st, Svc: svc, Handler: web.SecurityHeaders(mux), Log: log}, nil
}

// Open opens the configured database and builds the app on it. Close releases the database.
func Open(cfg *config.Config, log *slog.Logger) (*App, error) {
	st, err := store.Open(cfg.Database)
	if err != nil {
		return nil, err
	}
	a, err := Build(cfg, st, log)
	if err != nil {
		st.Close()
		return nil, err
	}
	return a, nil
}

func (a *App) Close() error { return a.Store.Close() }

// Server is the HTTP server for the handler. Plain HTTP: the reverse proxy in front terminates TLS
// and signs users in.
func (a *App) Server() *http.Server {
	return &http.Server{
		Addr:              a.Cfg.ListenHTTP,
		Handler:           a.Handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// /auth/v2/auth extends its own deadline past push-timeout.
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  2 * time.Minute,
		ErrorLog:     slog.NewLogLogger(a.Log.Handler(), slog.LevelWarn),
	}
}

// purgeInterval is how often expired challenges, unverified devices and unfinished revocations
// are cleaned up.
const purgeInterval = 10 * time.Minute

// Serve runs the startup checks, the listener and the purge loop until ctx ends. Each value
// received on the reload channel re-reads the configuration with load and applies it; a refused
// reload keeps the running one and is logged.
func (a *App) Serve(ctx context.Context, reload <-chan struct{}, load func() (*config.Config, error)) error {
	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err := a.Svc.StartupChecks(checkCtx)
	cancel()
	if err != nil {
		return errors.Join(errors.New("startup check"), err)
	}

	srv := a.Server()
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	a.Log.Info("listening", "http", a.Cfg.ListenHTTP, "hostname", a.Cfg.DuoHostname)

	go func() {
		t := time.NewTicker(purgeInterval)
		defer t.Stop()
		for {
			a.Svc.Purge(ctx)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	for {
		select {
		case <-reload:
			a.Reload(load)
		case err := <-errc:
			if !errors.Is(err, http.ErrServerClosed) {
				return err
			}
		case <-ctx.Done():
			a.Log.Info("shutting down")
			shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shCtx)
			return nil
		}
	}
}

// Reload applies a freshly loaded configuration, or logs why it was refused.
func (a *App) Reload(load func() (*config.Config, error)) {
	next, err := load()
	if err != nil {
		a.Log.Error("reload refused; keeping current config", "err", err)
		return
	}
	if err := a.Svc.Reload(next); err != nil {
		a.Log.Error("reload refused; keeping current config", "err", err)
		return
	}
	a.Cfg = next
	a.Log.Info("config reloaded", "push_disabled", next.PushDisabled)
}
