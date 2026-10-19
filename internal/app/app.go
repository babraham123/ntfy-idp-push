// Package app assembles the shim: the store, core, the Duo API and web handlers, the HTTP server's
// timeouts and the background loops. serve and the integration harness both build from here, so
// tests run the handler that ships.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/core"
	"github.com/babraham123/ntfy-idp-push/internal/directory"
	"github.com/babraham123/ntfy-idp-push/internal/duoapi"
	"github.com/babraham123/ntfy-idp-push/internal/mail"
	"github.com/babraham123/ntfy-idp-push/internal/store"
	"github.com/babraham123/ntfy-idp-push/internal/web"
)

// App is one shim process's worth of wiring over an open store.
type App struct {
	Cfg   *config.Config
	Store *store.Store
	Svc   *core.Service
	// Dir is nil when no directory is configured.
	Dir     directory.Source
	Handler http.Handler
	Log     *slog.Logger
}

// Build wires core and the handlers over an already open store, the user directory (nil for none)
// and the mail sender.
func Build(cfg *config.Config, st *store.Store, log *slog.Logger, dir directory.Source, mailer mail.Sender) (*App, error) {
	svc, err := core.New(cfg, st, log, dir, mailer)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	duoapi.New(svc, log).Register(mux)
	web.New(svc, log).Register(mux)
	return &App{Cfg: cfg, Store: st, Svc: svc, Dir: dir, Handler: web.SecurityHeaders(mux), Log: log}, nil
}

// Open builds the configured directory source and mail sender, opens the configured database and
// builds the app on them. Neither the source nor the sender connects until it is used, so commands
// that need neither work while the directory or the relay is down. Close releases the database.
func Open(cfg *config.Config, log *slog.Logger) (*App, error) {
	var dir directory.Source
	if cfg.DirectoryType != "" {
		var err error
		if dir, err = directory.New(DirectoryConfig(cfg)); err != nil {
			return nil, err
		}
	}
	mailer, err := mail.New(MailConfig(cfg))
	if err != nil {
		return nil, err
	}
	st, err := store.Open(cfg.Database)
	if err != nil {
		return nil, err
	}
	a, err := Build(cfg, st, log, dir, mailer)
	if err != nil {
		st.Close()
		return nil, err
	}
	return a, nil
}

func (a *App) Close() error { return a.Store.Close() }

// DirectoryConfig is the directory source the directory-* keys describe.
func DirectoryConfig(cfg *config.Config) directory.Config {
	return directory.Config{
		Type: cfg.DirectoryType,
		LDAP: directory.LDAPConfig{
			Address:              cfg.DirectoryLDAPAddress,
			StartTLS:             cfg.DirectoryLDAPStartTLS,
			TLSSkipVerify:        cfg.DirectoryLDAPTLSSkipVerify,
			CAFile:               cfg.DirectoryLDAPCAFile,
			BaseDN:               cfg.DirectoryLDAPBaseDN,
			User:                 cfg.DirectoryLDAPUser,
			Password:             cfg.DirectoryLDAPPassword,
			UsersFilter:          cfg.DirectoryLDAPUsersFilter,
			AttributeUsername:    cfg.DirectoryLDAPAttributeUsername,
			AttributeMail:        cfg.DirectoryLDAPAttributeMail,
			AttributeDisplayName: cfg.DirectoryLDAPAttributeDisplayName,
			AttributeMemberOf:    cfg.DirectoryLDAPAttributeMemberOf,
			GroupDN:              cfg.DirectoryLDAPGroupDN,
		},
	}
}

// MailConfig is the SMTP relay and sender the smtp-* and mail-* keys describe.
func MailConfig(cfg *config.Config) mail.Config {
	return mail.Config{
		Host:     cfg.SMTPHost,
		Port:     cfg.SMTPPort,
		User:     cfg.SMTPUser,
		Password: cfg.SMTPPassword,
		StartTLS: cfg.SMTPStartTLS,
		From:     cfg.MailFrom,
		ReplyTo:  cfg.MailReplyTo,
	}
}

// Server is the HTTP server for the handler. Plain HTTP: the reverse proxy in front terminates TLS
// and signs users in.
func (a *App) Server() *http.Server {
	return &http.Server{
		Addr:              a.Cfg.ListenHTTP,
		Handler:           a.Handler,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    16 << 10,
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

// every runs fn now and then every interval until ctx ends.
func every(ctx context.Context, interval time.Duration, fn func()) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		fn()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Serve runs the startup checks, the listener, the purge loop and, with a directory, the sync loop
// until ctx ends. Each value received on the reload channel re-reads the configuration with load
// and applies it; a refused reload keeps the running one and is logged.
func (a *App) Serve(ctx context.Context, reload <-chan struct{}, load func() (*config.Config, error)) error {
	if err := a.startupChecks(ctx); err != nil {
		return err
	}

	srv := a.Server()
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	a.Log.Info("listening", "http", a.Cfg.ListenHTTP, "hostname", a.Cfg.DuoHostname)

	go every(ctx, purgeInterval, func() { a.Svc.Purge(ctx) })
	if a.Dir == nil {
		a.Log.Info("directory sync off: no directory-type; provision users with user provision --email")
	} else {
		// Sync logs its own failures. directory-sync-interval is restart-only, so the startup value
		// holds for the process.
		go every(ctx, a.Cfg.DirectorySyncInterval.D(), func() { _ = a.Svc.Sync(ctx) })
	}

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

// startupChecks fails closed on an unsafe ntfy setup and on a directory that cannot work as
// configured. A group that does not exist would list nobody, and the first round would delete
// every user the directory manages.
func (a *App) startupChecks(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := a.Svc.StartupChecks(ctx); err != nil {
		return errors.Join(errors.New("startup check"), err)
	}
	if a.Dir == nil {
		return nil
	}
	if err := a.Dir.Check(ctx); err != nil {
		key := "directory-ldap-*"
		if errors.Is(err, directory.ErrNoGroup) {
			key = "directory-ldap-group-dn"
		}
		return errors.Join(fmt.Errorf("directory check (%s)", key), err)
	}
	return nil
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
