package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/duoapi"
	"github.com/babraham123/ntfy-idp-push/internal/web"
)

func serve(cfg *config.Config, cfgPath string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	svc, closeFn, err := open(cfg)
	if err != nil {
		return err
	}
	defer closeFn()
	log := svc.Log

	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = svc.StartupChecks(checkCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("startup check: %w", err)
	}

	mux := http.NewServeMux()
	duoapi.New(svc, log).Register(mux)
	web.New(svc, log).Register(mux)

	// Plain HTTP: the reverse proxy in front terminates TLS and signs users in.
	srv := &http.Server{
		Addr:              cfg.ListenHTTP,
		Handler:           web.SecurityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// /auth/v2/auth extends its own deadline past push-timeout.
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  2 * time.Minute,
		ErrorLog:     slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("listening", "http", cfg.ListenHTTP, "hostname", cfg.DuoHostname)

	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			svc.Purge(ctx)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	for {
		select {
		case <-hup:
			next, err := config.Load(cfgPath)
			if err != nil {
				log.Error("reload refused; keeping current config", "err", err)
				continue
			}
			svc.Reload(next)
			log.Info("config reloaded", "push_disabled", next.PushDisabled)
		case err := <-errc:
			if !errors.Is(err, http.ErrServerClosed) {
				return err
			}
		case <-ctx.Done():
			log.Info("shutting down")
			shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shCtx)
			return nil
		}
	}
}
