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
	"github.com/babraham123/ntfy-idp-push/internal/tlsconfig"
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
	identity, err := web.NewIdentity(ctx, svc, mux)
	if err != nil {
		return err
	}
	duoapi.New(svc, log).Register(mux)
	web.New(svc, identity, log).Register(mux)

	newServer := func(addr string) *http.Server {
		return &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			// /auth/v2/auth extends its own deadline past push-timeout.
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  2 * time.Minute,
			ErrorLog:     slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		}
	}
	var servers []*http.Server
	errc := make(chan error, 2)
	if cfg.ListenHTTPS != "" {
		tc, err := tlsconfig.New(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return err
		}
		srv := newServer(cfg.ListenHTTPS)
		srv.TLSConfig = tc
		servers = append(servers, srv)
		go func() { errc <- srv.ListenAndServeTLS("", "") }()
		log.Info("listening", "https", cfg.ListenHTTPS, "hostname", cfg.DuoHostname)
	}
	if cfg.ListenHTTP != "" {
		srv := newServer(cfg.ListenHTTP)
		servers = append(servers, srv)
		go func() { errc <- srv.ListenAndServe() }()
		log.Info("listening", "http", cfg.ListenHTTP)
	}

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
			for _, s := range servers {
				_ = s.Shutdown(shCtx)
			}
			return nil
		}
	}
}
