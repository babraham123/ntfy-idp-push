package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/babraham123/ntfy-idp-push/internal/app"
	"github.com/babraham123/ntfy-idp-push/internal/config"
)

// serve runs the server until SIGINT or SIGTERM, reloading the configuration from cfgPath on
// SIGHUP.
func serve(cfg *config.Config, cfgPath string, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a, err := app.Open(cfg, log)
	if err != nil {
		return err
	}
	defer a.Close()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	reload := make(chan struct{}, 1)
	go func() {
		for range hup {
			reload <- struct{}{}
		}
	}()
	return a.Serve(ctx, reload, func() (*config.Config, error) { return config.Load(cfgPath) })
}
