// Package tlsconfig builds the server TLS config. IdPs pin Duo's CA bundle, so the certificate must
// chain to one of those roots: ACME from Google Trust Services (with EAB), or a static file.
package tlsconfig

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"

	"github.com/babraham123/ntfy-idp-push/internal/config"
)

func New(ctx context.Context, cfg *config.Config) (*tls.Config, error) {
	switch cfg.TLSMode {
	case "file":
		return fileConfig(cfg.TLSCertFile, cfg.TLSKeyFile)
	case "acme":
		return acmeConfig(ctx, cfg)
	}
	return nil, fmt.Errorf("unknown tls-mode %q", cfg.TLSMode)
}

// fileConfig reloads the key pair when the certificate file changes, so renewals need no restart.
func fileConfig(certFile, keyFile string) (*tls.Config, error) {
	var (
		mu      sync.Mutex
		cur     *tls.Certificate
		modTime time.Time
	)
	load := func() error {
		st, err := os.Stat(certFile)
		if err != nil {
			return err
		}
		if cur != nil && st.ModTime().Equal(modTime) {
			return nil
		}
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}
		cur, modTime = &c, st.ModTime()
		return nil
	}
	if err := load(); err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			mu.Lock()
			defer mu.Unlock()
			// A half-written renewal keeps serving the previous pair.
			_ = load()
			return cur, nil
		},
	}, nil
}

func acmeConfig(ctx context.Context, cfg *config.Config) (*tls.Config, error) {
	keyType := map[string]certmagic.KeyType{"p256": certmagic.P256, "p384": certmagic.P384, "rsa2048": certmagic.RSA2048}[cfg.ACMEKeyType]
	cm := certmagic.NewDefault()
	cm.Storage = &certmagic.FileStorage{Path: cfg.ACMEStorage}
	cm.KeySource = certmagic.StandardKeyGenerator{KeyType: keyType}
	cm.Logger = zap.NewNop()
	issuer := certmagic.NewACMEIssuer(cm, certmagic.ACMEIssuer{
		CA:     cfg.ACMECA,
		Email:  cfg.ACMEEmail,
		Agreed: true,
		ExternalAccount: &acme.EAB{
			KeyID:  cfg.ACMEEABKID,
			MACKey: cfg.ACMEEABHMAC,
		},
		// TLS-ALPN-01 on the HTTPS listener; no port 80 needed.
		DisableHTTPChallenge: true,
	})
	cm.Issuers = []certmagic.Issuer{issuer}
	if err := cm.ManageSync(ctx, []string{cfg.DuoHostname}); err != nil {
		return nil, fmt.Errorf("acme: %w", err)
	}
	tc := cm.TLSConfig()
	tc.MinVersion = tls.VersionTLS12
	tc.NextProtos = append([]string{"h2", "http/1.1"}, tc.NextProtos...)
	return tc, nil
}
