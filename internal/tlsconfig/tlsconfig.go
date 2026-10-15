// Package tlsconfig builds the server TLS config from a certificate and key on disk.
package tlsconfig

import (
	"crypto/tls"
	"os"
	"sync"
	"time"
)

// New reloads the key pair when the certificate file changes, so renewals need no restart.
func New(certFile, keyFile string) (*tls.Config, error) {
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
