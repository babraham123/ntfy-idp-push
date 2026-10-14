// Package config loads and validates the server.yml-style configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const EnvPrefix = "NTFY_IDP_PUSH_"

// Duration accepts Go duration strings ("300s", "1h") in YAML and env.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

type Config struct {
	ListenHTTPS string `yaml:"listen-https"`
	// ListenHTTP serves plain HTTP, for running behind a TLS-terminating proxy that preserves Host.
	ListenHTTP string `yaml:"listen-http"`
	// PublicURL is the origin users reach the shim at; defaults to https://<duo-hostname>.
	PublicURL string `yaml:"public-url"`

	DuoHostname           string   `yaml:"duo-hostname"`
	DuoIntegrationKey     string   `yaml:"duo-integration-key"`
	DuoSecretKey          string   `yaml:"duo-secret-key"`
	DuoSecretKeyPrevious  string   `yaml:"duo-secret-key-previous"`
	DuoSecretKeyRotatedAt string   `yaml:"duo-secret-key-rotated-at"`
	DuoKeyGrace           Duration `yaml:"duo-key-grace"`
	DuoMaxSkew            Duration `yaml:"duo-max-skew"`
	PushTimeout           Duration `yaml:"push-timeout"`
	PushDisabled          bool     `yaml:"push-disabled"`

	TLSMode     string `yaml:"tls-mode"`
	ACMECA      string `yaml:"acme-ca"`
	ACMEEABKID  string `yaml:"acme-eab-kid"`
	ACMEEABHMAC string `yaml:"acme-eab-hmac"`
	ACMEEmail   string `yaml:"acme-email"`
	ACMEKeyType string `yaml:"acme-key-type"`
	ACMEStorage string `yaml:"acme-storage"`
	TLSCertFile string `yaml:"tls-cert-file"`
	TLSKeyFile  string `yaml:"tls-key-file"`

	AuthMode         string   `yaml:"auth-mode"`
	TrustedProxies   []string `yaml:"trusted-proxies"`
	OIDCIssuer       string   `yaml:"oidc-issuer"`
	OIDCClientID     string   `yaml:"oidc-client-id"`
	OIDCClientSecret string   `yaml:"oidc-client-secret"`
	EnrollPortalURL  string   `yaml:"enroll-portal-url"`

	NtfyBaseURL     string   `yaml:"ntfy-base-url"`
	NtfyAdminToken  string   `yaml:"ntfy-admin-token"`
	NtfyTopicPrefix string   `yaml:"ntfy-topic-prefix"`
	DefaultTopics   []string `yaml:"default-topics"`

	EnrollRole            string   `yaml:"enroll-role"`
	EnrollAccess          []string `yaml:"enroll-access"`
	EnrollAccessReconcile bool     `yaml:"enroll-access-reconcile"`

	WebAuthnAllowSynced        bool `yaml:"webauthn-allow-synced"`
	WebAuthnRequireAttestation bool `yaml:"webauthn-require-attestation"`

	Database string `yaml:"database"`

	// Derived by Validate.
	Access         []AccessRule `yaml:"-"`
	TrustedNets    []*net.IPNet `yaml:"-"`
	PublicOrigin   string       `yaml:"-"`
	previousKeyEnd time.Time
}

func defaults() *Config {
	return &Config{
		ListenHTTPS:     ":443",
		DuoMaxSkew:      Duration(300 * time.Second),
		PushTimeout:     Duration(60 * time.Second),
		DuoKeyGrace:     Duration(time.Hour),
		TLSMode:         "acme",
		ACMECA:          "https://dv.acme-v02.api.pki.goog/directory",
		ACMEKeyType:     "p256",
		ACMEStorage:     "/var/lib/ntfy-idp-push/acme",
		AuthMode:        "forward",
		NtfyTopicPrefix: "push-",
		EnrollRole:      "user",
		Database:        "/var/lib/ntfy-idp-push/db.sqlite",
	}
}

// Load reads path (may be empty), applies NTFY_IDP_PUSH_* env overrides and validates.
func Load(path string) (*Config, error) {
	c := defaults()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		// An empty file decodes as io.EOF and means "all defaults".
		if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	if err := applyEnv(c, os.LookupEnv); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// EnvName maps a kebab key to its env variable.
func EnvName(key string) string {
	return EnvPrefix + strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
}

func applyEnv(c *Config, lookup func(string) (string, bool)) error {
	v := reflect.ValueOf(c).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		key := t.Field(i).Tag.Get("yaml")
		if key == "" || key == "-" {
			continue
		}
		raw, ok := lookup(EnvName(key))
		if !ok {
			continue
		}
		f := v.Field(i)
		switch f.Interface().(type) {
		case string:
			f.SetString(raw)
		case bool:
			b, err := strconv.ParseBool(raw)
			if err != nil {
				return fmt.Errorf("%s: %w", EnvName(key), err)
			}
			f.SetBool(b)
		case Duration:
			d, err := time.ParseDuration(raw)
			if err != nil {
				return fmt.Errorf("%s: %w", EnvName(key), err)
			}
			f.Set(reflect.ValueOf(Duration(d)))
		case []string:
			var list []string
			for _, s := range strings.Split(raw, ",") {
				if s = strings.TrimSpace(s); s != "" {
					list = append(list, s)
				}
			}
			f.Set(reflect.ValueOf(list))
		}
	}
	return nil
}

func (c *Config) Validate() error {
	var errs []error
	req := func(name, val string) {
		if strings.TrimSpace(val) == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}
	c.DuoHostname = strings.ToLower(c.DuoHostname)
	req("duo-hostname", c.DuoHostname)
	req("duo-integration-key", c.DuoIntegrationKey)
	req("duo-secret-key", c.DuoSecretKey)
	req("ntfy-base-url", c.NtfyBaseURL)
	req("ntfy-admin-token", c.NtfyAdminToken)
	req("ntfy-topic-prefix", c.NtfyTopicPrefix)
	req("database", c.Database)
	if len(c.DuoSecretKey) > 0 && len(c.DuoSecretKey) < 40 {
		errs = append(errs, errors.New("duo-secret-key must be at least 40 characters"))
	}

	if c.PublicURL == "" {
		c.PublicURL = "https://" + c.DuoHostname
	}
	if u, err := url.Parse(c.PublicURL); err != nil || u.Host == "" {
		errs = append(errs, fmt.Errorf("public-url %q is not an absolute URL", c.PublicURL))
	} else {
		c.PublicOrigin = u.Scheme + "://" + u.Host
		c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	}
	if u, err := url.Parse(c.NtfyBaseURL); err != nil || u.Host == "" {
		errs = append(errs, fmt.Errorf("ntfy-base-url %q is not an absolute URL", c.NtfyBaseURL))
	}
	c.NtfyBaseURL = strings.TrimRight(c.NtfyBaseURL, "/")

	switch c.TLSMode {
	case "acme":
		if c.ListenHTTPS != "" {
			req("acme-eab-kid", c.ACMEEABKID)
			req("acme-eab-hmac", c.ACMEEABHMAC)
			req("acme-email", c.ACMEEmail)
		}
	case "file":
		if c.ListenHTTPS != "" {
			req("tls-cert-file", c.TLSCertFile)
			req("tls-key-file", c.TLSKeyFile)
		}
	default:
		errs = append(errs, fmt.Errorf("tls-mode must be acme or file, got %q", c.TLSMode))
	}
	if c.ListenHTTPS == "" && c.ListenHTTP == "" {
		errs = append(errs, errors.New("one of listen-https or listen-http is required"))
	}
	if c.ACMEKeyType != "p256" && c.ACMEKeyType != "p384" && c.ACMEKeyType != "rsa2048" {
		errs = append(errs, fmt.Errorf("acme-key-type must be p256, p384 or rsa2048, got %q", c.ACMEKeyType))
	}

	switch c.AuthMode {
	case "forward":
		if len(c.TrustedProxies) == 0 {
			errs = append(errs, errors.New("auth-mode forward requires trusted-proxies"))
		}
	case "oidc":
		req("oidc-issuer", c.OIDCIssuer)
		req("oidc-client-id", c.OIDCClientID)
		req("oidc-client-secret", c.OIDCClientSecret)
	default:
		errs = append(errs, fmt.Errorf("auth-mode must be forward or oidc, got %q", c.AuthMode))
	}
	c.TrustedNets = nil
	for _, p := range c.TrustedProxies {
		if !strings.Contains(p, "/") {
			if ip := net.ParseIP(p); ip != nil && ip.To4() != nil {
				p += "/32"
			} else {
				p += "/128"
			}
		}
		_, n, err := net.ParseCIDR(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("trusted-proxies: %w", err))
			continue
		}
		c.TrustedNets = append(c.TrustedNets, n)
	}

	// ntfy's admin API can only create role "user"; refusing anything else keeps enrollment from
	// ever being a path to ntfy admin.
	if c.EnrollRole != "user" {
		errs = append(errs, fmt.Errorf("enroll-role must be \"user\", got %q", c.EnrollRole))
	}
	access, err := ParseAccessRules(c.EnrollAccess)
	if err != nil {
		errs = append(errs, err)
	}
	c.Access = access
	if err == nil {
		if err := ValidateAccess(access, c.NtfyTopicPrefix, ""); err != nil {
			errs = append(errs, err)
		}
		for _, t := range c.DefaultTopics {
			if !Readable(access, t, placeholderUser) {
				errs = append(errs, fmt.Errorf("default-topics entry %q is not readable under enroll-access", t))
			}
		}
	}

	if c.DuoSecretKeyPrevious != "" {
		at, err := time.Parse(time.RFC3339, c.DuoSecretKeyRotatedAt)
		if err != nil {
			errs = append(errs, fmt.Errorf("duo-secret-key-rotated-at: %w", err))
		}
		c.previousKeyEnd = at.Add(c.DuoKeyGrace.D())
	}
	return errors.Join(errs...)
}

// SecretKeys returns the keys an incoming signature may be made with: the current one, and the
// previous one while inside duo-key-grace.
func (c *Config) SecretKeys(now time.Time) []string {
	keys := []string{c.DuoSecretKey}
	if c.DuoSecretKeyPrevious != "" && now.Before(c.previousKeyEnd) {
		keys = append(keys, c.DuoSecretKeyPrevious)
	}
	return keys
}

// NtfyHost is the host part of ntfy-base-url, used in ntfy:// deep links.
func (c *Config) NtfyHost() (host string, secure bool) {
	u, _ := url.Parse(c.NtfyBaseURL)
	return u.Host, u.Scheme == "https"
}
