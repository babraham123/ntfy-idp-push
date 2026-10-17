// Package config loads and validates the server.yml-style configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
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
	// ListenHTTP serves plain HTTP. The shim always sits behind the reverse proxy that terminates
	// TLS and signs users in, so there is no TLS listener.
	ListenHTTP string `yaml:"listen-http"`
	// PublicURL is the origin users reach the shim at; defaults to https://<duo-hostname>.
	PublicURL string `yaml:"public-url"`

	DuoHostname              string   `yaml:"duo-hostname"`
	DuoIntegrationKey        string   `yaml:"duo-integration-key"`
	DuoSecretKey             string   `yaml:"duo-secret-key"`
	DuoSecretKeyFile         string   `yaml:"duo-secret-key-file"`
	DuoSecretKeyPrevious     string   `yaml:"duo-secret-key-previous"`
	DuoSecretKeyPreviousFile string   `yaml:"duo-secret-key-previous-file"`
	DuoSecretKeyRotatedAt    string   `yaml:"duo-secret-key-rotated-at"`
	DuoKeyGrace              Duration `yaml:"duo-key-grace"`
	DuoMaxSkew               Duration `yaml:"duo-max-skew"`
	PushTimeout              Duration `yaml:"push-timeout"`
	PushDisabled             bool     `yaml:"push-disabled"`

	// TrustedProxies are the peers whose IdentityHeader and X-Forwarded-For are believed. Anyone
	// who can reach the shim from one of them can sign in as anyone, so keep it to the proxy.
	TrustedProxies []string `yaml:"trusted-proxies"`
	// IdentityHeader carries the signed-in username, set by the proxy's forward-auth step.
	IdentityHeader  string `yaml:"identity-header"`
	EnrollPortalURL string `yaml:"enroll-portal-url"`

	NtfyBaseURL        string   `yaml:"ntfy-base-url"`
	NtfyAdminToken     string   `yaml:"ntfy-admin-token"`
	NtfyAdminTokenFile string   `yaml:"ntfy-admin-token-file"`
	NtfyTopicPrefix    string   `yaml:"ntfy-topic-prefix"`
	DefaultTopics      []string `yaml:"default-topics"`

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
		ListenHTTP:      ":8080",
		IdentityHeader:  "Remote-User",
		DuoMaxSkew:      Duration(300 * time.Second),
		PushTimeout:     Duration(60 * time.Second),
		DuoKeyGrace:     Duration(time.Hour),
		NtfyTopicPrefix: "push-",
		EnrollRole:      "user",
		// A passkey without an attestation statement could come from any software authenticator;
		// opting out is a deliberate loosening.
		WebAuthnRequireAttestation: true,
		Database:                   "/var/lib/ntfy-idp-push/db.sqlite",
	}
}

// Load reads config path, applies NTFY_IDP_PUSH_* overrides, reads secret files, and validates.
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
	if err := c.readSecretFiles(); err != nil {
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

	req("listen-http", c.ListenHTTP)

	// The self-service pages know the user only from the proxy's header, so without a trusted
	// proxy nobody can sign in.
	req("identity-header", c.IdentityHeader)
	c.IdentityHeader = textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(c.IdentityHeader))
	if len(c.TrustedProxies) == 0 {
		errs = append(errs, errors.New("trusted-proxies is required: the proxy that sets "+c.IdentityHeader))
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

	// Refusing roles other than "user" prevents enrollment from escalating to ntfy admin.
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

// secretFile pairs a secret with the <key>-file setting that may supply it.
type secretFile struct {
	key         string
	value, path *string
}

func (c *Config) secretFiles() []secretFile {
	return []secretFile{
		{"duo-secret-key", &c.DuoSecretKey, &c.DuoSecretKeyFile},
		{"duo-secret-key-previous", &c.DuoSecretKeyPrevious, &c.DuoSecretKeyPreviousFile},
		{"ntfy-admin-token", &c.NtfyAdminToken, &c.NtfyAdminTokenFile},
	}
}

// readSecretFiles populates <key> from <key>-file (for Docker/systemd secrets), failing if both are
// set.
func (c *Config) readSecretFiles() error {
	var errs []error
	for _, s := range c.secretFiles() {
		if *s.path == "" {
			continue
		}
		if *s.value != "" {
			errs = append(errs, fmt.Errorf("set only one of %s and %s-file", s.key, s.key))
			continue
		}
		b, err := os.ReadFile(*s.path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s-file: %w", s.key, err))
			continue
		}
		*s.value = strings.TrimRight(string(b), "\r\n")
	}
	return errors.Join(errs...)
}

// RestartOnly lists the keys of next that differ from c and take effect only on a restart: the
// listener and database are bound at startup, and the WebAuthn relying party is built from
// public-url and the webauthn-* keys. Everything else applies to the next request after a reload.
func (c *Config) RestartOnly(next *Config) []string {
	var keys []string
	diff := func(key string, changed bool) {
		if changed {
			keys = append(keys, key)
		}
	}
	diff("listen-http", c.ListenHTTP != next.ListenHTTP)
	diff("database", c.Database != next.Database)
	diff("public-url", c.PublicURL != next.PublicURL)
	diff("webauthn-allow-synced", c.WebAuthnAllowSynced != next.WebAuthnAllowSynced)
	diff("webauthn-require-attestation", c.WebAuthnRequireAttestation != next.WebAuthnRequireAttestation)
	// Existing devices keep topics under the old prefix, which the shim would then treat as foreign.
	diff("ntfy-topic-prefix", c.NtfyTopicPrefix != next.NtfyTopicPrefix)
	return keys
}

// SecretKeys returns the current key and the previous key (if within duo-key-grace).
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
