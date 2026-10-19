package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func valid() *Config {
	c := defaults()
	c.DuoHostname = "push.example.com"
	c.DuoIntegrationKey = "DIAAAAAAAAAAAAAAAAAA"
	c.DuoSecretKey = strings.Repeat("s", 40)
	c.TrustedProxies = []string{"10.0.0.0/8"}
	c.NtfyBaseURL = "https://ntfy.example.com"
	c.NtfyAdminToken = "tk_x"
	c.EnrollAccess = []string{"${user}-*:rw", "alerts:ro"}
	c.DefaultTopics = []string{"alerts", "${user}-inbox"}
	c.DirectoryType = "ldap"
	c.SMTPHost = "smtp.example.com"
	c.MailFrom = "push@example.com"
	return c
}

func TestEnrollAccessValidation(t *testing.T) {
	for _, c := range []struct {
		access  []string
		topics  []string
		wantErr string
	}{
		{access: []string{"${user}-*:rw", "alerts:ro"}},
		{access: []string{"push-*:ro"}, wantErr: "push topics"},
		{access: []string{"*-inbox:rw"}, wantErr: "push topics"}, // matches push-x-inbox
		{access: []string{"p*:rw"}, wantErr: "push topics"},
		{access: []string{"*:ro"}, wantErr: "every topic"},
		{access: []string{"everyone:ro"}, wantErr: "every topic"},
		{access: []string{"alerts:admin"}, wantErr: "unknown permission"},
		{access: []string{"alerts"}, wantErr: "want <topic-pattern>:<access>"},
		{access: []string{"alerts:wo"}, topics: []string{"alerts"}, wantErr: "not readable"},
		// ntfy keeps one entry per pattern, so a second rule for it would silently replace the first.
		{access: []string{"alerts:deny", "alerts:ro"}, wantErr: "two rules"},
		{access: []string{"${user}-*:rw", "u0-*:ro"}, wantErr: "two rules"},
		// ntfy applies the longest matching pattern, whatever the config order.
		{access: []string{"news*:ro", "news-private:deny"}, topics: []string{"news-private"}, wantErr: "not readable"},
		{access: []string{"news-*:deny", "news-public:ro"}, topics: []string{"news-public"}},
		// On equal length, a grant that allows write wins over one that does not.
		{access: []string{"news-*:ro", "n*feed:wo"}, topics: []string{"news-feed"}, wantErr: "not readable"},
		{access: []string{"news-*:wo", "n*feed:rw"}, topics: []string{"news-feed"}},
		{access: []string{"${user}-*:read-write"}, topics: []string{"${user}-inbox"}},
	} {
		cfg := valid()
		cfg.EnrollAccess, cfg.DefaultTopics = c.access, c.topics
		err := cfg.Validate()
		if c.wantErr == "" && err != nil {
			t.Errorf("%v: unexpected %v", c.access, err)
		} else if c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
			t.Errorf("%v: got %v, want %q", c.access, err, c.wantErr)
		}
	}
}

func TestExpandAccessRechecksRealUsername(t *testing.T) {
	rules, _ := ParseAccessRules([]string{"${user}-*:rw"})
	if _, err := ExpandAccess(rules, "push-", "alice"); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"push", "pus*", "*"} {
		if _, err := ExpandAccess(rules, "push-", u); err == nil {
			t.Errorf("username %q expanded to a pattern over push topics", u)
		}
	}
}

func TestValidateFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"admin role":         func(c *Config) { c.EnrollRole = "admin" },
		"short secret":       func(c *Config) { c.DuoSecretKey = "short" },
		"no trusted proxy":   func(c *Config) { c.TrustedProxies = nil },
		"bad trusted proxy":  func(c *Config) { c.TrustedProxies = []string{"proxy"} },
		"no identity header": func(c *Config) { c.IdentityHeader = " " },
		"no listener":        func(c *Config) { c.ListenHTTP = "" },
		"unknown directory":  func(c *Config) { c.DirectoryType = "ad" },
		"no sync interval":   func(c *Config) { c.DirectorySyncInterval = 0 },
		"no smtp host":       func(c *Config) { c.SMTPHost = "" },
		"no mail from":       func(c *Config) { c.MailFrom = "" },
	} {
		c := valid()
		mutate(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Without a directory nothing is polled, so the sync interval is not checked.
func TestNoDirectory(t *testing.T) {
	c := valid()
	c.DirectoryType, c.DirectorySyncInterval = "", 0
	if err := c.Validate(); err != nil {
		t.Fatalf("no directory refused: %v", err)
	}
}

func TestDefaults(t *testing.T) {
	d := defaults()
	if !d.WebAuthnRequireAttestation {
		t.Fatal("webauthn-require-attestation should default to true")
	}
	if d.DirectorySyncInterval.D() != 15*time.Minute || d.DirectoryLDAPUsersFilter != "(objectClass=person)" ||
		d.DirectoryLDAPAttributeUsername != "uid" || d.DirectoryLDAPAttributeMail != "mail" ||
		d.DirectoryLDAPAttributeDisplayName != "displayName" || d.DirectoryLDAPAttributeMemberOf != "memberOf" ||
		d.SMTPPort != 587 || !d.SMTPStartTLS {
		t.Fatalf("directory and smtp defaults: %+v", d)
	}
}

func TestEnvOverrides(t *testing.T) {
	c := valid()
	env := map[string]string{
		"NTFY_IDP_PUSH_ENROLL_ACCESS": "${user}-*:rw, news:ro",
		"NTFY_IDP_PUSH_PUSH_TIMEOUT":  "45s",
		"NTFY_IDP_PUSH_PUSH_DISABLED": "true",
		"NTFY_IDP_PUSH_DUO_HOSTNAME":  "Other.Example.com",

		"NTFY_IDP_PUSH_DIRECTORY_TYPE":           "ldap",
		"NTFY_IDP_PUSH_DIRECTORY_SYNC_INTERVAL":  "5m",
		"NTFY_IDP_PUSH_DIRECTORY_LDAP_ADDRESS":   "ldaps://ldap.example.com",
		"NTFY_IDP_PUSH_DIRECTORY_LDAP_CA_FILE":   "/etc/ssl/private-ca.pem",
		"NTFY_IDP_PUSH_DIRECTORY_LDAP_START_TLS": "false",
		"NTFY_IDP_PUSH_DIRECTORY_LDAP_GROUP_DN":  "cn=push,dc=example,dc=com",
		"NTFY_IDP_PUSH_SMTP_PORT":                "465",
		"NTFY_IDP_PUSH_SMTP_STARTTLS":            "false",
		"NTFY_IDP_PUSH_MAIL_REPLY_TO":            "admin@example.com",
	}
	if err := applyEnv(c, func(k string) (string, bool) { v, ok := env[k]; return v, ok }); err != nil {
		t.Fatal(err)
	}
	c.DefaultTopics = nil
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(c.EnrollAccess) != 2 || c.EnrollAccess[1] != "news:ro" || c.PushTimeout.D() != 45*time.Second ||
		!c.PushDisabled || c.DuoHostname != "other.example.com" || c.PublicURL != "https://other.example.com" {
		t.Fatalf("env not applied: %+v", c)
	}
	if c.DirectoryType != "ldap" || c.DirectorySyncInterval.D() != 5*time.Minute ||
		c.DirectoryLDAPAddress != "ldaps://ldap.example.com" || c.DirectoryLDAPCAFile != "/etc/ssl/private-ca.pem" ||
		c.DirectoryLDAPGroupDN != "cn=push,dc=example,dc=com" || c.SMTPPort != 465 || c.SMTPStartTLS ||
		c.MailReplyTo != "admin@example.com" {
		t.Fatalf("directory and smtp env not applied: %+v", c)
	}
	if err := applyEnv(c, func(k string) (string, bool) { return "x", k == "NTFY_IDP_PUSH_SMTP_PORT" }); err == nil ||
		!strings.Contains(err.Error(), "NTFY_IDP_PUSH_SMTP_PORT") {
		t.Fatalf("non-numeric smtp-port: %v", err)
	}
}

// The directory source and mail sender are built once at startup, so changing their keys needs a
// restart; the ntfy connection and per-request settings do not.
func TestRestartOnly(t *testing.T) {
	c := valid()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	next := *c
	next.NtfyAdminToken = "tk_rotated"
	next.PushDisabled = true
	if keys := c.RestartOnly(&next); len(keys) != 0 {
		t.Fatalf("per-request keys refused: %v", keys)
	}
	next.DirectoryLDAPPassword = "rotated"
	next.SMTPPort = 2525
	next.MailFrom = "other@example.com"
	next.Database = "/elsewhere.sqlite"
	want := "database, directory-ldap-password, smtp-port, mail-from"
	if got := strings.Join(c.RestartOnly(&next), ", "); got != want {
		t.Fatalf("restart-only keys %q, want %q", got, want)
	}
}

func TestLoadAndRotate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yml")
	yml := `# shim config
duo-hostname: push.example.com
duo-integration-key: DIAAAAAAAAAAAAAAAAAA
duo-secret-key: "` + strings.Repeat("o", 40) + `"  # from keygen
trusted-proxies: [10.0.0.5]
identity-header: x-authentik-username
ntfy-base-url: https://ntfy.example.com
ntfy-admin-token: tk_x
smtp-host: smtp.example.com
mail-from: push@example.com
`
	if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.IdentityHeader != "X-Authentik-Username" || len(c.TrustedNets) != 1 || c.TrustedNets[0].String() != "10.0.0.5/32" {
		t.Fatalf("identity settings: %q %v", c.IdentityHeader, c.TrustedNets)
	}
	now := time.Now()
	key, err := RotateSecretKey(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if c, err = Load(path); err != nil {
		t.Fatal(err)
	}
	if c.DuoSecretKey != key || c.DuoSecretKeyPrevious != strings.Repeat("o", 40) {
		t.Fatalf("rotation not persisted: %q %q", c.DuoSecretKey, c.DuoSecretKeyPrevious)
	}
	if keys := c.SecretKeys(now.Add(30 * time.Minute)); len(keys) != 2 {
		t.Fatalf("inside grace: %d keys", len(keys))
	}
	if keys := c.SecretKeys(now.Add(2 * time.Hour)); len(keys) != 1 {
		t.Fatalf("after grace: %d keys", len(keys))
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "# shim config") {
		t.Fatal("comments lost on rotation")
	}

	if err := os.WriteFile(path, []byte(yml+"unknown-key: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestSecretFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	skey := strings.Repeat("k", 40)
	cfgPath := write("server.yml", `duo-hostname: push.example.com
duo-integration-key: DIAAAAAAAAAAAAAAAAAA
duo-secret-key-file: `+write("skey", skey+"\n")+`
trusted-proxies: [10.0.0.0/8]
ntfy-base-url: https://ntfy.example.com
directory-type: ldap
directory-ldap-password-file: `+write("ldap", "ldap-secret\n")+`
smtp-host: smtp.example.com
mail-from: push@example.com
`)
	// Docker and Podman secrets, and systemd credentials, are files named by an env variable.
	t.Setenv("NTFY_IDP_PUSH_NTFY_ADMIN_TOKEN_FILE", write("token", "tk_from_file\r\n"))
	t.Setenv("NTFY_IDP_PUSH_SMTP_PASSWORD_FILE", write("smtp", "smtp-secret"))
	c, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if c.DuoSecretKey != skey || c.NtfyAdminToken != "tk_from_file" || c.DirectoryLDAPPassword != "ldap-secret" ||
		c.SMTPPassword != "smtp-secret" {
		t.Fatalf("secrets not read from files: %q %q %q %q", c.DuoSecretKey, c.NtfyAdminToken, c.DirectoryLDAPPassword, c.SMTPPassword)
	}

	// A reload re-reads the files, so a rotated secret file takes effect on SIGHUP.
	write("token", "tk_rotated")
	if c, err = Load(cfgPath); err != nil || c.NtfyAdminToken != "tk_rotated" {
		t.Fatalf("reload: %v %q", err, c.NtfyAdminToken)
	}

	t.Setenv("NTFY_IDP_PUSH_NTFY_ADMIN_TOKEN", "tk_inline")
	if _, err := Load(cfgPath); err == nil || !strings.Contains(err.Error(), "only one of ntfy-admin-token") {
		t.Fatalf("value and file both set: %v", err)
	}
	os.Unsetenv("NTFY_IDP_PUSH_NTFY_ADMIN_TOKEN")
	t.Setenv("NTFY_IDP_PUSH_NTFY_ADMIN_TOKEN_FILE", filepath.Join(dir, "missing"))
	if _, err := Load(cfgPath); err == nil || !strings.Contains(err.Error(), "ntfy-admin-token-file") {
		t.Fatalf("missing file: %v", err)
	}

	if _, err := RotateSecretKey(cfgPath, time.Now()); err == nil {
		t.Fatal("rotated a key kept in a secret file")
	}
}
