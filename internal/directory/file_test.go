package directory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// autheliaDB is shaped like Authelia's generated users_database.yml, password hashes included.
const autheliaDB = `
users:
  john:
    disabled: false
    displayname: "John Doe"
    password: "$argon2id$v=19$m=65536,t=3,p=4$abc$def"
    email: john.doe@example.com
    groups:
      - admins
      - dev
  alice:
    displayname: "Alice"
    email: alice@example.com
    groups: [dev]
  bob:
    disabled: true
    displayname: "Bob"
    email: bob@example.com
    groups: [dev, ops]
  harry:
    displayname: "Harry"
    email: harry@example.com
  everyone:
    email: reserved@example.com
    groups: [dev]
  "has space":
    groups: [dev]
`

func writeDB(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "users_database.yml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func listFile(t *testing.T, path, group string) ([]Person, error) {
	t.Helper()
	src, err := New(Config{Type: "file", File: path, Group: group})
	if err != nil {
		t.Fatal(err)
	}
	return src.List(context.Background())
}

func TestFileListsAutheliaUsers(t *testing.T) {
	got, err := listFile(t, writeDB(t, autheliaDB), "")
	if err != nil {
		t.Fatal(err)
	}
	// Sorted by username; "everyone" and "has space" are names ntfy would refuse.
	want := []Person{
		{Username: "alice", Email: "alice@example.com", DisplayName: "Alice", Groups: []string{"dev"}},
		{Username: "bob", Email: "bob@example.com", DisplayName: "Bob", Groups: []string{"dev", "ops"}, Disabled: true},
		{Username: "harry", Email: "harry@example.com", DisplayName: "Harry"},
		{Username: "john", Email: "john.doe@example.com", DisplayName: "John Doe", Groups: []string{"admins", "dev"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestFileGroupFilter(t *testing.T) {
	path := writeDB(t, autheliaDB)
	for _, c := range []struct {
		group string
		want  []string
	}{
		{group: "dev", want: []string{"alice", "bob", "john"}},
		{group: "ops", want: []string{"bob"}},
		{group: "Dev"}, // Authelia group names are case-sensitive
		{group: "nobody"},
	} {
		got, err := listFile(t, path, c.group)
		if c.want == nil {
			if err != nil || len(got) != 0 {
				t.Errorf("group %q: got %v, %v; want nobody", c.group, got, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("group %q: %v", c.group, err)
		}
		if names := usernames(got); !reflect.DeepEqual(names, c.want) {
			t.Errorf("group %q: got %v, want %v", c.group, names, c.want)
		}
	}
}

// Check requires the group to have a member, since the file defines groups only through
// memberships; a disabled member counts. Without a group, it only parses the file.
func TestFileCheck(t *testing.T) {
	path := writeDB(t, autheliaDB)
	for _, c := range []struct {
		path, group, wantErr string // wantErr "" passes
		noGroup              bool
	}{
		{path, "dev", "", false},
		{path, "ops", "", false}, // bob, disabled, is its only member
		{path, "", "", false},
		{path, "Dev", `"Dev"`, true},
		{path, "nobody", `"nobody"`, true},
		{writeDB(t, "users: [\n"), "", "parse", false},
		{filepath.Join(t.TempDir(), "absent.yml"), "dev", "absent.yml", false},
	} {
		src, err := New(Config{Type: "file", File: c.path, Group: c.group})
		if err != nil {
			t.Fatal(err)
		}
		err = src.Check(context.Background())
		if c.wantErr == "" && err != nil || c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
			t.Errorf("%s group %q: got %v, want %q", filepath.Base(c.path), c.group, err, c.wantErr)
		}
		if errors.Is(err, ErrNoGroup) != c.noGroup {
			t.Errorf("group %q: %v is ErrNoGroup: %v", c.group, err, !c.noGroup)
		}
	}
}

func TestFileEmptyOrBroken(t *testing.T) {
	for name, content := range map[string]string{
		"empty file":       "",
		"no users key":     "groups: {}\n",
		"empty users":      "users: {}\n",
		"only invalid ids": "users:\n  everyone: {}\n  \"a b\": {}\n",
	} {
		if got, err := listFile(t, writeDB(t, content), ""); err != nil || len(got) != 0 {
			t.Errorf("%s: got %v, %v; want nobody", name, got, err)
		}
	}
	// A broken or missing file is an error, not an empty directory.
	for name, path := range map[string]string{
		"malformed": writeDB(t, "users: [\n"),
		"missing":   filepath.Join(t.TempDir(), "absent.yml"),
	} {
		if _, err := listFile(t, path, ""); err == nil {
			t.Errorf("%s: listed without error", name)
		}
	}
}

func TestFileRereadsOnEveryList(t *testing.T) {
	path := writeDB(t, "users:\n  alice: {}\n")
	src, err := New(Config{Type: "file", File: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("users:\n  alice: {}\n  bob: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := src.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if names := usernames(got); !reflect.DeepEqual(names, []string{"alice", "bob"}) {
		t.Errorf("got %v", names)
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	ldapOK := LDAPConfig{
		Address:           "ldap://ldap.example.com",
		BaseDN:            "dc=example,dc=com",
		UsersFilter:       "(objectClass=person)",
		AttributeUsername: "uid",
		AttributeMemberOf: "memberOf",
	}
	for _, c := range []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"unknown type", Config{Type: "ad"}, "unknown type"},
		{"no type", Config{}, "unknown type"},
		{"file without path", Config{Type: "file"}, "file path"},
		{"ldap without address", Config{Type: "ldap", LDAP: with(ldapOK, func(l *LDAPConfig) { l.Address = "" })}, "address"},
		{"ldap without base DN", Config{Type: "ldap", LDAP: with(ldapOK, func(l *LDAPConfig) { l.BaseDN = "" })}, "base DN"},
		{"ldap without filter", Config{Type: "ldap", LDAP: with(ldapOK, func(l *LDAPConfig) { l.UsersFilter = "" })}, "users filter"},
		{"ldap without username attribute", Config{Type: "ldap", LDAP: with(ldapOK, func(l *LDAPConfig) { l.AttributeUsername = "" })}, "username attribute"},
		{"ldap wrong scheme", Config{Type: "ldap", LDAP: with(ldapOK, func(l *LDAPConfig) { l.Address = "https://ldap.example.com" })}, "scheme"},
		{"ldaps with start-tls", Config{Type: "ldap", LDAP: with(ldapOK, func(l *LDAPConfig) { l.Address = "ldaps://ldap.example.com"; l.StartTLS = true })}, "start-tls"},
		{"ldap bad filter", Config{Type: "ldap", LDAP: with(ldapOK, func(l *LDAPConfig) { l.UsersFilter = "(objectClass=person" })}, "users filter"},
		{"ldap bad group DN", Config{Type: "ldap", LDAP: with(ldapOK, func(l *LDAPConfig) { l.GroupDN = "not a dn" })}, "group DN"},
		{"ldap group DN without member-of", Config{Type: "ldap", LDAP: with(ldapOK, func(l *LDAPConfig) { l.GroupDN = "cn=g,dc=example,dc=com"; l.AttributeMemberOf = "" })}, "member-of"},
		{"ldap missing CA file", Config{Type: "ldap", LDAP: with(ldapOK, func(l *LDAPConfig) { l.CAFile = filepath.Join(t.TempDir(), "absent.pem") })}, "CA file"},
	} {
		_, err := New(c.cfg)
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.wantErr)
		}
	}
	for _, addr := range []string{"ldap://ldap.example.com", "ldaps://ldap.example.com:636", "ldap://10.0.0.5:389"} {
		if _, err := New(Config{Type: "ldap", LDAP: with(ldapOK, func(l *LDAPConfig) { l.Address = addr })}); err != nil {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

func with(l LDAPConfig, f func(*LDAPConfig)) LDAPConfig {
	f(&l)
	return l
}

func usernames(people []Person) []string {
	var out []string
	for _, p := range people {
		out = append(out, p.Username)
	}
	return out
}
