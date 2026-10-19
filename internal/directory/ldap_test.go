package directory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// fakeLDAP serves pages of entries, handing out the page index as the paging cookie the way a
// server's opaque cursor would be used.
type fakeLDAP struct {
	pages    [][]*ldap.Entry
	bindErr  error
	searches []*ldap.SearchRequest
	cookies  []string // cookie sent with each search
	bound    []string
	closed   atomic.Bool // Close runs on the context watcher goroutine
	onSearch func()
}

func (f *fakeLDAP) Bind(user, password string) error {
	f.bound = append(f.bound, user+":"+password)
	return f.bindErr
}

func (f *fakeLDAP) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if f.onSearch != nil {
		f.onSearch()
	}
	if f.closed.Load() {
		return nil, errors.New("ldap: connection closed")
	}
	f.searches = append(f.searches, req)
	paging, ok := ldap.FindControl(req.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
	if !ok {
		return nil, errors.New("no paging control")
	}
	f.cookies = append(f.cookies, string(paging.Cookie))
	page := 0
	if len(paging.Cookie) > 0 {
		page, _ = strconv.Atoi(string(paging.Cookie))
	}
	res := &ldap.SearchResult{}
	if page < len(f.pages) {
		res.Entries = f.pages[page]
	}
	next := &ldap.ControlPaging{PagingSize: paging.PagingSize}
	if page+1 < len(f.pages) {
		next.Cookie = []byte(strconv.Itoa(page + 1))
	}
	res.Controls = []ldap.Control{next}
	return res, nil
}

func (f *fakeLDAP) Close() error {
	f.closed.Store(true)
	return nil
}

var ldapBase = LDAPConfig{
	Address:              "ldaps://ldap.example.com",
	BaseDN:               "dc=example,dc=com",
	User:                 "cn=authelia,dc=example,dc=com",
	Password:             "secret",
	UsersFilter:          "(&(objectClass=person)(!(pwdAccountLockedTime=*)))",
	AttributeUsername:    "uid",
	AttributeMail:        "mail",
	AttributeDisplayName: "displayName",
	AttributeMemberOf:    "memberOf",
}

func newFakeSource(t *testing.T, cfg LDAPConfig, f *fakeLDAP) Source {
	t.Helper()
	src, err := New(Config{Type: "ldap", LDAP: cfg})
	if err != nil {
		t.Fatal(err)
	}
	src.(*ldapSource).dial = func() (ldapConn, error) { return f, nil }
	return src
}

func entry(dn string, attrs map[string][]string) *ldap.Entry {
	return ldap.NewEntry(dn, attrs)
}

func TestLDAPMapsAttributes(t *testing.T) {
	f := &fakeLDAP{pages: [][]*ldap.Entry{{
		// Servers may return attribute names in a different case than configured.
		entry("uid=zoe,ou=people,dc=example,dc=com", map[string][]string{
			"UID": {"zoe"}, "Mail": {"zoe@example.com", "z@example.com"}, "displayname": {"Zoe Z"},
			"memberof": {"cn=dev,ou=groups,dc=example,dc=com"},
		}),
		entry("uid=adam,ou=people,dc=example,dc=com", map[string][]string{
			"uid": {"adam"}, "mail": {"adam@example.com"},
		}),
		// No username: a service account or an entry the filter caught by accident.
		entry("cn=printer,dc=example,dc=com", map[string][]string{"mail": {"printer@example.com"}}),
		entry("uid=everyone,dc=example,dc=com", map[string][]string{"uid": {"everyone"}}),
	}}}
	got, err := newFakeSource(t, ldapBase, f).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []Person{
		{Username: "adam", Email: "adam@example.com"},
		{Username: "zoe", Email: "zoe@example.com", DisplayName: "Zoe Z", Groups: []string{"cn=dev,ou=groups,dc=example,dc=com"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	if !reflect.DeepEqual(f.bound, []string{"cn=authelia,dc=example,dc=com:secret"}) {
		t.Errorf("binds %v", f.bound)
	}
	req := f.searches[0]
	if req.BaseDN != ldapBase.BaseDN || req.Filter != ldapBase.UsersFilter || req.Scope != ldap.ScopeWholeSubtree {
		t.Errorf("search %+v", req)
	}
	if !reflect.DeepEqual(req.Attributes, []string{"uid", "mail", "displayName", "memberOf"}) {
		t.Errorf("attributes %v", req.Attributes)
	}
	if !f.closed.Load() {
		t.Error("connection left open")
	}
}

func TestLDAPPagesThroughResults(t *testing.T) {
	var pages [][]*ldap.Entry
	for p := range 3 {
		var page []*ldap.Entry
		for i := range 2 {
			name := "u" + strconv.Itoa(p*2+i)
			page = append(page, entry("uid="+name+",dc=example,dc=com", map[string][]string{"uid": {name}}))
		}
		pages = append(pages, page)
	}
	f := &fakeLDAP{pages: pages}
	got, err := newFakeSource(t, ldapBase, f).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if names := usernames(got); !reflect.DeepEqual(names, []string{"u0", "u1", "u2", "u3", "u4", "u5"}) {
		t.Errorf("got %v", names)
	}
	if !reflect.DeepEqual(f.cookies, []string{"", "1", "2"}) {
		t.Errorf("cookies sent %q", f.cookies)
	}
	paging := ldap.FindControl(f.searches[0].Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
	if paging.PagingSize != 1000 {
		t.Errorf("page size %d", paging.PagingSize)
	}
}

func TestLDAPGroupFilter(t *testing.T) {
	f := &fakeLDAP{pages: [][]*ldap.Entry{{
		entry("uid=in", map[string][]string{"uid": {"in"}, "memberOf": {"cn=other,dc=example,dc=com", "CN=Push Users,OU=Groups,DC=Example,DC=com"}}),
		entry("uid=spaced", map[string][]string{"uid": {"spaced"}, "memberOf": {"cn=push users, ou=groups, dc=example, dc=com"}}),
		entry("uid=out", map[string][]string{"uid": {"out"}, "memberOf": {"cn=other,dc=example,dc=com"}}),
		entry("uid=nested", map[string][]string{"uid": {"nested"}, "memberOf": {"cn=sub,cn=push users,ou=groups,dc=example,dc=com"}}),
		entry("uid=none", map[string][]string{"uid": {"none"}}),
	}}}
	cfg := ldapBase
	cfg.GroupDN = "cn=push users,ou=groups,dc=example,dc=com"
	got, err := newFakeSource(t, cfg, f).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if names := usernames(got); !reflect.DeepEqual(names, []string{"in", "spaced"}) {
		t.Errorf("got %v", names)
	}
}

func TestLDAPEmptyAndFailures(t *testing.T) {
	cfg := ldapBase
	cfg.GroupDN = "cn=push,dc=example,dc=com"
	nobodyInGroup := &fakeLDAP{pages: [][]*ldap.Entry{{entry("uid=a", map[string][]string{"uid": {"a"}})}}}
	for name, c := range map[string]struct {
		cfg LDAPConfig
		f   *fakeLDAP
	}{
		"no entries":      {ldapBase, &fakeLDAP{}},
		"only nameless":   {ldapBase, &fakeLDAP{pages: [][]*ldap.Entry{{entry("cn=x", map[string][]string{"cn": {"x"}})}}}},
		"nobody in group": {cfg, nobodyInGroup},
	} {
		if got, err := newFakeSource(t, c.cfg, c.f).List(context.Background()); !errors.Is(err, ErrEmpty) {
			t.Errorf("%s: got %v, %v; want ErrEmpty", name, got, err)
		}
	}

	bindFail := &fakeLDAP{bindErr: errors.New("invalid credentials"), pages: [][]*ldap.Entry{{entry("uid=a", map[string][]string{"uid": {"a"}})}}}
	if _, err := newFakeSource(t, ldapBase, bindFail).List(context.Background()); err == nil || !strings.Contains(err.Error(), "bind") {
		t.Errorf("bind failure: got %v", err)
	}
	if len(bindFail.searches) != 0 {
		t.Error("searched after a failed bind")
	}

	dup := &fakeLDAP{pages: [][]*ldap.Entry{
		{entry("uid=a,ou=one", map[string][]string{"uid": {"a"}, "mail": {"a@one"}})},
		{entry("uid=a,ou=two", map[string][]string{"uid": {"a"}, "mail": {"a@two"}})},
	}}
	if _, err := newFakeSource(t, ldapBase, dup).List(context.Background()); err == nil || errors.Is(err, ErrEmpty) {
		t.Errorf("duplicate username: got %v", err)
	}

	dialFail := newFakeSource(t, ldapBase, nil)
	dialFail.(*ldapSource).dial = func() (ldapConn, error) { return nil, errors.New("connection refused") }
	if _, err := dialFail.List(context.Background()); err == nil || errors.Is(err, ErrEmpty) {
		t.Errorf("dial failure: got %v", err)
	}
}

func TestLDAPAnonymousBind(t *testing.T) {
	cfg := ldapBase
	cfg.User, cfg.Password = "", ""
	f := &fakeLDAP{pages: [][]*ldap.Entry{{entry("uid=a", map[string][]string{"uid": {"a"}})}}}
	if _, err := newFakeSource(t, cfg, f).List(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.bound) != 0 {
		t.Errorf("bound as %v", f.bound)
	}
}

func TestLDAPCancelClosesConnection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeLDAP{pages: [][]*ldap.Entry{{entry("uid=a", map[string][]string{"uid": {"a"}})}}}
	// Cancelling mid-request must unblock it by closing the connection.
	f.onSearch = func() {
		cancel()
		deadline := time.Now().Add(time.Second)
		for !f.closed.Load() && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}
	if _, err := newFakeSource(t, ldapBase, f).List(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("got %v, want context.Canceled", err)
	}
}

func TestLDAPTLSConfig(t *testing.T) {
	cert, certPEM := selfSigned(t, "ldap.internal")
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := ldapBase
	cfg.CAFile = caFile
	tc, err := ldapTLSConfig(cfg, "ldap.internal")
	if err != nil {
		t.Fatal(err)
	}
	if tc.ServerName != "ldap.internal" || tc.InsecureSkipVerify {
		t.Errorf("tls config %+v", tc)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: tc.RootCAs, DNSName: "ldap.internal"}); err != nil {
		t.Errorf("CA file not trusted: %v", err)
	}
	want, err := x509.SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	want.AddCert(cert)
	if !tc.RootCAs.Equal(want) {
		t.Error("CA file should extend the system roots, not replace them")
	}

	// Without a CA file the system roots apply (nil RootCAs).
	tc, err = ldapTLSConfig(ldapBase, "ldap.example.com")
	if err != nil || tc.RootCAs != nil {
		t.Errorf("no CA file: %+v, %v", tc, err)
	}

	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.CAFile = bad
	if _, err := New(Config{Type: "ldap", LDAP: cfg}); err == nil || !strings.Contains(err.Error(), "CA file") {
		t.Errorf("invalid PEM: got %v", err)
	}
}

func selfSigned(t *testing.T, host string) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test LDAP CA"},
		DNSNames:              []string{host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
