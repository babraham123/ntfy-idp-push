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
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// fakeLDAP serves pages of entries, handing out the page index as the paging cookie the way a
// server's opaque cursor would be used.
type fakeLDAP struct {
	pages   [][]*ldap.Entry
	bindErr error
	// group answers base-scope searches: the entries found, or groupErr.
	group    []*ldap.Entry
	groupErr error
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
	if req.Scope == ldap.ScopeBaseObject {
		if f.groupErr != nil {
			return nil, f.groupErr
		}
		return &ldap.SearchResult{Entries: f.group}, nil
	}
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
	src.(*ldapSource).dial = func(context.Context) (ldapConn, error) { return f, nil }
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

// Every page is mapped and filtered as it arrives: members from all pages are kept, and the
// non-members and nameless entries on each page are dropped.
func TestLDAPPagesThroughResults(t *testing.T) {
	const group = "cn=push,dc=example,dc=com"
	var pages [][]*ldap.Entry
	for p := range 3 {
		var page []*ldap.Entry
		for i := range 2 {
			name := "u" + strconv.Itoa(p*2+i)
			page = append(page, entry("uid="+name+",dc=example,dc=com", map[string][]string{"uid": {name}, "memberOf": {group}}))
		}
		page = append(page,
			entry("uid=x"+strconv.Itoa(p)+",dc=example,dc=com", map[string][]string{"uid": {"x" + strconv.Itoa(p)}, "memberOf": {"cn=other,dc=example,dc=com"}}),
			entry("cn=nameless"+strconv.Itoa(p), map[string][]string{"memberOf": {group}}))
		pages = append(pages, page)
	}
	f := &fakeLDAP{pages: pages}
	cfg := ldapBase
	cfg.GroupDN = group
	got, err := newFakeSource(t, cfg, f).List(context.Background())
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

// The server is asked for the group's members only, with the DN escaped for the filter; the
// entries it returns are still checked, since some servers match member-of loosely.
func TestLDAPGroupFilter(t *testing.T) {
	f := &fakeLDAP{pages: [][]*ldap.Entry{{
		entry("uid=in", map[string][]string{"uid": {"in"}, "memberOf": {"cn=other,dc=example,dc=com", "CN=Push Users (All),OU=Groups,DC=Example,DC=com"}}),
		entry("uid=spaced", map[string][]string{"uid": {"spaced"}, "memberOf": {"cn=push users (all), ou=groups, dc=example, dc=com"}}),
		entry("uid=out", map[string][]string{"uid": {"out"}, "memberOf": {"cn=other,dc=example,dc=com"}}),
		entry("uid=nested", map[string][]string{"uid": {"nested"}, "memberOf": {"cn=sub,cn=push users (all),ou=groups,dc=example,dc=com"}}),
		entry("uid=none", map[string][]string{"uid": {"none"}}),
	}}}
	cfg := ldapBase
	cfg.GroupDN = "cn=push users (all),ou=groups,dc=example,dc=com"
	got, err := newFakeSource(t, cfg, f).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if names := usernames(got); !reflect.DeepEqual(names, []string{"in", "spaced"}) {
		t.Errorf("got %v", names)
	}
	const want = `(&(&(objectClass=person)(!(pwdAccountLockedTime=*)))(memberOf=cn=push users \28all\29,ou=groups,dc=example,dc=com))`
	if got := f.searches[0].Filter; got != want {
		t.Errorf("filter %s\nwant   %s", got, want)
	}
	if _, err := ldap.CompileFilter(f.searches[0].Filter); err != nil {
		t.Errorf("filter does not compile: %v", err)
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
		if got, err := newFakeSource(t, c.cfg, c.f).List(context.Background()); err != nil || len(got) != 0 {
			t.Errorf("%s: got %v, %v; want nobody", name, got, err)
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
	if _, err := newFakeSource(t, ldapBase, dup).List(context.Background()); err == nil {
		t.Errorf("duplicate username: got %v", err)
	}

	dialFail := newFakeSource(t, ldapBase, nil)
	dialFail.(*ldapSource).dial = func(context.Context) (ldapConn, error) { return nil, errors.New("connection refused") }
	if _, err := dialFail.List(context.Background()); err == nil {
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

// Check binds and, with a group DN, reads that one entry without attributes; a group the server
// does not have fails, as does a bind it refuses.
func TestLDAPCheck(t *testing.T) {
	const group = "cn=push,ou=groups,dc=example,dc=com"
	withGroup := ldapBase
	withGroup.GroupDN = group
	found := []*ldap.Entry{entry(group, nil)}
	noSuchObject := ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
	for _, c := range []struct {
		name    string
		cfg     LDAPConfig
		f       *fakeLDAP
		wantErr string // "" passes; the group DN itself means ErrNoGroup
	}{
		{"group found", withGroup, &fakeLDAP{group: found}, ""},
		{"group missing", withGroup, &fakeLDAP{groupErr: noSuchObject}, group},
		{"group not returned", withGroup, &fakeLDAP{}, group},
		{"group search fails", withGroup, &fakeLDAP{groupErr: errors.New("insufficient access")}, "insufficient access"},
		{"group bind fails", withGroup, &fakeLDAP{bindErr: errors.New("invalid credentials"), group: found}, "bind"},
		{"no group", ldapBase, &fakeLDAP{}, ""},
		{"no group bind fails", ldapBase, &fakeLDAP{bindErr: errors.New("invalid credentials")}, "bind"},
	} {
		err := newFakeSource(t, c.cfg, c.f).Check(context.Background())
		if c.wantErr == "" && err != nil || c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.wantErr)
		}
		if errors.Is(err, ErrNoGroup) != (c.wantErr == group) {
			t.Errorf("%s: %v is ErrNoGroup: %v", c.name, err, errors.Is(err, ErrNoGroup))
		}
		if !reflect.DeepEqual(c.f.bound, []string{"cn=authelia,dc=example,dc=com:secret"}) {
			t.Errorf("%s: binds %v", c.name, c.f.bound)
		}
		if !c.f.closed.Load() {
			t.Errorf("%s: connection left open", c.name)
		}
		if c.cfg.GroupDN == "" || c.f.bindErr != nil {
			if len(c.f.searches) != 0 {
				t.Errorf("%s: searched %+v", c.name, c.f.searches[0])
			}
			continue
		}
		if len(c.f.searches) != 1 {
			t.Fatalf("%s: %d searches, want 1", c.name, len(c.f.searches))
		}
		req := c.f.searches[0]
		if req.BaseDN != group || req.Scope != ldap.ScopeBaseObject || req.Filter != "(objectClass=*)" ||
			!reflect.DeepEqual(req.Attributes, []string{"1.1"}) {
			t.Errorf("%s: search %+v", c.name, req)
		}
	}

	dialFail := newFakeSource(t, withGroup, nil)
	dialFail.(*ldapSource).dial = func(context.Context) (ldapConn, error) { return nil, errors.New("connection refused") }
	if err := dialFail.Check(context.Background()); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("dial failure: got %v", err)
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

// stalledStartTLS is the server end of a connection that accepts StartTLS and then never answers
// the TLS handshake. It reports each request it reads on reqs.
func stalledStartTLS(t *testing.T, srv net.Conn, reqs chan<- struct{}) {
	t.Helper()
	go func() {
		defer srv.Close()
		req, err := ber.ReadPacket(srv)
		if err != nil {
			return
		}
		reqs <- struct{}{}
		res := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		res.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, req.Children[0].Value, "MessageID"))
		ext := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationExtendedResponse, nil, "Extended Response")
		ext.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(ldap.LDAPResultSuccess), "resultCode"))
		ext.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
		ext.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
		res.AppendChild(ext)
		if _, err := srv.Write(res.Bytes()); err != nil {
			return
		}
		// Swallow the ClientHello and never answer it.
		_, _ = io.Copy(io.Discard, srv)
	}()
}

// A StartTLS handshake the server never answers gives up at the request timeout, or as soon as the
// caller's context ends, instead of hanging the sync.
func TestLDAPStartTLSHandshakeIsBounded(t *testing.T) {
	cfg := ldapBase
	cfg.Address, cfg.StartTLS = "ldap://ldap.example.com", true
	for _, c := range []struct {
		name    string
		timeout time.Duration
		cancel  bool
		want    error
	}{
		{"timeout", 100 * time.Millisecond, false, nil},
		{"cancel", time.Hour, true, context.Canceled},
	} {
		t.Run(c.name, func(t *testing.T) {
			src, err := New(Config{Type: "ldap", LDAP: cfg})
			if err != nil {
				t.Fatal(err)
			}
			s := src.(*ldapSource)
			s.timeout = c.timeout
			reqs := make(chan struct{}, 1)
			s.dialNet = func(context.Context) (net.Conn, error) {
				cli, srv := net.Pipe()
				stalledStartTLS(t, srv, reqs)
				return cli, nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if c.cancel {
				go func() {
					<-reqs
					// Past the StartTLS response, into the handshake.
					time.Sleep(50 * time.Millisecond)
					cancel()
				}()
			}
			start := time.Now()
			done := make(chan error, 1)
			go func() {
				_, err := src.List(ctx)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "start tls") {
					t.Fatalf("got %v, want a start tls failure", err)
				}
				if c.want != nil && !errors.Is(err, c.want) {
					t.Fatalf("got %v, want %v", err, c.want)
				}
				if c.timeout < time.Hour && time.Since(start) > c.timeout+2*time.Second {
					t.Fatalf("took %v with a %v timeout", time.Since(start), c.timeout)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("StartTLS did not give up")
			}
		})
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
