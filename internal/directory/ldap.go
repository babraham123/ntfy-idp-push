package directory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const (
	ldapPageSize    = 1000
	ldapDialTimeout = 10 * time.Second
	ldapTimeout     = 30 * time.Second
)

// ldapConn is the slice of *ldap.Conn the source uses, so tests can stand in for a server.
type ldapConn interface {
	Bind(username, password string) error
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

type ldapSource struct {
	cfg     LDAPConfig
	groupDN *ldap.DN // nil keeps everyone
	filter  string   // the users filter, narrowed to the group's members when a group is set
	tls     *tls.Config
	ldaps   bool // the transport dialNet opens is already TLS
	timeout time.Duration
	// dial opens an unbound connection, over the transport dialNet opens. Tests replace either.
	dial    func(ctx context.Context) (ldapConn, error)
	dialNet func(ctx context.Context) (net.Conn, error)
}

func newLDAPSource(cfg LDAPConfig) (*ldapSource, error) {
	for _, req := range []struct{ name, val string }{
		{"address", cfg.Address},
		{"base DN", cfg.BaseDN},
		{"users filter", cfg.UsersFilter},
		{"username attribute", cfg.AttributeUsername},
	} {
		if req.val == "" {
			return nil, fmt.Errorf("directory: ldap source needs a %s", req.name)
		}
	}
	u, err := url.Parse(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("directory: ldap address: %w", err)
	}
	if u.Scheme != "ldap" && u.Scheme != "ldaps" {
		return nil, fmt.Errorf("directory: ldap address %q: scheme must be ldap or ldaps", cfg.Address)
	}
	if u.Scheme == "ldaps" && cfg.StartTLS {
		return nil, errors.New("directory: ldap start-tls is for ldap:// addresses; ldaps:// is already TLS")
	}
	if _, err := ldap.CompileFilter(cfg.UsersFilter); err != nil {
		return nil, fmt.Errorf("directory: ldap users filter: %w", err)
	}
	s := &ldapSource{cfg: cfg, filter: cfg.UsersFilter, ldaps: u.Scheme == "ldaps", timeout: ldapTimeout}
	if cfg.GroupDN != "" {
		if cfg.AttributeMemberOf == "" {
			return nil, errors.New("directory: ldap group DN needs a member-of attribute")
		}
		if s.groupDN, err = ldap.ParseDN(cfg.GroupDN); err != nil {
			return nil, fmt.Errorf("directory: ldap group DN: %w", err)
		}
		// The server narrows the search so a large directory does not send every entry for a small
		// group.
		s.filter = "(&" + cfg.UsersFilter + "(" + cfg.AttributeMemberOf + "=" + ldap.EscapeFilter(cfg.GroupDN) + "))"
		if _, err := ldap.CompileFilter(s.filter); err != nil {
			return nil, fmt.Errorf("directory: ldap member-of attribute: %w", err)
		}
	}
	if s.tls, err = ldapTLSConfig(cfg, u.Hostname()); err != nil {
		return nil, err
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"ldap": "389", "ldaps": "636"}[u.Scheme]
	}
	addr := net.JoinHostPort(u.Hostname(), port)
	s.dialNet = func(ctx context.Context) (net.Conn, error) {
		nd := &net.Dialer{Timeout: ldapDialTimeout}
		if s.ldaps {
			return (&tls.Dialer{NetDialer: nd, Config: s.tls}).DialContext(ctx, "tcp", addr)
		}
		return nd.DialContext(ctx, "tcp", addr)
	}
	s.dial = s.connect
	return s, nil
}

// connect opens the connection and, with start-tls, upgrades it. go-ldap's StartTLS takes no
// context and its handshake has no deadline, so the transport gets a deadline for the upgrade and
// a cancelled ctx closes it.
func (s *ldapSource) connect(ctx context.Context) (ldapConn, error) {
	nc, err := s.dialNet(ctx)
	if err != nil {
		return nil, err
	}
	c := ldap.NewConn(nc, s.ldaps)
	c.Start()
	c.SetTimeout(s.timeout)
	if !s.cfg.StartTLS {
		return c, nil
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if err := nc.SetDeadline(time.Now().Add(s.timeout)); err != nil {
		c.Close()
		return nil, err
	}
	err = c.StartTLS(s.tls)
	if err == nil {
		err = nc.SetDeadline(time.Time{})
	}
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("start tls: %w", ctxErr(ctx, err))
	}
	return c, nil
}

// ldapTLSConfig serves both ldaps:// and StartTLS. StartTLS has no address to infer the
// certificate's name from, so the name is always set. A CA file extends the system roots rather than
// replacing them because the same process also talks TLS to public hosts.
func ldapTLSConfig(cfg LDAPConfig, host string) (*tls.Config, error) {
	tc := &tls.Config{ServerName: host, InsecureSkipVerify: cfg.TLSSkipVerify}
	if cfg.CAFile == "" {
		return tc, nil
	}
	pem, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("directory: ldap CA file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("directory: system cert pool: %w", err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("directory: ldap CA file %s has no PEM certificates", cfg.CAFile)
	}
	tc.RootCAs = pool
	return tc, nil
}

// open dials and binds. done releases the connection and the watcher that closes it when ctx
// ends: go-ldap takes no context, and closing the connection is what unblocks an in-flight request.
func (s *ldapSource) open(ctx context.Context) (c ldapConn, done func(), err error) {
	c, err = s.dial(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("directory: ldap connect: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	done = func() {
		stop()
		c.Close()
	}
	if s.cfg.User != "" {
		if err := c.Bind(s.cfg.User, s.cfg.Password); err != nil {
			done()
			return nil, nil, fmt.Errorf("directory: ldap bind: %w", ctxErr(ctx, err))
		}
	}
	return c, done, nil
}

// Check connects and binds, and with a group DN set, reads that entry: a group DN that names
// nothing would otherwise make every round list nobody.
func (s *ldapSource) Check(ctx context.Context) error {
	c, done, err := s.open(ctx)
	if err != nil {
		return err
	}
	defer done()
	if s.groupDN == nil {
		return nil
	}
	// "1.1" asks for no attributes: only the entry's existence matters.
	req := ldap.NewSearchRequest(s.cfg.GroupDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"1.1"}, nil)
	res, err := c.Search(req)
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) || (err == nil && len(res.Entries) == 0) {
		return fmt.Errorf("directory: ldap group %q: %w", s.cfg.GroupDN, ErrNoGroup)
	}
	if err != nil {
		return fmt.Errorf("directory: ldap group %q: %w", s.cfg.GroupDN, ctxErr(ctx, err))
	}
	return nil
}

func (s *ldapSource) List(ctx context.Context) ([]Person, error) {
	c, done, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	people, err := s.search(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("directory: ldap search: %w", ctxErr(ctx, err))
	}
	return finish(people)
}

// search pages through the whole result itself (rather than SearchWithPaging) so the cookie
// handling runs against the same ldapConn tests fake, and maps each page as it arrives so only
// the people are kept. Servers that ignore the paging control simply answer with everything and
// no cookie.
func (s *ldapSource) search(ctx context.Context, c ldapConn) ([]Person, error) {
	attrs := []string{s.cfg.AttributeUsername}
	for _, a := range []string{s.cfg.AttributeMail, s.cfg.AttributeDisplayName, s.cfg.AttributeMemberOf} {
		if a != "" {
			attrs = append(attrs, a)
		}
	}
	paging := ldap.NewControlPaging(ldapPageSize)
	req := ldap.NewSearchRequest(s.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		s.filter, attrs, []ldap.Control{paging})
	var people []Person
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		res, err := c.Search(req)
		if err != nil {
			return nil, err
		}
		for _, e := range res.Entries {
			if p, ok := s.person(e); ok {
				people = append(people, p)
			}
		}
		next, ok := ldap.FindControl(res.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
		if !ok || len(next.Cookie) == 0 {
			return people, nil
		}
		paging.SetCookie(next.Cookie)
	}
}

// person maps an entry; attribute names compare case-insensitively as LDAP defines them. LDAP has
// no portable "disabled" attribute, so disabled accounts are expected to be excluded by the users
// filter, which makes them absent and lets the sync disable them.
func (s *ldapSource) person(e *ldap.Entry) (Person, bool) {
	p := Person{Username: e.GetEqualFoldAttributeValue(s.cfg.AttributeUsername)}
	if p.Username == "" {
		return Person{}, false
	}
	if s.cfg.AttributeMail != "" {
		p.Email = e.GetEqualFoldAttributeValue(s.cfg.AttributeMail)
	}
	if s.cfg.AttributeDisplayName != "" {
		p.DisplayName = e.GetEqualFoldAttributeValue(s.cfg.AttributeDisplayName)
	}
	if s.cfg.AttributeMemberOf != "" {
		if groups := e.GetEqualFoldAttributeValues(s.cfg.AttributeMemberOf); len(groups) > 0 {
			p.Groups = groups
		}
	}
	// The search filter already asked for members; this check stands for servers that match
	// member-of loosely (substring or case rules that differ from DN equality).
	if s.groupDN != nil && !slices.ContainsFunc(p.Groups, s.isGroup) {
		return Person{}, false
	}
	return p, true
}

// isGroup compares DNs structurally so spacing and case differences between the configured group DN
// and the server's member-of values do not drop members.
func (s *ldapSource) isGroup(dn string) bool {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return strings.EqualFold(dn, s.cfg.GroupDN)
	}
	return parsed.EqualFold(s.groupDN)
}

// ctxErr reports a cancellation as such instead of as the closed-connection error it causes.
func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
