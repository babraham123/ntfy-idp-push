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
	dial    func() (ldapConn, error)
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
	s := &ldapSource{cfg: cfg}
	if cfg.GroupDN != "" {
		if cfg.AttributeMemberOf == "" {
			return nil, errors.New("directory: ldap group DN needs a member-of attribute")
		}
		if s.groupDN, err = ldap.ParseDN(cfg.GroupDN); err != nil {
			return nil, fmt.Errorf("directory: ldap group DN: %w", err)
		}
	}
	tlsCfg, err := ldapTLSConfig(cfg, u.Hostname())
	if err != nil {
		return nil, err
	}
	s.dial = func() (ldapConn, error) {
		c, err := ldap.DialURL(cfg.Address,
			ldap.DialWithDialer(&net.Dialer{Timeout: ldapDialTimeout}),
			ldap.DialWithTLSConfig(tlsCfg))
		if err != nil {
			return nil, err
		}
		c.SetTimeout(ldapTimeout)
		if cfg.StartTLS {
			if err := c.StartTLS(tlsCfg); err != nil {
				c.Close()
				return nil, fmt.Errorf("start tls: %w", err)
			}
		}
		return c, nil
	}
	return s, nil
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

func (s *ldapSource) List(ctx context.Context) ([]Person, error) {
	c, err := s.dial()
	if err != nil {
		return nil, fmt.Errorf("directory: ldap connect: %w", err)
	}
	defer c.Close()
	// go-ldap takes no context; closing the connection is what unblocks an in-flight request.
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()

	if s.cfg.User != "" {
		if err := c.Bind(s.cfg.User, s.cfg.Password); err != nil {
			return nil, fmt.Errorf("directory: ldap bind: %w", ctxErr(ctx, err))
		}
	}
	entries, err := s.search(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("directory: ldap search: %w", ctxErr(ctx, err))
	}
	people := make([]Person, 0, len(entries))
	for _, e := range entries {
		if p, ok := s.person(e); ok {
			people = append(people, p)
		}
	}
	return finish(people)
}

// search pages through the whole result itself (rather than SearchWithPaging) so the cookie
// handling runs against the same ldapConn tests fake. Servers that ignore the paging control simply
// answer with everything and no cookie.
func (s *ldapSource) search(ctx context.Context, c ldapConn) ([]*ldap.Entry, error) {
	attrs := []string{s.cfg.AttributeUsername}
	for _, a := range []string{s.cfg.AttributeMail, s.cfg.AttributeDisplayName, s.cfg.AttributeMemberOf} {
		if a != "" {
			attrs = append(attrs, a)
		}
	}
	paging := ldap.NewControlPaging(ldapPageSize)
	req := ldap.NewSearchRequest(s.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		s.cfg.UsersFilter, attrs, []ldap.Control{paging})
	var entries []*ldap.Entry
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		res, err := c.Search(req)
		if err != nil {
			return nil, err
		}
		entries = append(entries, res.Entries...)
		next, ok := ldap.FindControl(res.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
		if !ok || len(next.Cookie) == 0 {
			return entries, nil
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
