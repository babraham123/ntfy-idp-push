// Package directory lists the people the shim keeps ntfy accounts for, from LDAP or from Authelia's
// file user database.
package directory

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Person is one directory entry as the sync sees it.
type Person struct {
	Username    string
	Email       string
	DisplayName string
	Groups      []string
	Disabled    bool
}

// Source lists the directory's people, sorted by username.
type Source interface {
	List(ctx context.Context) ([]Person, error)
}

// Config selects and configures a Source; it mirrors the directory-* configuration keys.
type Config struct {
	Type string // "ldap" or "file"
	// File is the path to Authelia's users_database.yml (Type "file").
	File string
	// Group keeps only file users in this group; empty keeps everyone.
	Group string
	LDAP  LDAPConfig
}

// LDAPConfig configures the ldap Source.
type LDAPConfig struct {
	Address              string // ldap://host[:port] or ldaps://host[:port]
	StartTLS             bool
	TLSSkipVerify        bool
	CAFile               string // PEM bundle trusted in addition to the system roots
	BaseDN               string
	User                 string // bind DN; empty binds anonymously
	Password             string
	UsersFilter          string
	AttributeUsername    string
	AttributeMail        string
	AttributeDisplayName string
	AttributeMemberOf    string
	GroupDN              string // keeps only members of this group; empty keeps everyone
}

// New builds the Source cfg.Type names.
func New(cfg Config) (Source, error) {
	switch cfg.Type {
	case "file":
		if cfg.File == "" {
			return nil, errors.New("directory: file source needs a file path")
		}
		return &fileSource{path: cfg.File, group: cfg.Group}, nil
	case "ldap":
		return newLDAPSource(cfg.LDAP)
	default:
		return nil, fmt.Errorf("directory: unknown type %q (want ldap or file)", cfg.Type)
	}
}

// usernameRe duplicates core's username rule (ntfy's user.AllowedUsername) rather than importing
// it: core imports directory for the sync, so directory cannot import core.
var usernameRe = regexp.MustCompile(`^[-_.+@a-zA-Z0-9]{1,128}$`)

func validUsername(u string) bool {
	return usernameRe.MatchString(u) && u != "everyone"
}

// finish applies the rules every source shares: entries core could never provision are dropped, and
// a username listed twice fails the whole list because either entry might be the impostor.
func finish(people []Person) ([]Person, error) {
	people = slices.DeleteFunc(people, func(p Person) bool { return !validUsername(p.Username) })
	slices.SortFunc(people, func(a, b Person) int { return strings.Compare(a.Username, b.Username) })
	for i := 1; i < len(people); i++ {
		if people[i].Username == people[i-1].Username {
			return nil, fmt.Errorf("directory: username %q is listed more than once", people[i].Username)
		}
	}
	return people, nil
}
