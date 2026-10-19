package directory

import (
	"context"
	"fmt"
	"os"
	"slices"

	"gopkg.in/yaml.v3"
)

// fileSource reads Authelia's users_database.yml on every List, so edits Authelia picks up reach the
// sync without a restart.
type fileSource struct {
	path  string
	group string
}

// autheliaFile is the subset of Authelia's file user database the sync needs; password hashes and
// any other fields are ignored.
type autheliaFile struct {
	Users map[string]struct {
		DisplayName string   `yaml:"displayname"`
		Email       string   `yaml:"email"`
		Groups      []string `yaml:"groups"`
		Disabled    bool     `yaml:"disabled"`
	} `yaml:"users"`
}

func (s *fileSource) read(ctx context.Context) (*autheliaFile, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("directory: %w", err)
	}
	var f autheliaFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("directory: parse %s: %w", s.path, err)
	}
	return &f, nil
}

// Check parses the file and, with a group set, requires some user to be in it: Authelia's file has
// no list of groups, only each user's memberships.
func (s *fileSource) Check(ctx context.Context) error {
	f, err := s.read(ctx)
	if err != nil || s.group == "" {
		return err
	}
	for _, u := range f.Users {
		if slices.Contains(u.Groups, s.group) {
			return nil
		}
	}
	return fmt.Errorf("directory: group %q has no members in %s: %w", s.group, s.path, ErrNoGroup)
}

func (s *fileSource) List(ctx context.Context) ([]Person, error) {
	f, err := s.read(ctx)
	if err != nil {
		return nil, err
	}
	people := make([]Person, 0, len(f.Users))
	for name, u := range f.Users {
		if s.group != "" && !slices.Contains(u.Groups, s.group) {
			continue
		}
		people = append(people, Person{
			Username:    name,
			Email:       u.Email,
			DisplayName: u.DisplayName,
			Groups:      u.Groups,
			Disabled:    u.Disabled,
		})
	}
	return finish(people)
}
