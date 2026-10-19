package testutil

import (
	"context"
	"slices"
	"strings"
	"sync"

	"github.com/babraham123/ntfy-idp-push/internal/directory"
)

var _ directory.Source = (*FakeDirectory)(nil)

// FakeDirectory is a directory.Source listing whatever the test set, with the real sources'
// contract: sorted by username. The zero value lists nobody.
type FakeDirectory struct {
	mu     sync.Mutex
	people []directory.Person
	err    error
}

// Set replaces the people the directory lists.
func (f *FakeDirectory) Set(people ...directory.Person) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.people = slices.Clone(people)
}

// Fail makes every later List return err; nil restores listing.
func (f *FakeDirectory) Fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *FakeDirectory) List(ctx context.Context) ([]directory.Person, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	out := slices.Clone(f.people)
	slices.SortFunc(out, func(a, b directory.Person) int { return strings.Compare(a.Username, b.Username) })
	return out, nil
}
