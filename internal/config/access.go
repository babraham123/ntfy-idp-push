package config

import (
	"fmt"
	"strings"
)

// Permission values are ntfy's canonical spellings, as accepted by PUT /v1/users/access.
const (
	PermReadWrite = "read-write"
	PermReadOnly  = "read-only"
	PermWriteOnly = "write-only"
	PermDenyAll   = "deny-all"
)

// placeholderUser stands in for ${user} when validating config before any real username is known.
// It is chosen so it cannot itself collide with a topic prefix check.
const placeholderUser = "u0"

type AccessRule struct {
	Pattern    string // may contain ${user} and ntfy's * wildcard
	Permission string
}

// Grant is a rule with ${user} expanded, as applied to ntfy.
type Grant struct {
	Topic      string `json:"topic"`
	Permission string `json:"permission"`
}

func ParsePermission(s string) (string, error) {
	switch strings.ToLower(s) {
	case "rw", "read-write":
		return PermReadWrite, nil
	case "ro", "read-only", "read":
		return PermReadOnly, nil
	case "wo", "write-only", "write":
		return PermWriteOnly, nil
	case "deny", "deny-all", "none":
		return PermDenyAll, nil
	}
	return "", fmt.Errorf("unknown permission %q", s)
}

func ParseAccessRules(entries []string) ([]AccessRule, error) {
	rules := make([]AccessRule, 0, len(entries))
	for _, e := range entries {
		i := strings.LastIndex(e, ":")
		if i <= 0 {
			return nil, fmt.Errorf("enroll-access %q: want <topic-pattern>:<access>", e)
		}
		perm, err := ParsePermission(e[i+1:])
		if err != nil {
			return nil, fmt.Errorf("enroll-access %q: %w", e, err)
		}
		rules = append(rules, AccessRule{Pattern: e[:i], Permission: perm})
	}
	return rules, nil
}

func Expand(pattern, username string) string {
	return strings.ReplaceAll(pattern, "${user}", username)
}

// Expand returns the grants for username, refusing any that would reach push topics.
func ExpandAccess(rules []AccessRule, prefix, username string) ([]Grant, error) {
	if err := ValidateAccess(rules, prefix, username); err != nil {
		return nil, err
	}
	grants := make([]Grant, 0, len(rules))
	for _, r := range rules {
		grants = append(grants, Grant{Topic: Expand(r.Pattern, username), Permission: r.Permission})
	}
	return grants, nil
}

// ValidateAccess refuses patterns that could match a push topic (<prefix>*) or everything. With
// username empty it checks the config shape; at enrollment it is re-run with the real username,
// because "${user}-*" for a user named like the prefix would otherwise grant every push topic.
func ValidateAccess(rules []AccessRule, prefix, username string) error {
	if username == "" {
		username = placeholderUser
	}
	seen := map[string]bool{}
	for _, r := range rules {
		p := Expand(r.Pattern, username)
		// ntfy keeps one ACL entry per user and pattern, so a second rule would silently replace the first.
		if seen[p] {
			return fmt.Errorf("enroll-access has two rules for %q", p)
		}
		seen[p] = true
		if p == "" || strings.Trim(p, "*") == "" || p == "everyone" {
			return fmt.Errorf("enroll-access pattern %q matches every topic", r.Pattern)
		}
		if strings.ContainsAny(p, " /") {
			return fmt.Errorf("enroll-access pattern %q is not a valid topic pattern", r.Pattern)
		}
		if GlobsIntersect(p, prefix+"*") {
			return fmt.Errorf("enroll-access pattern %q (as %q) can match push topics %s*", r.Pattern, p, prefix)
		}
	}
	return nil
}

// Readable reports whether topic (with ${user} expanded) is readable under the rules, using the
// rule ntfy applies regardless of config order: the longest matching pattern, then the one that
// allows write, then the one that allows read (ntfy user/manager_*.go).
func Readable(rules []AccessRule, topic, username string) bool {
	topic = Expand(topic, username)
	var best *AccessRule
	var bestRank [3]int
	for i, r := range rules {
		p := Expand(r.Pattern, username)
		if !GlobMatch(p, topic) {
			continue
		}
		if rank := aclRank(p, r.Permission); best == nil || rankAbove(rank, bestRank) {
			best, bestRank = &rules[i], rank
		}
	}
	return best != nil && canRead(best.Permission)
}

func canRead(perm string) bool  { return perm == PermReadWrite || perm == PermReadOnly }
func canWrite(perm string) bool { return perm == PermReadWrite || perm == PermWriteOnly }

func aclRank(pattern, perm string) [3]int {
	b := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	return [3]int{len(pattern), b(canWrite(perm)), b(canRead(perm))}
}

func rankAbove(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

// GlobMatch matches s against an ntfy topic pattern where * is the only wildcard.
func GlobMatch(pattern, s string) bool {
	return GlobsIntersect(pattern, s) && !strings.Contains(s, "*")
}

// GlobsIntersect reports whether some string matches both * patterns.
func GlobsIntersect(a, b string) bool {
	type key struct{ i, j int }
	memo := map[key]bool{}
	var f func(i, j int) bool
	f = func(i, j int) bool {
		k := key{i, j}
		if v, ok := memo[k]; ok {
			return v
		}
		var r bool
		switch {
		case i == len(a) && j == len(b):
			r = true
		case i < len(a) && a[i] == '*':
			r = f(i+1, j) || (j < len(b) && f(i, j+1))
		case j < len(b) && b[j] == '*':
			r = f(i, j+1) || (i < len(a) && f(i+1, j))
		case i < len(a) && j < len(b):
			r = a[i] == b[j] && f(i+1, j+1)
		}
		memo[k] = r
		return r
	}
	return f(0, 0)
}
