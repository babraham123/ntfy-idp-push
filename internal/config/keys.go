package config

import (
	"crypto/rand"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const keyAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomString(alphabet string, n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		// 256 % 36 bias is negligible for keys of this length.
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// NewIntegrationKey returns a Duo-shaped integration key ("DI" + 18 chars).
func NewIntegrationKey() string { return "DI" + randomString(keyAlphabet, 18) }

// NewSecretKey returns a 40-character secret key, as Duo issues.
func NewSecretKey() string {
	return randomString("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 40)
}

// RotateSecretKey rewrites path with a new duo-secret-key, keeping the old one as
// duo-secret-key-previous (accepted for duo-key-grace). Comments and ordering are preserved.
func RotateSecretKey(path string, now time.Time) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return "", err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return "", fmt.Errorf("%s: not a YAML mapping", path)
	}
	m := doc.Content[0]
	old := lookup(m, "duo-secret-key")
	if old == "" {
		return "", fmt.Errorf("%s: no duo-secret-key to rotate (secrets from env must be rotated by hand)", path)
	}
	key := NewSecretKey()
	set(m, "duo-secret-key", key)
	set(m, "duo-secret-key-previous", old)
	set(m, "duo-secret-key-rotated-at", now.UTC().Format(time.RFC3339))
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return "", err
	}
	return key, os.Rename(tmp, path)
}

func lookup(m *yaml.Node, key string) string {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1].Value
		}
	}
	return ""
}

func set(m *yaml.Node, key, value string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1].Kind, m.Content[i+1].Tag, m.Content[i+1].Value = yaml.ScalarNode, "!!str", value
			return
		}
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value, Style: yaml.DoubleQuotedStyle})
}
