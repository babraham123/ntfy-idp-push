// Package token mints the random secrets the shim hands out (links, codes, session IDs, passwords)
// and the hashes it stores in their place.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// Random returns n random bytes, URL-safe base64 encoded.
func Random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Hash is the form a token is stored in.
func Hash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}
