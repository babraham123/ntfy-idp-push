package duoapi

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	errNoCredentials = errors.New("missing request credentials")
	errBadIKey       = errors.New("invalid integration key")
	errBadSignature  = errors.New("invalid signature")
	errSkew          = errors.New("request date out of range")
	errReplay        = errors.New("duplicate request")
)

// CanonParams is Duo's parameter canonicalization: keys and values sorted, query-escaped with %20.
func CanonParams(params url.Values) string {
	sorted := url.Values{}
	for k, v := range params {
		vs := append([]string(nil), v...)
		sort.Strings(vs)
		sorted[k] = vs
	}
	return strings.ReplaceAll(sorted.Encode(), "+", "%20")
}

// CanonV2 is the canonical string of signature version 2 (form-encoded requests).
func CanonV2(date, method, host, path string, params url.Values) string {
	return strings.Join([]string{date, strings.ToUpper(method), strings.ToLower(host), path, CanonParams(params)}, "\n")
}

// CanonV5 is v2 plus the SHA-512 of the body and of the x-duo-* headers (JSON requests).
func CanonV5(date, method, host, path string, params url.Values, body []byte, duoHeaders http.Header) string {
	return CanonV2(date, method, host, path, params) + "\n" + sha512Hex(body) + "\n" + sha512Hex([]byte(canonDuoHeaders(duoHeaders)))
}

func sha512Hex(b []byte) string {
	h := sha512.Sum512(b)
	return hex.EncodeToString(h[:])
}

// canonDuoHeaders joins lower-cased x-duo-* header names and values, sorted by name, with NULs,
// as duo_client_python does for v5.
func canonDuoHeaders(h http.Header) string {
	var names []string
	for k := range h {
		if l := strings.ToLower(k); strings.HasPrefix(l, "x-duo-") {
			names = append(names, l)
		}
	}
	sort.Strings(names)
	parts := make([]string, 0, 2*len(names))
	for _, n := range names {
		parts = append(parts, n, h.Get(n))
	}
	return strings.Join(parts, "\x00")
}

func hmacHex(newHash func() hash.Hash, key, msg string) string {
	m := hmac.New(newHash, []byte(key))
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

// SignatureHeader builds the Authorization header value a Duo client sends.
func SignatureHeader(ikey, skey, canon string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(ikey+":"+hmacHex(sha512.New, skey, canon)))
}

// signedRequest is the parsed, verified-for-shape part of an incoming signed request.
type signedRequest struct {
	date   string
	ikey   string
	sig    string
	params url.Values
	body   []byte
	json   bool
}

func parseAuthorization(r *http.Request) (ikey, sig string, err error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Basic ") {
		return "", "", errNoCredentials
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, "Basic "))
	if err != nil {
		return "", "", errNoCredentials
	}
	ikey, sig, ok := strings.Cut(string(raw), ":")
	if !ok || ikey == "" || sig == "" {
		return "", "", errNoCredentials
	}
	return ikey, strings.ToLower(sig), nil
}

func parseDate(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC1123Z, time.RFC1123, time.RFC850, time.ANSIC} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errSkew
}

// verify checks the signature against each accepted secret key. Only a body identifies the
// signing variant: a JSON body is v5, a form body v2. A bodyless request (GET/DELETE) carries no
// Content-Type in either client, so it may be v2 or v5 and both are tried. SHA-1 (older
// duo_client_python configurations) exists only for v2.
func verify(req *signedRequest, r *http.Request, host string, skeys []string) error {
	v2 := CanonV2(req.date, r.Method, host, r.URL.Path, req.params)
	v5 := CanonV5(req.date, r.Method, host, r.URL.Path, req.params, req.body, r.Header)
	var canons []string
	switch {
	case req.json:
		canons = []string{v5}
	case len(req.body) == 0:
		canons = []string{v2, v5}
	default:
		canons = []string{v2}
	}
	newHash := sha512.New
	switch len(req.sig) {
	case 2 * sha512.Size:
	case 2 * sha1.Size:
		if req.json {
			return errBadSignature
		}
		newHash, canons = sha1.New, []string{v2}
	default:
		return errBadSignature
	}
	for _, k := range skeys {
		for _, canon := range canons {
			if subtle.ConstantTimeCompare([]byte(hmacHex(newHash, k, canon)), []byte(req.sig)) == 1 {
				return nil
			}
		}
	}
	return errBadSignature
}

// replayCache remembers signatures for the skew window; a signature seen twice is refused.
type replayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newReplayCache() *replayCache { return &replayCache{seen: map[string]time.Time{}} }

func (c *replayCache) check(date, sig string, now time.Time, window time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, exp := range c.seen {
		if now.After(exp) {
			delete(c.seen, k)
		}
	}
	key := date + "\x00" + sig
	if _, ok := c.seen[key]; ok {
		return errReplay
	}
	c.seen[key] = now.Add(2 * window)
	return nil
}
