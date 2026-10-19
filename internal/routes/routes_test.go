package routes_test

import (
	"testing"

	"github.com/babraham123/ntfy-idp-push/internal/routes"
)

func TestURLShapes(t *testing.T) {
	const public = "https://push.test"
	// Secrets ride in the fragment, which browsers never send to the server.
	if got := routes.EnrollURL(public, "Ab-_09"); got != public+"/token/#Ab-_09" {
		t.Errorf("EnrollURL %q", got)
	}
	if got := routes.VerifyURL(public, "dev", "t/k"); got != public+"/token/verify/dev#t=t%2Fk" {
		t.Errorf("VerifyURL %q", got)
	}
	if got := routes.QRURL(public, routes.EnrollURL(public, "c")); got != public+"/token/qr?value=https%3A%2F%2Fpush.test%2Ftoken%2F%23c" {
		t.Errorf("QRURL %q", got)
	}
	if got := routes.DenyURL(public, "ch"); got != public+"/challenge/ch/deny" {
		t.Errorf("DenyURL %q", got)
	}
}

func TestEnrollURLRoundTrip(t *testing.T) {
	const public = "https://push.test"
	for _, code := range []string{"abc", "Ab-_09", "ünïcode", "a/b#c"} {
		u := routes.EnrollURL(public, code)
		if got := routes.EnrollCode(public, u); got != code {
			t.Errorf("EnrollCode(EnrollURL(%q)) = %q (url %s)", code, got, u)
		}
	}
	for _, u := range []string{
		"https://evil.example/token/#abc",
		public + "/token/#",
		public + "/token/",
		// The path form links had before codes moved to the fragment.
		public + "/token/abc",
		public + "/token/#a%zz",
		public + "/enroll?code=abc",
	} {
		if got := routes.EnrollCode(public, u); got != "" {
			t.Errorf("EnrollCode(%q) = %q, want none", u, got)
		}
	}
}
