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
	if got := routes.SubscribeURL(public, "a b/c", "dé"); got != public+"/subscribe/a%20b%2Fc?user=d%C3%A9" {
		t.Errorf("SubscribeURL %q", got)
	}
	if got := routes.DenyURL(public, "ch"); got != public+"/challenge/ch/deny" {
		t.Errorf("DenyURL %q", got)
	}
}
