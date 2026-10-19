package web_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/babraham123/ntfy-idp-push/internal/testutil"
)

// Token pages (/token/<code>, /token/verify/<device>?t=…) carry their whole credential in the URL,
// and the page-wide policy is same-origin so form posts keep their Origin. Every same-origin
// subresource therefore opts out of Referer by itself, or the proxy's access log would record the
// code with each asset request; the data: icon keeps browsers from fetching /favicon.ico the same way.
func TestSubresourcesSendNoReferrer(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	tag := regexp.MustCompile(`(?s)<(?:link|script|img|iframe|source|video|audio|object|embed)\b[^>]*>`)
	check := func(name, html string) {
		for _, m := range tag.FindAllString(html, -1) {
			if !strings.Contains(m, `href="/`) && !strings.Contains(m, `src="/`) {
				continue
			}
			if !strings.Contains(m, `referrerpolicy="no-referrer"`) {
				t.Errorf("%s: subresource without referrerpolicy: %s", name, m)
			}
		}
	}
	// Rendered pages prove the layout really emits the icon; the template sources cover pages that
	// need a live challenge or code to render.
	for _, page := range []string{"/enroll", "/devices"} {
		resp, b := h.Do(t, testutil.Request{Method: "GET", Path: page, User: "alice"})
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", page, resp.StatusCode, b)
		}
		if !strings.Contains(string(b), `<link rel="icon" href="data:,">`) {
			t.Errorf("%s declares no data: icon", page)
		}
		check(page, string(b))
	}
	files, err := filepath.Glob("templates/*.html")
	if err != nil || len(files) == 0 {
		t.Fatalf("templates: %v %v", files, err)
	}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		check(f, string(src))
	}
}
