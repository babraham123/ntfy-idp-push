package web_test

import (
	"strings"
	"testing"

	"github.com/babraham123/ntfy-idp-push/internal/testutil"
)

// The enrollment result page shows the instructions the browser's platform can follow: the
// Android app subscribes from an ntfy:// link, the iOS app does not open those and subscribes by
// hand, and a desktop is not the phone, so it shows a QR code for Android and the iOS steps.
func TestEnrollResultByPlatform(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	const (
		tapLink = `class="button ntfy-link"`
		qr      = `id="qr"`
		manual  = "If the app does not subscribe"
		ios     = "Use another server"
	)
	for name, tc := range map[string]struct {
		ua        string
		want, not []string
	}{
		"android": {"Mozilla/5.0 (Linux; Android 15; Pixel 9)", []string{tapLink, manual}, []string{qr, ios}},
		"iphone": {"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)",
			[]string{ios, "does not open ntfy:// links", `data-copy="server"`, `data-copy="topic"`}, []string{tapLink, qr, manual}},
		"desktop": {"Mozilla/5.0 (X11; Linux x86_64)", []string{qr, manual, ios}, []string{tapLink}},
	} {
		resp, b := h.Do(t, testutil.Request{Method: "GET", Path: "/enroll", User: "alice", Header: map[string]string{"User-Agent": tc.ua}})
		page := string(b)
		if resp.StatusCode != 200 || !strings.Contains(page, "welcome email") || !strings.Contains(page, "Resend setup notification") {
			t.Fatalf("%s: %d %s", name, resp.StatusCode, page)
		}
		for _, w := range tc.want {
			if !strings.Contains(page, w) {
				t.Errorf("%s page lacks %q", name, w)
			}
		}
		for _, n := range tc.not {
			if strings.Contains(page, n) {
				t.Errorf("%s page shows %q", name, n)
			}
		}
	}
}

// The welcome email's topic links lead to a public page that subscribes the phone to one of the
// user's default topics the way its platform can, and to nothing else.
func TestSubscribePage(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	host := strings.TrimPrefix(h.Cfg.NtfyBaseURL, "http://")
	// The Android button is a Chrome intent, so a phone without ntfy lands on its Play Store listing.
	intent := `intent://` + host + `/alice-inbox?secure=false&amp;user=alice#Intent;scheme=ntfy;package=io.heckel.ntfy;end`
	for name, tc := range map[string]struct {
		ua        string
		want, not []string
	}{
		"android": {"Mozilla/5.0 (Linux; Android 15; Pixel 9)", []string{`href="` + intent + `"`}, []string{`id="qr"`, "Use another server"}},
		"iphone": {"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)",
			[]string{"Use another server", `<code class="ntfy-server">` + h.Cfg.NtfyBaseURL + `</code>`, `<code class="ntfy-topic">alice-inbox</code>`},
			[]string{`href="ntfy://`, `id="qr"`}},
		"desktop": {"Mozilla/5.0 (X11; Linux x86_64)", []string{`id="qr" src="data:image/png;base64,`, "Use another server"}, []string{`class="button ntfy-link"`}},
	} {
		// No User: the phone opening the email is not signed in to the proxy.
		resp, b := h.Do(t, testutil.Request{Method: "GET", Path: "/subscribe/alice-inbox?user=alice", Header: map[string]string{"User-Agent": tc.ua}})
		page := string(b)
		if resp.StatusCode != 200 || !strings.Contains(page, "Subscribe to alice-inbox") || !strings.Contains(page, "<strong>alice</strong>") {
			t.Fatalf("%s: %d %s", name, resp.StatusCode, page)
		}
		for _, w := range tc.want {
			if !strings.Contains(page, w) {
				t.Errorf("%s page lacks %q", name, w)
			}
		}
		for _, n := range tc.not {
			if strings.Contains(page, n) {
				t.Errorf("%s page shows %q", name, n)
			}
		}
	}

	for _, path := range []string{
		"/subscribe/elsewhere?user=alice",
		"/subscribe/bob-inbox?user=alice",
		"/subscribe/alerts",
		"/subscribe/alerts?user=Not%20A%20Name",
	} {
		resp, b := h.Do(t, testutil.Request{Method: "GET", Path: path})
		if resp.StatusCode != 404 || strings.Contains(string(b), "ntfy://") {
			t.Errorf("%s: %d %s", path, resp.StatusCode, b)
		}
	}
}
