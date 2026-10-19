package web_test

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/babraham123/ntfy-idp-push/internal/core"
	"github.com/babraham123/ntfy-idp-push/internal/testutil"
)

// Enrollment codes and verify tokens ride only in the fragment, which browsers never send: the
// server reads them from request bodies alone, and a link that puts one in the path or query is
// refused without being looked at.
func TestTokenSecretsTravelInFragment(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	ctx := context.Background()
	get := func(path string) (int, string) {
		t.Helper()
		resp, b := h.Do(t, testutil.Request{Method: "GET", Path: path})
		// A redirect could lose the fragment the page reads its secret from.
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			t.Fatalf("GET %s redirected: %d %s", path, resp.StatusCode, resp.Header.Get("Location"))
		}
		return resp.StatusCode, string(b)
	}

	l, err := h.Svc.CreateEnrollLink(ctx, "erin", core.EnrollCodeTTL)
	if err != nil {
		t.Fatal(err)
	}
	link := l.URL
	path, code := testutil.Fragment(t, link)
	active := func(deviceID string) bool {
		t.Helper()
		_, devs, err := h.Svc.DevicesOf(ctx, "erin")
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range devs {
			if d.ID == deviceID {
				return d.Active()
			}
		}
		return false
	}
	if path != "/token/" || code == "" {
		t.Fatalf("enrollment link %q", link)
	}

	// The page is the same with or without a code: the server cannot know it.
	st, page := get("/token/")
	if st != 200 || strings.Contains(page, code) || strings.Contains(page, "erin") {
		t.Fatalf("enrollment page: %d %s", st, page)
	}
	// A code in the path is a stale link: the same invalid-link page a forged one gets, so the code
	// was never resolved.
	st, stale := get("/token/" + code)
	if _, forged := get("/token/forged"); st != 410 || stale != forged || !strings.Contains(stale, "Link expired") {
		t.Fatalf("code in the path: %d %s", st, stale)
	}
	for _, p := range []string{"/token", "/token/begin", "/token/verify/dev/extra"} {
		if st, body := get(p); st != 410 || body != stale {
			t.Errorf("GET %s: %d %s", p, st, body)
		}
	}
	// The message the page shows when the fragment is missing or begin finds the code gone is the
	// one the server answers a dead link with.
	body := regexp.MustCompile(`(?s)<h1>.*</p>`).FindString(stale)
	if !strings.Contains(page, `<template id="invalid" data-title="Link expired · ntfy-idp-push">`+body+`</template>`) {
		t.Fatalf("enrollment page lacks the invalid-link message %q: %s", body, page)
	}
	// Without a fragment the page posts no code; begin answers as for a dead link.
	resp, b := h.Do(t, testutil.Request{Method: "POST", Path: "/token/begin", Body: []byte(`{"name":"Phone"}`)})
	if resp.StatusCode != 410 || !strings.Contains(string(b), core.ErrInvalidCode.Error()) {
		t.Fatalf("begin without a code: %d %s", resp.StatusCode, b)
	}

	// The code from the fragment, posted with begin, enrolls erin.
	e, st, b := h.FinishEnroll(t, "", link, testutil.NewAuthenticator(t, testutil.PublicURL))
	if st != 200 {
		t.Fatalf("enroll by link: %d %s", st, b)
	}
	m := h.Ntfy.NextPublish(t)
	verify := regexp.MustCompile(`^` + regexp.QuoteMeta(testutil.PublicURL+"/token/verify/"+e.DeviceID) + `#t=[A-Za-z0-9_-]+$`)
	if !verify.MatchString(m.Click) || len(m.Actions) != 1 || m.Actions[0].URL != m.Click {
		t.Fatalf("setup push links: %s %+v", m.Click, m.Actions)
	}
	vpath, frag := testutil.Fragment(t, m.Click)
	tok, _ := url.ParseQuery(frag)
	query := vpath + "?t=" + url.QueryEscape(tok.Get("t"))

	// A token in the query string neither reaches the form nor activates the device.
	if st, page := get(query); st != 200 || strings.Contains(page, tok.Get("t")) {
		t.Fatalf("verify page with a query token: %d %s", st, page)
	}
	resp, _ = h.Do(t, testutil.Request{Method: "POST", Path: query, Body: []byte{},
		Header: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}})
	if resp.StatusCode != 410 || active(e.DeviceID) {
		t.Fatalf("verify with a query token: %d, active %v", resp.StatusCode, active(e.DeviceID))
	}
	h.VerifyFromPush(t, m)
	if !active(e.DeviceID) {
		t.Fatal("device not active after Activate")
	}
}
