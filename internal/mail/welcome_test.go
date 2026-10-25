package mail

import (
	"strings"
	"testing"
)

func welcome() Welcome {
	return Welcome{
		Username:    "alice",
		DisplayName: "Alice Liddell",
		Password:    "s3cret-Pa55",
		ServerURL:   "https://ntfy.example.com",
		Topics: []TopicLink{
			{Topic: "alerts", URL: "https://push.example.com/subscribe/alerts?user=alice"},
			{Topic: "backups", URL: "https://push.example.com/subscribe/backups?user=alice"},
		},
	}
}

func TestRenderWelcome(t *testing.T) {
	m, err := RenderWelcome(welcome())
	if err != nil {
		t.Fatal(err)
	}
	if m.To != "" || m.ToName != "Alice Liddell" {
		t.Errorf("To, ToName = %q, %q; want caller-set To and the display name", m.To, m.ToName)
	}
	if m.Subject != "Your ntfy account on ntfy.example.com" {
		t.Errorf("Subject = %q", m.Subject)
	}
	want := []string{
		"Alice Liddell",
		"https://ntfy.example.com",
		"alice",
		"s3cret-Pa55",
		"https://play.google.com/store/apps/details?id=io.heckel.ntfy",
		"https://f-droid.org/packages/io.heckel.ntfy/",
		"https://apps.apple.com/app/ntfy/id1625396347",
		"Manage users",
		"https://push.example.com/subscribe/alerts?user=alice",
		"https://push.example.com/subscribe/backups?user=alice",
		"only time the password is shown",
		"resend this email",
	}
	for _, s := range want {
		if !strings.Contains(m.Text, s) {
			t.Errorf("text lacks %q", s)
		}
		if !strings.Contains(m.HTML, s) {
			t.Errorf("html lacks %q", s)
		}
	}
	for _, s := range []string{
		`href="https://ntfy.example.com"`,
		`href="https://push.example.com/subscribe/alerts?user=alice">alerts</a>`,
		`href="https://push.example.com/subscribe/backups?user=alice">backups</a>`,
		`href="https://play.google.com/store/apps/details?id=io.heckel.ntfy"`,
	} {
		if !strings.Contains(m.HTML, s) {
			t.Errorf("html lacks link %q", s)
		}
	}
	if strings.Contains(m.Text, "<") {
		t.Error("text body contains markup")
	}
}

func TestRenderWelcomeFallsBackToUsername(t *testing.T) {
	w := welcome()
	w.DisplayName = ""
	w.Topics = nil
	m, err := RenderWelcome(w)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(m.Text, "Hi alice,") || !strings.Contains(m.HTML, "<p>Hi alice,</p>") {
		t.Errorf("greeting does not use the username:\n%s", m.Text)
	}
	if strings.Contains(m.Text, "/subscribe/") || strings.Contains(m.HTML, "Subscribe") {
		t.Error("subscribe step rendered without topics")
	}
}

func TestRenderWelcomeEscapesHTML(t *testing.T) {
	w := welcome()
	w.DisplayName = `<script>alert("x")</script>`
	w.Password = `p&<u>"'`
	w.Topics = []TopicLink{{Topic: "<i>t</i>", URL: `https://push.example.com/subscribe/t?a=1&b="2"`}}
	m, err := RenderWelcome(w)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"<script>", "<u>", "<i>t</i>", `"2"`} {
		if strings.Contains(m.HTML, raw) {
			t.Errorf("html contains unescaped %q", raw)
		}
	}
	for _, esc := range []string{"&lt;script&gt;", "p&amp;&lt;u&gt;", "&lt;i&gt;t&lt;/i&gt;", "a=1&amp;b="} {
		if !strings.Contains(m.HTML, esc) {
			t.Errorf("html lacks escaped %q", esc)
		}
	}
	if !strings.Contains(m.Text, `p&<u>"'`) {
		t.Error("text body altered the password")
	}
}

func TestRenderWelcomeRejects(t *testing.T) {
	for name, mutate := range map[string]func(*Welcome){
		"no username":    func(w *Welcome) { w.Username = "" },
		"no password":    func(w *Welcome) { w.Password = "" },
		"no server":      func(w *Welcome) { w.ServerURL = "" },
		"server not web": func(w *Welcome) { w.ServerURL = "javascript:alert(1)" },
		"topic not web":  func(w *Welcome) { w.Topics[0].URL = "javascript:alert(1)" },
		// Mail clients drop links with a non-web scheme.
		"topic deep link":    func(w *Welcome) { w.Topics[0].URL = "ntfy://ntfy.example.com/alerts" },
		"topic name empty":   func(w *Welcome) { w.Topics[0].Topic = "" },
		"topic url relative": func(w *Welcome) { w.Topics[0].URL = "/alerts" },
	} {
		t.Run(name, func(t *testing.T) {
			w := welcome()
			mutate(&w)
			if _, err := RenderWelcome(w); err == nil {
				t.Error("RenderWelcome accepted it")
			}
		})
	}
}
