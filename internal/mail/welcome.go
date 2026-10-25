package mail

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"net/url"
	texttemplate "text/template"
)

//go:embed templates/welcome.txt templates/welcome.html
var templateFS embed.FS

var (
	welcomeText = texttemplate.Must(texttemplate.ParseFS(templateFS, "templates/welcome.txt"))
	welcomeHTML = htmltemplate.Must(htmltemplate.ParseFS(templateFS, "templates/welcome.html"))
)

const (
	playStoreURL = "https://play.google.com/store/apps/details?id=io.heckel.ntfy"
	fdroidURL    = "https://f-droid.org/packages/io.heckel.ntfy/"
	appStoreURL  = "https://apps.apple.com/app/ntfy/id1625396347"
)

// TopicLink is a web page that subscribes the app to Topic. Mail clients drop ntfy:// links, so the
// page hands out the deep link instead.
type TopicLink struct {
	Topic, URL string
}

// Welcome is what a new ntfy account holder needs to sign in. Password is shown only in this email.
type Welcome struct {
	Username, DisplayName, Password, ServerURL string
	Topics                                     []TopicLink
}

type welcomeData struct {
	Name, Username, Password, ServerURL  string
	PlayStoreURL, FDroidURL, AppStoreURL string
	Topics                               []TopicLink
}

// RenderWelcome renders the welcome email. The caller sets To; ToName is the display name.
func RenderWelcome(w Welcome) (Message, error) {
	if w.Username == "" || w.Password == "" {
		return Message{}, errors.New("mail: welcome needs a username and password")
	}
	server := webURL(w.ServerURL)
	if server == nil {
		return Message{}, fmt.Errorf("mail: invalid server URL %q", w.ServerURL)
	}
	d := welcomeData{
		Name:         w.DisplayName,
		Username:     w.Username,
		Password:     w.Password,
		ServerURL:    w.ServerURL,
		PlayStoreURL: playStoreURL,
		FDroidURL:    fdroidURL,
		AppStoreURL:  appStoreURL,
		Topics:       w.Topics,
	}
	if d.Name == "" {
		d.Name = w.Username
	}
	for _, t := range w.Topics {
		if webURL(t.URL) == nil || t.Topic == "" {
			return Message{}, fmt.Errorf("mail: invalid topic link %q for %q", t.URL, t.Topic)
		}
	}
	var text, html bytes.Buffer
	if err := welcomeText.Execute(&text, d); err != nil {
		return Message{}, fmt.Errorf("mail: render welcome text: %w", err)
	}
	if err := welcomeHTML.Execute(&html, d); err != nil {
		return Message{}, fmt.Errorf("mail: render welcome html: %w", err)
	}
	return Message{
		ToName:  w.DisplayName,
		Subject: "Your ntfy account on " + server.Host,
		Text:    text.String(),
		HTML:    html.String(),
	}, nil
}

// webURL is s parsed when it is an absolute http(s) URL, the only links every mail client keeps.
func webURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil
	}
	return u
}
