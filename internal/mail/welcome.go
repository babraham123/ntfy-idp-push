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

// TopicLink is an ntfy:// deep link that subscribes the app to Topic.
type TopicLink struct {
	Topic, URL string
}

// Welcome is what a new ntfy account holder needs to sign in. Password is shown only in this email.
type Welcome struct {
	Username, DisplayName, Password, ServerURL string
	Topics                                     []TopicLink
}

type welcomeTopic struct {
	Topic string
	// URL is pre-vetted as ntfy://; html/template would otherwise replace the non-web scheme.
	URL htmltemplate.URL
}

type welcomeData struct {
	Name, Username, Password, ServerURL  string
	PlayStoreURL, FDroidURL, AppStoreURL string
	Topics                               []welcomeTopic
}

// RenderWelcome renders the welcome email. The caller sets To; ToName is the display name.
func RenderWelcome(w Welcome) (Message, error) {
	if w.Username == "" || w.Password == "" {
		return Message{}, errors.New("mail: welcome needs a username and password")
	}
	server, err := url.Parse(w.ServerURL)
	if err != nil || (server.Scheme != "https" && server.Scheme != "http") || server.Host == "" {
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
	}
	if d.Name == "" {
		d.Name = w.Username
	}
	for _, t := range w.Topics {
		u, err := url.Parse(t.URL)
		if err != nil || u.Scheme != "ntfy" || t.Topic == "" {
			return Message{}, fmt.Errorf("mail: invalid topic link %q for %q", t.URL, t.Topic)
		}
		d.Topics = append(d.Topics, welcomeTopic{Topic: t.Topic, URL: htmltemplate.URL(t.URL)})
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
