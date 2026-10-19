package mail

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/textproto"
	"regexp"
	"strings"
	"testing"
	"time"
)

// session is what the fake SMTP server saw on one connection.
type session struct {
	auth  string // "user\x00password" from AUTH PLAIN
	from  string
	rcpt  []string
	data  string
	tls   bool // the connection was encrypted when AUTH or MAIL arrived
	quit  bool
	steps []string
}

type fakeSMTP struct {
	addr     string
	port     int
	tls      *tls.Config // offered via STARTTLS, or used from the start when implicit
	implicit bool
	silent   bool // accept but never greet
	reject   bool // refuse RCPT
	sessions chan *session
}

func newFakeSMTP(t *testing.T, configure func(*fakeSMTP)) *fakeSMTP {
	t.Helper()
	f := &fakeSMTP{sessions: make(chan *session, 4)}
	if configure != nil {
		configure(f)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f.addr = ln.Addr().String()
	f.port = ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	s := &session{}
	defer func() { f.sessions <- s }()
	if f.silent {
		_, _ = io.Copy(io.Discard, c)
		return
	}
	if f.implicit {
		c = tls.Server(c, f.tls)
		s.tls = true
	}
	tp := textproto.NewConn(c)
	reply := func(line string) { _ = tp.PrintfLine("%s", line) }
	reply("220 fake ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		verb = strings.ToUpper(verb)
		s.steps = append(s.steps, verb)
		switch verb {
		case "EHLO", "HELO":
			if f.tls != nil && !s.tls {
				reply("250-fake")
				reply("250-STARTTLS")
			} else {
				reply("250-fake")
			}
			reply("250 AUTH PLAIN")
		case "STARTTLS":
			reply("220 go ahead")
			tc := tls.Server(c, f.tls)
			if err := tc.Handshake(); err != nil {
				return
			}
			c, s.tls = tc, true
			tp = textproto.NewConn(c)
		case "AUTH":
			cred, _ := strings.CutPrefix(arg, "PLAIN ")
			b, _ := base64.StdEncoding.DecodeString(cred)
			s.auth = strings.TrimPrefix(string(b), "\x00")
			if !s.tls {
				s.auth = "PLAINTEXT:" + s.auth
			}
			reply("235 ok")
		case "MAIL":
			s.from = strings.TrimSuffix(strings.TrimPrefix(arg, "FROM:<"), ">")
			reply("250 ok")
		case "RCPT":
			if f.reject {
				reply("550 no such user")
				continue
			}
			s.rcpt = append(s.rcpt, strings.TrimSuffix(strings.TrimPrefix(arg, "TO:<"), ">"))
			reply("250 ok")
		case "DATA":
			reply("354 go ahead")
			b, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			s.data = string(b)
			reply("250 queued")
		case "QUIT":
			s.quit = true
			reply("221 bye")
			return
		default:
			reply("502 unsupported")
		}
	}
}

func (f *fakeSMTP) session(t *testing.T) *session {
	t.Helper()
	select {
	case s := <-f.sessions:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("no SMTP session")
		return nil
	}
}

// selfSigned returns a server config for 127.0.0.1 and a client pool that trusts it.
func selfSigned(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, pool
}

func newSender(t *testing.T, f *fakeSMTP, cfg Config, roots *x509.CertPool) *smtpSender {
	t.Helper()
	cfg.Host = "127.0.0.1"
	cfg.Port = f.port
	if cfg.From == "" {
		cfg.From = "ntfy-idp-push <push@example.com>"
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ss := s.(*smtpSender)
	ss.tls.RootCAs = roots
	// Implicit TLS is chosen by port 465, which a test cannot bind.
	ss.implicitTLS = f.implicit
	return ss
}

func send(t *testing.T, s Sender, m Message) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.Send(ctx, m)
}

var testMessage = Message{
	To:      "alice@example.com",
	ToName:  "Alice Liddell",
	Subject: "Your ntfy account on ntfy.example.com",
	Text:    "Hi Alice,\nyour password is ünïcode=ok\n" + strings.Repeat("long line ", 20) + "\n",
	HTML:    "<p>Hi Alice,</p>\n<p>password <code>ünïcode=ok</code></p>\n",
}

// parsed is a delivered message read back as a mail client would.
type parsed struct {
	header      mail.Header
	parts       map[string]string // media type -> decoded body
	order       []string
	contentType string
}

func parse(t *testing.T, data string) parsed {
	t.Helper()
	msg, err := mail.ReadMessage(strings.NewReader(data))
	if err != nil {
		t.Fatalf("delivered message does not parse: %v\n%s", err, data)
	}
	p := parsed{header: msg.Header, parts: map[string]string{}}
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	p.contentType = mt
	if !strings.HasPrefix(mt, "multipart/") {
		body, _ := io.ReadAll(msg.Body)
		p.parts[mt] = string(body)
		return p
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		pt, pp, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil || pp["charset"] != "utf-8" {
			t.Errorf("part content type %q: %v", part.Header.Get("Content-Type"), err)
		}
		// NextPart decodes quoted-printable, line endings included, back to the original text.
		body, err := io.ReadAll(part)
		if err != nil {
			t.Fatal(err)
		}
		p.parts[pt] = string(body)
		p.order = append(p.order, pt)
	}
	return p
}

func TestSendPlainWithAuth(t *testing.T) {
	f := newFakeSMTP(t, nil)
	s := newSender(t, f, Config{User: "relay", Password: "pw", ReplyTo: "Help Desk <help@example.com>"}, nil)
	before := time.Now().Add(-time.Second)
	if err := send(t, s, testMessage); err != nil {
		t.Fatal(err)
	}
	got := f.session(t)
	// PlainAuth permits an unencrypted connection only because the relay is localhost.
	if got.auth != "PLAINTEXT:relay\x00pw" {
		t.Errorf("auth = %q", got.auth)
	}
	if got.from != "push@example.com" || len(got.rcpt) != 1 || got.rcpt[0] != "alice@example.com" {
		t.Errorf("envelope = %q -> %q", got.from, got.rcpt)
	}
	if !got.quit {
		t.Error("no QUIT")
	}
	// ReadDotBytes hands the data over with CRLF already turned into LF.
	_, body, found := strings.Cut(got.data, "\n\n")
	if !found || body == "" {
		t.Fatalf("no body after the header block:\n%s", got.data)
	}
	for _, line := range strings.Split(body, "\n") {
		if len(line) > 76 {
			t.Errorf("body line longer than quoted-printable's 76 octets: %q", line)
		}
	}

	p := parse(t, got.data)
	h := p.header
	if from, err := h.AddressList("From"); err != nil || len(from) != 1 || *from[0] != (mail.Address{Name: "ntfy-idp-push", Address: "push@example.com"}) {
		t.Errorf("From = %v, %v", from, err)
	}
	if to, err := h.AddressList("To"); err != nil || len(to) != 1 || *to[0] != (mail.Address{Name: "Alice Liddell", Address: "alice@example.com"}) {
		t.Errorf("To = %v, %v", to, err)
	}
	if rt, err := h.AddressList("Reply-To"); err != nil || len(rt) != 1 || rt[0].Address != "help@example.com" {
		t.Errorf("Reply-To = %v, %v", rt, err)
	}
	if subj, err := new(mime.WordDecoder).DecodeHeader(h.Get("Subject")); err != nil || subj != testMessage.Subject {
		t.Errorf("Subject = %q, %v", subj, err)
	}
	if d, err := h.Date(); err != nil || d.Before(before) || d.After(time.Now().Add(time.Second)) {
		t.Errorf("Date = %v, %v", d, err)
	}
	if !regexp.MustCompile(`^<[0-9a-f]{32}@example\.com>$`).MatchString(h.Get("Message-ID")) {
		t.Errorf("Message-ID = %q", h.Get("Message-ID"))
	}
	if h.Get("MIME-Version") != "1.0" {
		t.Errorf("MIME-Version = %q", h.Get("MIME-Version"))
	}
	if p.contentType != "multipart/alternative" || strings.Join(p.order, ",") != "text/plain,text/html" {
		t.Fatalf("structure = %s %v; want multipart/alternative text/plain,text/html", p.contentType, p.order)
	}
	if p.parts["text/plain"] != testMessage.Text {
		t.Errorf("text part = %q", p.parts["text/plain"])
	}
	if p.parts["text/html"] != testMessage.HTML {
		t.Errorf("html part = %q", p.parts["text/html"])
	}
}

func TestSendTextOnly(t *testing.T) {
	f := newFakeSMTP(t, nil)
	s := newSender(t, f, Config{}, nil)
	m := testMessage
	m.HTML = ""
	if err := send(t, s, m); err != nil {
		t.Fatal(err)
	}
	got := f.session(t)
	if got.auth != "" || got.steps[1] == "AUTH" {
		t.Errorf("authenticated without a user: %q", got.steps)
	}
	p := parse(t, got.data)
	if p.contentType != "text/plain" || len(p.parts) != 1 {
		t.Fatalf("structure = %s %v", p.contentType, p.parts)
	}
	if p.header.Get("Reply-To") != "" {
		t.Errorf("Reply-To set without config: %q", p.header.Get("Reply-To"))
	}
}

func TestSendStartTLS(t *testing.T) {
	serverTLS, roots := selfSigned(t)
	f := newFakeSMTP(t, func(f *fakeSMTP) { f.tls = serverTLS })
	s := newSender(t, f, Config{User: "relay", Password: "pw", StartTLS: true}, roots)
	if err := send(t, s, testMessage); err != nil {
		t.Fatal(err)
	}
	got := f.session(t)
	if !got.tls || got.auth != "relay\x00pw" {
		t.Errorf("tls = %v, auth = %q; want credentials only after STARTTLS", got.tls, got.auth)
	}
	if want := "EHLO,STARTTLS,EHLO,AUTH,MAIL,RCPT,DATA,QUIT"; strings.Join(got.steps, ",") != want {
		t.Errorf("steps = %v; want %s", got.steps, want)
	}
	if parse(t, got.data).parts["text/html"] != testMessage.HTML {
		t.Error("html part lost over TLS")
	}
}

func TestSendStartTLSUntrustedCert(t *testing.T) {
	serverTLS, _ := selfSigned(t)
	f := newFakeSMTP(t, func(f *fakeSMTP) { f.tls = serverTLS })
	s := newSender(t, f, Config{User: "relay", Password: "pw", StartTLS: true}, x509.NewCertPool())
	if err := send(t, s, testMessage); err == nil {
		t.Fatal("sent through a server with an untrusted certificate")
	}
	if got := f.session(t); got.auth != "" || got.from != "" {
		t.Errorf("leaked auth %q / mail from %q", got.auth, got.from)
	}
}

func TestSendRequiresOfferedStartTLS(t *testing.T) {
	f := newFakeSMTP(t, nil)
	s := newSender(t, f, Config{User: "relay", Password: "pw", StartTLS: true}, nil)
	err := send(t, s, testMessage)
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("err = %v; want a STARTTLS refusal", err)
	}
	if got := f.session(t); got.auth != "" || got.from != "" {
		t.Errorf("proceeded in plaintext: auth %q, mail from %q", got.auth, got.from)
	}
}

func TestSendImplicitTLS(t *testing.T) {
	serverTLS, roots := selfSigned(t)
	f := newFakeSMTP(t, func(f *fakeSMTP) { f.tls, f.implicit = serverTLS, true })
	s := newSender(t, f, Config{User: "relay", Password: "pw", StartTLS: true}, roots)
	if err := send(t, s, testMessage); err != nil {
		t.Fatal(err)
	}
	got := f.session(t)
	if got.auth != "relay\x00pw" || strings.Contains(strings.Join(got.steps, ","), "STARTTLS") {
		t.Errorf("auth = %q, steps = %v; want TLS from the first byte", got.auth, got.steps)
	}
	if len(got.rcpt) != 1 || got.data == "" {
		t.Errorf("not delivered: %+v", got)
	}
}

func TestSendRejectedRecipient(t *testing.T) {
	f := newFakeSMTP(t, func(f *fakeSMTP) { f.reject = true })
	s := newSender(t, f, Config{}, nil)
	if err := send(t, s, testMessage); err == nil || !strings.Contains(err.Error(), "550") {
		t.Fatalf("err = %v; want the 550", err)
	}
	if got := f.session(t); got.data != "" {
		t.Error("sent DATA after a rejected recipient")
	}
}

func TestSendHonorsContext(t *testing.T) {
	f := newFakeSMTP(t, func(f *fakeSMTP) { f.silent = true })
	s := newSender(t, f, Config{}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := s.Send(ctx, testMessage)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v; want deadline exceeded", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Error("Send outlived its context")
	}
}

func TestSendRejectsBadRecipient(t *testing.T) {
	s, err := New(Config{Host: "127.0.0.1", Port: 1, From: "push@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, to := range []string{"", "not an address", "Bob <bob@example.com>", "a@example.com, b@example.com", "a@example.com\r\nBcc: b@example.com"} {
		m := testMessage
		m.To = to
		// Port 1 is never dialed: the recipient is refused first.
		if err := send(t, s, m); err == nil || !strings.Contains(err.Error(), "invalid recipient") {
			t.Errorf("To %q: err = %v", to, err)
		}
	}
	m := testMessage
	m.Text = ""
	if err := send(t, s, m); err == nil || !strings.Contains(err.Error(), "no text body") {
		t.Errorf("empty text: err = %v", err)
	}
}

func TestComposeEncodesHeaderValues(t *testing.T) {
	from := &mail.Address{Name: "Push", Address: "push@example.com"}
	to := &mail.Address{Name: "Évil\r\nBcc: x@example.com", Address: "alice@example.com"}
	m := testMessage
	m.Subject = "hi\r\nBcc: y@example.com ✓"
	b, err := compose(from, nil, to, m, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p := parse(t, string(b))
	if bcc := p.header.Get("Bcc"); bcc != "" {
		t.Fatalf("header injected: Bcc %q", bcc)
	}
	if got, err := p.header.AddressList("To"); err != nil || len(got) != 1 || *got[0] != *to {
		t.Errorf("To = %v, %v", got, err)
	}
	if subj, _ := new(mime.WordDecoder).DecodeHeader(p.header.Get("Subject")); subj != m.Subject {
		t.Errorf("Subject = %q", subj)
	}
}

func TestNewValidates(t *testing.T) {
	ok := Config{Host: "smtp.example.com", Port: 587, From: "ntfy-idp-push <push@example.com>"}
	if _, err := New(ok); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Host: "smtp.example.com", Port: 465, From: ok.From})
	if err != nil || !s.(*smtpSender).implicitTLS {
		t.Errorf("port 465: implicit TLS not selected (%v)", err)
	}
	if s.(*smtpSender).tls.ServerName != "smtp.example.com" {
		t.Error("TLS does not verify the configured host")
	}
	for name, mutate := range map[string]func(*Config){
		"no host":      func(c *Config) { c.Host = "" },
		"no port":      func(c *Config) { c.Port = 0 },
		"port range":   func(c *Config) { c.Port = 70000 },
		"no from":      func(c *Config) { c.From = "" },
		"bad from":     func(c *Config) { c.From = "push at example" },
		"bad reply-to": func(c *Config) { c.ReplyTo = "help@" },
	} {
		c := ok
		mutate(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
