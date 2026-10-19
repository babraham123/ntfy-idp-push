// Package mail renders the welcome email and delivers mail over SMTP.
package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"
)

// Message is one email to one recipient. Text is required; HTML, when set, is sent as the
// preferred alternative.
type Message struct {
	To, ToName, Subject, Text, HTML string
}

// Sender delivers a Message.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// Config is the SMTP relay and envelope sender. Port 465 means implicit TLS; on any other port
// StartTLS requires the server to upgrade the connection before credentials or mail are sent.
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	StartTLS bool
	From     string
	ReplyTo  string
}

const implicitTLSPort = 465

// sendTimeout bounds a send whose context has no deadline, so a stalled relay cannot hang the
// caller (a directory sync round) forever.
const sendTimeout = time.Minute

type smtpSender struct {
	cfg         Config
	addr        string
	from        *mail.Address
	replyTo     *mail.Address
	tls         *tls.Config
	implicitTLS bool
}

// New validates cfg and returns an SMTP Sender. It does not connect.
func New(cfg Config) (Sender, error) {
	if cfg.Host == "" {
		return nil, errors.New("mail: smtp host is required")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("mail: invalid smtp port %d", cfg.Port)
	}
	from, err := mail.ParseAddress(cfg.From)
	if err != nil {
		return nil, fmt.Errorf("mail: invalid from address %q: %w", cfg.From, err)
	}
	var replyTo *mail.Address
	if cfg.ReplyTo != "" {
		if replyTo, err = mail.ParseAddress(cfg.ReplyTo); err != nil {
			return nil, fmt.Errorf("mail: invalid reply-to address %q: %w", cfg.ReplyTo, err)
		}
	}
	return &smtpSender{
		cfg:         cfg,
		addr:        net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		from:        from,
		replyTo:     replyTo,
		tls:         &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12},
		implicitTLS: cfg.Port == implicitTLSPort,
	}, nil
}

func (s *smtpSender) Send(ctx context.Context, m Message) error {
	to, err := recipient(m)
	if err != nil {
		return err
	}
	msg, err := compose(s.from, s.replyTo, to, m, time.Now())
	if err != nil {
		return err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, sendTimeout)
		defer cancel()
	}
	conn, err := s.dial(ctx)
	if err != nil {
		return fmt.Errorf("mail: dial %s: %w", s.addr, err)
	}
	// net/smtp has no context support; closing the connection is what unblocks a pending read.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := s.deliver(conn, to.Address, msg); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("mail: send to %s: %w", to.Address, ctx.Err())
		}
		return fmt.Errorf("mail: send to %s: %w", to.Address, err)
	}
	return nil
}

func (s *smtpSender) dial(ctx context.Context) (net.Conn, error) {
	if s.implicitTLS {
		d := &tls.Dialer{Config: s.tls}
		return d.DialContext(ctx, "tcp", s.addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", s.addr)
}

func (s *smtpSender) deliver(conn net.Conn, rcpt string, msg []byte) error {
	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if err := c.Hello(helloName()); err != nil {
		return err
	}
	if s.cfg.StartTLS && !s.implicitTLS {
		// Refuse rather than fall back to plaintext: a stripped STARTTLS would leak the password.
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("server does not offer STARTTLS")
		}
		if err := c.StartTLS(s.tls); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if s.cfg.User != "" {
		// PlainAuth itself refuses an unencrypted connection to anything but localhost.
		if err := c.Auth(smtp.PlainAuth("", s.cfg.User, s.cfg.Password, s.cfg.Host)); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := c.Mail(s.from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(rcpt); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func helloName() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "localhost"
}

// recipient accepts only a bare address in To, so a crafted value cannot add recipients or
// headers; the display name comes from ToName and is encoded by mail.Address.
func recipient(m Message) (*mail.Address, error) {
	a, err := mail.ParseAddress(m.To)
	if err != nil || a.Address != m.To {
		return nil, fmt.Errorf("mail: invalid recipient %q", m.To)
	}
	return &mail.Address{Name: m.ToName, Address: a.Address}, nil
}

// compose builds the RFC 5322 message: multipart/alternative (text, then the preferred html) or
// plain text alone when there is no HTML. Bodies are quoted-printable so any UTF-8 is 7-bit safe.
func compose(from, replyTo, to *mail.Address, m Message, now time.Time) ([]byte, error) {
	if m.Text == "" {
		return nil, errors.New("mail: message has no text body")
	}
	id, err := messageID(from.Address)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	header := func(k, v string) { fmt.Fprintf(&buf, "%s: %s\r\n", k, v) }
	header("From", from.String())
	header("To", to.String())
	if replyTo != nil {
		header("Reply-To", replyTo.String())
	}
	header("Subject", mime.QEncoding.Encode("utf-8", m.Subject))
	header("Date", now.Format(time.RFC1123Z))
	header("Message-ID", id)
	header("MIME-Version", "1.0")

	if m.HTML == "" {
		header("Content-Type", "text/plain; charset=utf-8")
		header("Content-Transfer-Encoding", "quoted-printable")
		buf.WriteString("\r\n")
		if err := writeQP(&buf, m.Text); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for _, p := range []struct{ typ, content string }{{"text/plain", m.Text}, {"text/html", m.HTML}} {
		pw, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {p.typ + "; charset=utf-8"},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, err
		}
		if err := writeQP(pw, p.content); err != nil {
			return nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	header("Content-Type", mime.FormatMediaType("multipart/alternative", map[string]string{"boundary": mw.Boundary()}))
	buf.WriteString("\r\n")
	buf.Write(body.Bytes())
	return buf.Bytes(), nil
}

func writeQP(w io.Writer, s string) error {
	qp := quotedprintable.NewWriter(w)
	if _, err := io.WriteString(qp, s); err != nil {
		return err
	}
	return qp.Close()
}

func messageID(from string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	domain := "localhost"
	if i := strings.LastIndexByte(from, '@'); i >= 0 {
		domain = from[i+1:]
	}
	return "<" + hex.EncodeToString(b) + "@" + domain + ">", nil
}
