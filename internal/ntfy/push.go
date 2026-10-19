package ntfy

import (
	"context"
	"fmt"
	"net/http"
)

// Titles of the pushes the shim sends, by which the ntfy app and the tests tell them apart.
const (
	LoginTitle = "Sign-in request"
	SetupTitle = "Finish setup"
)

// Login is a sign-in request for the phone subscribed to Topic. The push is tagged with
// ChallengeID so that ClearLogin can remove it once the login is decided. Approve opens ApproveURL
// in the browser; Deny posts DenyToken to DenyURL from the app itself.
type Login struct {
	Topic, ChallengeID, Text string
	ApproveURL, DenyURL      string
	DenyToken                string
}

// SendLogin pushes l to its topic.
func (c *Client) SendLogin(ctx context.Context, l Login) error {
	return c.Publish(ctx, &Message{
		Topic:      l.Topic,
		SequenceID: l.ChallengeID,
		Title:      LoginTitle,
		Message:    l.Text,
		Priority:   4,
		Tags:       []string{"lock"},
		Click:      l.ApproveURL,
		Actions: []Action{
			{Action: "view", Label: "Approve", URL: l.ApproveURL, Clear: true},
			{Action: "http", Label: "Deny", URL: l.DenyURL, Method: http.MethodPost, Body: l.DenyToken, Clear: true},
		},
	})
}

// ClearLogin removes the login push for challengeID from the phones subscribed to topic.
func (c *Client) ClearLogin(ctx context.Context, topic, challengeID string) error {
	return c.DeleteMessage(ctx, topic, challengeID)
}

// Setup asks the owner of the phone subscribed to Topic to activate the device named DeviceName by
// opening VerifyURL.
type Setup struct {
	Topic, DeviceName, VerifyURL string
}

// SendSetup pushes s to its topic.
func (c *Client) SendSetup(ctx context.Context, s Setup) error {
	return c.Publish(ctx, &Message{
		Topic:    s.Topic,
		Title:    SetupTitle,
		Message:  "Tap to finish enrolling " + s.DeviceName + " for sign-in approvals.",
		Priority: 4,
		Tags:     []string{"key"},
		Click:    s.VerifyURL,
		Actions:  []Action{{Action: "view", Label: SetupTitle, URL: s.VerifyURL, Clear: true}},
	})
}

// CheckServer fails on an ntfy setup that would let anyone but the phone read pushes: a token that
// is not an admin's, a server that cannot list users, or one that lets anonymous clients read
// probeTopic, which stands in for every push topic. It ends with a publish to probeTopic, so a
// server that accepts reads but refuses writes fails here rather than at the first login.
func (c *Client) CheckServer(ctx context.Context, probeTopic string) error {
	acct, err := c.Account(ctx)
	if err != nil {
		return fmt.Errorf("ntfy admin token: %w", err)
	}
	if acct.Role != "admin" {
		return fmt.Errorf("ntfy token belongs to %q with role %q; admin required", acct.Username, acct.Role)
	}
	if _, err := c.Users(ctx); err != nil {
		return fmt.Errorf("ntfy GET /v1/users: %w", err)
	}
	status, err := c.AnonymousReadStatus(ctx, probeTopic)
	if err != nil {
		return fmt.Errorf("ntfy anonymous probe: %w", err)
	}
	if status != http.StatusUnauthorized && status != http.StatusForbidden {
		return fmt.Errorf("anonymous read of %q returned %d; set ntfy auth-default-access: deny-all", probeTopic, status)
	}
	if err := c.Publish(ctx, &Message{Topic: probeTopic, Message: "probe", Cache: "no", Firebase: "no"}); err != nil {
		return fmt.Errorf("publish to %q: %w", probeTopic, err)
	}
	return nil
}
