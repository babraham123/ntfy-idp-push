// Package ntfy is a client for the ntfy admin and publish APIs.
package ntfy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// ErrNotSupported means the server lacks an optional endpoint (e.g. ntfy#597 enroll codes).
var ErrNotSupported = errors.New("not supported by ntfy server")

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{BaseURL: baseURL, Token: token, HTTP: &http.Client{Timeout: 15 * time.Second}}
}

type HTTPError struct {
	Method, Path string
	Status       int
	// Code is ntfy's error code from the JSON body (e.g. 40031), or 0.
	Code int
	Body string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("ntfy %s %s: %d %s", e.Method, e.Path, e.Status, e.Body)
}

func IsStatus(err error, status int) bool {
	var he *HTTPError
	return errors.As(err, &he) && he.Status == status
}

// codeUserNotFound is ntfy's "invalid request: user does not exist" (HTTP 400).
const codeUserNotFound = 40031

// IsUserNotFound reports whether ntfy refused the call because the user does not exist.
func IsUserNotFound(err error) bool {
	var he *HTTPError
	return errors.As(err, &he) && he.Code == codeUserNotFound
}

// maxResponse bounds every ntfy response read into memory.
const maxResponse = 1 << 20

func (c *Client) do(ctx context.Context, method, path string, in, out any, auth bool) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if resp.StatusCode/100 != 2 {
		he := &HTTPError{Method: method, Path: path, Status: resp.StatusCode, Body: string(bytes.TrimSpace(b))}
		var body struct{ Code int }
		if json.Unmarshal(b, &body) == nil {
			he.Code = body.Code
		}
		return he
	}
	if len(b) > maxResponse {
		// GET /v1/users lists every ntfy user with its grants, so this is reached first by a large
		// user base; a truncated list must never be mistaken for the whole one.
		return fmt.Errorf("ntfy %s %s: response exceeds the %d MiB cap (too many ntfy users or grants for this client)", method, path, maxResponse>>20)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

type Grant struct {
	Topic      string `json:"topic"`
	Permission string `json:"permission"`
}

type User struct {
	Username string  `json:"username"`
	Role     string  `json:"role"`
	Grants   []Grant `json:"grants,omitempty"`
}

type Account struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

// Account returns the account the admin token belongs to.
func (c *Client) Account(ctx context.Context) (*Account, error) {
	var a Account
	return &a, c.do(ctx, http.MethodGet, "/v1/account", nil, &a, true)
}

func (c *Client) Users(ctx context.Context) ([]User, error) {
	var us []User
	return us, c.do(ctx, http.MethodGet, "/v1/users", nil, &us, true)
}

// User returns the named ntfy user, or nil if it does not exist.
func (c *Client) User(ctx context.Context, username string) (*User, error) {
	us, err := c.Users(ctx)
	if err != nil {
		return nil, err
	}
	for i := range us {
		if us[i].Username == username {
			return &us[i], nil
		}
	}
	return nil, nil
}

func (c *Client) AddUser(ctx context.Context, username, password string) error {
	return c.do(ctx, http.MethodPost, "/v1/users", map[string]string{"username": username, "password": password}, nil, true)
}

// ChangePassword sets username's password (admin PUT /v1/users); the user's tokens stay valid.
func (c *Client) ChangePassword(ctx context.Context, username, password string) error {
	return c.do(ctx, http.MethodPut, "/v1/users", map[string]string{"username": username, "password": password}, nil, true)
}

// DeleteUser removes username. A user that is already gone counts as deleted, so an interrupted
// delete-and-recreate can resume.
func (c *Client) DeleteUser(ctx context.Context, username string) error {
	err := c.do(ctx, http.MethodDelete, "/v1/users", map[string]string{"username": username}, nil, true)
	if IsUserNotFound(err) {
		return nil
	}
	return err
}

func (c *Client) AllowAccess(ctx context.Context, username, topic, permission string) error {
	return c.do(ctx, http.MethodPut, "/v1/users/access",
		map[string]string{"username": username, "topic": topic, "permission": permission}, nil, true)
}

// ResetAccess removes username's grant on topic. A missing user has no grants, so that counts as
// done; ntfy reports it only as a generic 500, hence the lookup.
func (c *Client) ResetAccess(ctx context.Context, username, topic string) error {
	err := c.do(ctx, http.MethodDelete, "/v1/users/access", map[string]string{"username": username, "topic": topic}, nil, true)
	if err == nil {
		return nil
	}
	if u, lerr := c.User(ctx, username); lerr == nil && u == nil {
		return nil
	}
	return err
}

type EnrollCode struct {
	Code    string `json:"code"`
	Expires int64  `json:"expires"` // Unix seconds; ntfy issues codes valid for 10 minutes
}

func (ec *EnrollCode) ExpiresAt() time.Time { return time.Unix(ec.Expires, 0) }

// MintEnrollCode asks for a single-use code that redeems for a new token as username (ntfy#597,
// POST /v1/users/token/enroll). Issuing a code invalidates the user's previous pending one. ntfy
// refuses admin users (401) and unknown users (400). Servers without the endpoint answer 404,
// reported as ErrNotSupported.
func (c *Client) MintEnrollCode(ctx context.Context, username string) (*EnrollCode, error) {
	var ec EnrollCode
	err := c.do(ctx, http.MethodPost, "/v1/users/token/enroll", map[string]string{"username": username}, &ec, true)
	if IsStatus(err, http.StatusNotFound) || IsStatus(err, http.StatusMethodNotAllowed) {
		return nil, ErrNotSupported
	}
	if err == nil && ec.Code == "" {
		return nil, errors.New("ntfy enroll: empty code")
	}
	return &ec, err
}

type Action struct {
	Action string `json:"action"`
	Label  string `json:"label"`
	URL    string `json:"url"`
	Method string `json:"method,omitempty"`
	Body   string `json:"body,omitempty"`
	Clear  bool   `json:"clear,omitempty"`
}

type Message struct {
	Topic      string   `json:"topic"`
	SequenceID string   `json:"sequence_id,omitempty"`
	Title      string   `json:"title,omitempty"`
	Message    string   `json:"message"`
	Priority   int      `json:"priority,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Click      string   `json:"click,omitempty"`
	Actions    []Action `json:"actions,omitempty"`
	Cache      string   `json:"cache,omitempty"`
	Firebase   string   `json:"firebase,omitempty"`
}

func (c *Client) Publish(ctx context.Context, m *Message) error {
	return c.do(ctx, http.MethodPost, "/", m, nil, true)
}

type Token struct {
	Token    string `json:"token"`
	Label    string `json:"label,omitempty"`
	Username string `json:"username"`
}

// RedeemEnrollCode exchanges an enrollment code for a token, as the app or web app does
// (POST /v1/account/token/redeem, unauthenticated).
func (c *Client) RedeemEnrollCode(ctx context.Context, code, label string) (*Token, error) {
	var t Token
	return &t, c.do(ctx, http.MethodPost, "/v1/account/token/redeem", map[string]string{"code": code, "label": label}, &t, false)
}

// DeleteMessage removes a published message (by sequence ID) from subscribers' lists.
func (c *Client) DeleteMessage(ctx context.Context, topic, sequenceID string) error {
	return c.do(ctx, http.MethodDelete, "/"+url.PathEscape(topic)+"/"+url.PathEscape(sequenceID), nil, nil, true)
}

// AnonymousReadStatus returns the HTTP status of an unauthenticated poll of topic.
func (c *Client) AnonymousReadStatus(ctx context.Context, topic string) (int, error) {
	err := c.do(ctx, http.MethodGet, "/"+url.PathEscape(topic)+"/json?poll=1", nil, nil, false)
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Status, nil
	} else if err != nil {
		return 0, err
	}
	return http.StatusOK, nil
}
