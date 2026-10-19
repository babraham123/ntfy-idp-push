// Package routes is the shim's public URL scheme: the one place that spells the paths users,
// phones and the IdP are sent to. web registers handlers on these paths, core mints the links it
// pushes from them, and duoapi builds the activation barcode with them.
package routes

import (
	"net/url"
	"strings"
)

// Path prefixes. Identity routes trust the proxy's identity header; token routes carry their own
// credential (an enrollment code, result token, verify token, deny token or passkey).
const (
	Enroll    = "/enroll"
	Devices   = "/devices"
	Token     = "/token"
	Challenge = "/challenge"
	Static    = "/static/"
	Health    = "/healthz"
)

// EnrollURL is the single-use enrollment page for code.
func EnrollURL(public, code string) string { return public + Token + "/" + url.PathEscape(code) }

// EnrollCode is the inverse of EnrollURL: the code an enrollment URL under public carries, or ""
// when u is not one.
func EnrollCode(public, u string) string {
	prefix := public + Token + "/"
	if !strings.HasPrefix(u, prefix) {
		return ""
	}
	code, err := url.PathUnescape(u[len(prefix):])
	if err != nil || code == "" || strings.ContainsAny(code, "/?#") {
		return ""
	}
	return code
}

// VerifyURL activates deviceID; the setup push carries it.
func VerifyURL(public, deviceID, verifyToken string) string {
	return public + Token + "/verify/" + url.PathEscape(deviceID) + "?t=" + url.QueryEscape(verifyToken)
}

// ApproveURL is the approve page for a challenge; the login push opens it.
func ApproveURL(public, challengeID string) string {
	return public + Challenge + "/" + url.PathEscape(challengeID)
}

// DenyURL is the login push's Deny action target.
func DenyURL(public, challengeID string) string { return ApproveURL(public, challengeID) + "/deny" }

// QRURL renders an enrollment URL as a barcode for the IdP's enrollment screen.
func QRURL(public, enrollURL string) string {
	return public + Token + "/qr?value=" + url.QueryEscape(enrollURL)
}
