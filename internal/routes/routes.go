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
	Subscribe = "/subscribe"
	Static    = "/static/"
	Health    = "/healthz"
)

// EnrollURL is the single-use enrollment link for code. The code rides in the fragment, which
// browsers never send: it stays out of the proxy's access log, Referers and the page request, and
// the page posts it itself.
func EnrollURL(public, code string) string { return public + Token + "/#" + url.PathEscape(code) }

// EnrollCode is the inverse of EnrollURL: the code an enrollment URL under public carries, or ""
// when u is not one.
func EnrollCode(public, u string) string {
	prefix := EnrollURL(public, "")
	if !strings.HasPrefix(u, prefix) {
		return ""
	}
	code, err := url.PathUnescape(u[len(prefix):])
	if err != nil {
		return ""
	}
	return code
}

// VerifyURL activates deviceID; the setup push carries it. The token rides in the fragment, as
// EnrollURL's code does.
func VerifyURL(public, deviceID, verifyToken string) string {
	return public + Token + "/verify/" + url.PathEscape(deviceID) + "#t=" + url.QueryEscape(verifyToken)
}

// ApproveURL is the approve page for a challenge; the login push opens it.
func ApproveURL(public, challengeID string) string {
	return public + Challenge + "/" + url.PathEscape(challengeID)
}

// DenyURL is the login push's Deny action target.
func DenyURL(public, challengeID string) string { return ApproveURL(public, challengeID) + "/deny" }

// SubscribeURL is the page that subscribes user's ntfy app to topic. Mail clients drop links with
// an ntfy:// scheme, so the welcome email links here and the page hands out the deep link.
func SubscribeURL(public, topic, user string) string {
	return public + Subscribe + "/" + url.PathEscape(topic) + "?user=" + url.QueryEscape(user)
}

// QRURL renders an enrollment URL as a barcode for the IdP's enrollment screen.
func QRURL(public, enrollURL string) string {
	return public + Token + "/qr?value=" + url.QueryEscape(enrollURL)
}
