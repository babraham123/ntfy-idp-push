// Package qr renders the QR codes phones scan off a screen.
package qr

import (
	"encoding/base64"

	"github.com/skip2/go-qrcode"
)

// DataURL is a PNG QR code of content as a data: URL. Inlining the image means the browser never
// requests it, so content, which is often a secret, never appears in a request line or access log.
func DataURL(content string) (string, error) {
	png, err := qrcode.Encode(content, qrcode.Medium, 320)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}
