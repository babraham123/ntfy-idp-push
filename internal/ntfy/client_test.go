package ntfy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOversizedResponseIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A valid user list just over the cap: truncating it would drop users, not fail to parse.
		w.Write([]byte(`[{"username":"a","role":"user"}` + strings.Repeat(` `, maxResponse) + `]`))
	}))
	t.Cleanup(srv.Close)
	_, err := New(srv.URL, "tk").Users(context.Background())
	if err == nil || !strings.Contains(err.Error(), "1 MiB cap") {
		t.Fatalf("got %v", err)
	}
}
