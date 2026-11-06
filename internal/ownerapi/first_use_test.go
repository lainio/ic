package ownerapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/peerapi"
)

func TestFirstUseOwnerStrictInputAndCredentials(t *testing.T) {
	defer assert.PushTester(t)()
	h, file, bind := try.To3(
		NewFirstUseCredentials(t.Context(), nil, nil, nil, nil, t.TempDir()),
	)
	prove, accept, establish, use, message := bind(nil)
	assert.That(prove == nil && accept == nil && establish == nil && use == nil)
	assert.That(message == nil)
	auth := strings.TrimSpace(
		strings.TrimPrefix(
			string(try.To1(os.ReadFile(file))),
			"Authorization:",
		),
	)
	for _, tc := range []struct {
		body   string
		status int
	}{
		{"{}", 409}, {" {}\n", 409}, {"{ }", 400}, {"[]", 400}, {"null", 400},
		{"{} {}", 400}, {`{"session":"x"}`, 400}, {`{"target":"x"}`, 400},
		{`{"expires":60}`, 400}, {`{"request":"x"}`, 400},
		{strings.Repeat(" ", 65), 413},
	} {
		for _, credential := range []string{"", auth} {
			r := httptest.NewRequest(
				"POST",
				firstUsePath,
				strings.NewReader(tc.body),
			)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", credential)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := tc.status
			if credential == "" {
				want = 401
			}
			assert.Equal(w.Code, want)
			assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
		}
	}
	for _, mode := range []string{"method", "query", "encoding", "trailer", "media", "duplicate media", "duplicate auth", "escaped", "nil body"} {
		r := httptest.NewRequest("POST", firstUsePath, strings.NewReader("{}"))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", auth)
		want := 400
		switch mode {
		case "nil body":
			r.Body = nil
		case "method":
			r.Method = "GET"
			want = 405
		case "query":
			r.URL.ForceQuery = true
		case "encoding":
			r.Header.Set("Content-Encoding", "gzip")
		case "trailer":
			r.Header.Set("Trailer", "X-Test")
		case "media":
			r.Header.Set("Content-Type", "text/plain")
			want = 415
		case "duplicate media":
			r.Header.Add("Content-Type", "application/json")
			want = 415
		case "duplicate auth":
			r.Header.Add("Authorization", auth)
			want = 401
		case "escaped":
			r.URL.RawPath = "/owner/pw/%66irst-use"
			want = 404
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assert.Equal(w.Code, want)
	}
	old, oldFile, _ := try.To3(
		NewEstablishmentCredentials(
			t.Context(),
			nil,
			nil,
			nil,
			nil,
			t.TempDir(),
		),
	)
	oldAuth := strings.TrimSpace(
		strings.TrimPrefix(
			string(try.To1(os.ReadFile(oldFile))),
			"Authorization:",
		),
	)
	for _, handler := range []http.Handler{old, peerapi.NewHandler(nil, nil, nil)} {
		r := httptest.NewRequest("POST", firstUsePath, strings.NewReader("{}"))
		r.Header.Set("Authorization", oldAuth)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		assert.Equal(w.Code, 404)
	}
}
