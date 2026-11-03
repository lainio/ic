package peerapi

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
)

func TestFirstUseStrictPeerBoundary(t *testing.T) {
	defer assert.PushTester(t)()
	calls := 0
	h := NewFirstUseHandler(
		func([]byte) ([]byte, error) { calls++; return nil, errors.New("secret diagnostic") },
		http.NotFoundHandler(),
	)
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"version":1,"request":"AQ=="}`, 409},
		{`{"version":1,"request":"AQ==","request":"AQ=="}`, 400},
		{`{"version":1,"Version":1,"request":"AQ=="}`, 400},
		{`{"version":1,"request":"AQ==","root":"x"}`, 400},
		{`{"version":1,"request":"AQ=="} {}`, 400},
		{`{"version":1.0,"request":"AQ=="}`, 400},
		{`{"version":2,"request":"AQ=="}`, 400},
		{`{"version":1,"request":"AR=="}`, 400},
		{`{"version":1,"request":"AQ==\n"}`, 400},
		{`{"version":1,"request":null}`, 400},
		{`{"version":1,"request":[]}`, 400},
		{`{"version":1}`, 400},
		{"{}", 400}, {"[]", 400}, {"null", 400},
		{strings.Repeat("x", maxEstablishmentEnvelopeBytes+1), 413},
	} {
		r := httptest.NewRequest(
			"POST",
			"/peer/pw/first-use",
			strings.NewReader(tc.body),
		)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assert.Equal(w.Code, tc.status)
		assert.Equal(w.Body.String(), http.StatusText(tc.status)+"\n")
		assert.Equal(w.Header().Get("Cache-Control"), "no-store")
	}
	assert.Equal(calls, 1)
	for _, mode := range []string{"GET", "query", "encoding", "trailer", "duplicate media", "wrong media", "escaped", "owner", "nil"} {
		r := httptest.NewRequest(
			"POST",
			"/peer/pw/first-use",
			bytes.NewBufferString(`{"version":1,"request":"AQ=="}`),
		)
		r.Header.Set("Content-Type", "application/json")
		want := 400
		handler := h
		switch mode {
		case "GET":
			r.Method = "GET"
			want = 405
		case "query":
			r.URL.RawQuery = "x=y"
		case "encoding":
			r.Header.Set("Content-Encoding", "gzip")
		case "trailer":
			r.Trailer = http.Header{"X-Extra": nil}
		case "duplicate media":
			r.Header.Add("Content-Type", "application/json")
			want = 415
		case "wrong media":
			r.Header.Set("Content-Type", "application/octet-stream")
			want = 415
		case "escaped":
			r.URL.RawPath = "/peer/pw/%66irst-use"
			want = 404
		case "owner":
			r.URL.Path = "/owner/pw/first-use"
			want = 404
		case "nil":
			handler = NewFirstUseHandler(nil, http.NotFoundHandler())
			want = 404
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		assert.Equal(w.Code, want)
	}
	assert.Equal(calls, 1)
}
