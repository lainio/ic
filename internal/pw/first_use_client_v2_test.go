package pw

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestSendFirstUseV2ExactBytesAndTransportIsolation(t *testing.T) {
	defer assert.PushTester(t)()
	var proxyCalls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		_ *http.Request,
	) {
		proxyCalls.Add(1)
		w.WriteHeader(502)
	}))
	defer proxy.Close()
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
		"http_proxy"} {
		t.Setenv(name, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	observed := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request,
	) {
		body, err := io.ReadAll(r.Body)
		if err != nil || r.Method != "POST" ||
			r.URL.RequestURI() != "/peer/pw/first-use" ||
			r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" ||
			r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(500)
			return
		}
		observed <- body
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, `{"version":2,"response":"Ag=="}`)
	}))
	defer server.Close()
	response := try.To1(SendFirstUseV2(t.Context(), SavedFirstUseV2{
		request: []byte{1}, peerOrigin: server.URL}))
	assert.DeepEqual(response, []byte{2})
	assert.Equal(string(<-observed), `{"version":2,"request":"AQ=="}`)
	assert.Equal(proxyCalls.Load(), int32(0))
}

func TestSendFirstUseV2StrictResponse(t *testing.T) {
	for _, body := range []string{
		`{"version":1,"response":"AQ=="}`,
		`{"version":3,"response":"AQ=="}`,
		`{"version":2.0,"response":"AQ=="}`,
		`{"version":2e0,"response":"AQ=="}`,
		`{"version":"2","response":"AQ=="}`,
		`{"version":2,"version":2,"response":"AQ=="}`,
		`{"version":2,"response":"AQ==","response":"AQ=="}`,
		`{"ver\u0073ion":2,"response":"AQ=="}`,
		`{"version":2,"re\u0073ponse":"AQ=="}`,
		`{"version":2,"Response":"AQ=="}`,
		`{"version":2,"response":"AQ==","url":"private"}`,
		`{"version":2,"response":"AQ=="} {}`,
		`{"version":2,"response":"AR=="}`,
		`{"version":2,"response":"AQ==\n"}`,
		`{"version":2,"response":"AQ"}`,
		`{"version":2,"response":null}`,
		`{"version":2,"response":[]}`,
		`{"version":2,"response":""}`,
		`{"version":2}`, "", "null", "[]", "\xff",
		strings.Repeat(" ", maxEstablishmentEnvelopeBytes+1),
	} {
		t.Run(body, func(t *testing.T) {
			defer assert.PushTester(t)()
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, _ *http.Request) {
					calls.Add(1)
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Cache-Control", "no-store")
					_, _ = io.WriteString(w, body)
				}))
			defer server.Close()
			_, err := SendFirstUseV2(t.Context(), SavedFirstUseV2{
				request: []byte{1}, peerOrigin: server.URL})
			assert.Equal(err, ErrFirstUseExchange)
			assert.Equal(calls.Load(), int32(1))
		})
	}
}

func TestSendFirstUseV2NoRedirectAndCancellation(t *testing.T) {
	defer assert.PushTester(t)()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		_ *http.Request,
	) {
		calls.Add(1)
		w.Header().Set("Location", "/peer/pw/first-use")
		w.WriteHeader(307)
	}))
	defer server.Close()
	saved := SavedFirstUseV2{request: []byte{1}, peerOrigin: server.URL}
	_, err := SendFirstUseV2(t.Context(), saved)
	assert.Equal(err, ErrFirstUseExchange)
	assert.Equal(calls.Load(), int32(1))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = SendFirstUseV2(ctx, saved)
	assert.Equal(err, ErrFirstUseExchange)
	assert.Equal(calls.Load(), int32(1))
	for _, invalid := range []SavedFirstUseV2{{},
		{request: []byte{1}, peerOrigin: server.URL + "/peer/introduction"},
		{request: []byte{1}, peerOrigin: "http://localhost:12345"},
		{request: []byte{1}, peerOrigin: "http://192.0.2.1:80"},
		{request: bytes.Repeat([]byte{1}, MaxFirstUseBytesV2*2),
			peerOrigin: server.URL},
	} {
		_, err = SendFirstUseV2(t.Context(), invalid)
		assert.Equal(err, ErrFirstUseExchange)
	}
	assert.Equal(calls.Load(), int32(1))
}
