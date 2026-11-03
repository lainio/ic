package pw

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestSendFirstUseStrictResponse(t *testing.T) {
	for _, name := range []string{"refused", "redirect", "media", "duplicate media",
		"cache", "duplicate cache", "encoding", "headers", "oversized", "chunked",
		"short length", "long length", "trailer", "duplicate", "unknown", "alias",
		"float", "exponent", "string version", "missing version", "trailing", "utf8",
		"null", "array", "base64", "pad bits", "newline", "empty", "oversized bytes"} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			var calls atomic.Int32
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					calls.Add(1)
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Cache-Control", "no-store")
					data := `{"version":1,"response":"AQ=="}`
					switch name {
					case "refused":
						w.WriteHeader(409)
					case "redirect":
						w.Header().Set("Location", "/peer/pw/first-use")
						w.WriteHeader(307)
					case "media":
						w.Header().Set("Content-Type", "text/plain")
					case "duplicate media":
						w.Header().Add("Content-Type", "application/json")
					case "cache":
						w.Header().Del("Cache-Control")
					case "duplicate cache":
						w.Header().Add("Cache-Control", "no-store")
					case "encoding":
						w.Header().Set("Content-Encoding", "gzip")
					case "headers":
						w.Header().Set("X-Large", strings.Repeat("x", 8192))
					case "oversized", "chunked":
						data += strings.Repeat(
							" ",
							maxEstablishmentEnvelopeBytes+1,
						)
					case "short length":
						w.Header().Set("Content-Length", "1")
					case "long length":
						w.Header().Set("Content-Length", "3072")
					case "trailer":
						w.Header().Set("Trailer", "X-Late")
					case "duplicate":
						data = `{"version":1,"response":"AQ==","response":"AQ=="}`
					case "unknown":
						data = `{"version":1,"response":"AQ==","private_diagnostic":1}`
					case "alias":
						data = strings.Replace(
							data,
							"response",
							"Response",
							1,
						)
					case "float":
						data = strings.Replace(data, ":1,", ":1.0,", 1)
					case "exponent":
						data = strings.Replace(data, ":1,", ":1e0,", 1)
					case "string version":
						data = strings.Replace(data, ":1,", `:"1",`, 1)
					case "missing version":
						data = `{"response":"AQ=="}`
					case "trailing":
						data += `{}`
					case "utf8":
						data = "\xff"
					case "null":
						data = "null"
					case "array":
						data = "[]"
					case "base64":
						data = strings.Replace(data, "AQ==", "!!!!", 1)
					case "pad bits":
						data = strings.Replace(data, "AQ==", "AR==", 1)
					case "newline":
						data = strings.Replace(data, "AQ==", `AQ==\n`, 1)
					case "empty":
						data = strings.Replace(data, "AQ==", "", 1)
					case "oversized bytes":
						encoded, _ := json.Marshal(struct {
							Version  int    `json:"version"`
							Response []byte `json:"response"`
						}{1, make([]byte, MaxEstablishmentBytes+1)})
						data = string(encoded)
					}
					if name == "chunked" {
						w.(http.Flusher).Flush()
					}
					_, _ = io.WriteString(w, data)
					if name == "trailer" {
						w.Header().Set("X-Late", "value")
					}
				}),
			)
			defer server.Close()
			_, err := SendFirstUse(
				t.Context(),
				SavedFirstUse{request: []byte{1},
					endpoint: server.URL + "/peer/introduction"},
			)
			assert.Equal(err, ErrFirstUseExchange)
			assert.Equal(calls.Load(), int32(1))
		})
	}
}

func TestSendFirstUseExactBytesNoProxy(t *testing.T) {
	defer assert.PushTester(t)()
	var proxyCalls atomic.Int32
	proxy := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			proxyCalls.Add(1)
			w.WriteHeader(502)
		}),
	)
	defer proxy.Close()
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy"} {
		t.Setenv(name, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	observed := make(chan []byte, 1)
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil || r.Header.Get("Authorization") != "" ||
				r.Header.Get(
					"Cookie",
				) != "" || r.URL.Path != "/peer/pw/first-use" {
				w.WriteHeader(500)
				return
			}
			observed <- body
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = io.WriteString(w, `{"version":1,"response":"AQ=="}`)
		}),
	)
	defer server.Close()
	raw := bytes.Repeat([]byte{42}, 512)
	response := try.To1(SendFirstUse(t.Context(), SavedFirstUse{request: raw,
		endpoint: server.URL + "/peer/introduction"}))
	assert.DeepEqual(response, []byte{1})
	var got struct {
		Version int
		Request []byte
	}
	try.To(json.Unmarshal(<-observed, &got))
	assert.Equal(got.Version, 1)
	assert.DeepEqual(got.Request, raw)
	assert.Equal(proxyCalls.Load(), int32(0))
}

func TestSendFirstUseCancellation(t *testing.T) {
	defer assert.PushTester(t)()
	entered := make(chan struct{})
	server := httptest.NewServer(
		http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			close(entered)
			<-r.Context().Done()
		}),
	)
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := SendFirstUse(
			ctx,
			SavedFirstUse{
				request:  []byte{1},
				endpoint: server.URL + "/peer/introduction",
			},
		)
		done <- err
	}()
	<-entered
	cancel()
	assert.Equal(<-done, ErrFirstUseExchange)
}
