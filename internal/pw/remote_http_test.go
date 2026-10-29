package pw_test

import (
	"bytes"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/pw"
)

func TestRequestRemoteAcceptanceRejectsHTTPAndJSON(t *testing.T) {
	for _, path := range []string{challengePath, acceptPath} {
		for _, name := range []string{
			"refused", "capacity", "redirect", "media", "duplicate media",
			"missing media", "cache", "duplicate cache", "encoding", "headers",
			"missing", "oversized", "chunked oversized", "long length",
			"short length", "trailer", "duplicate", "unknown", "case alias",
			"version float", "version exponent", "version string", "version absent",
			"trailing", "invalid UTF8", "null", "array", "base64", "pad bits",
			"base64 newline", "empty bytes", "short bytes", "long bytes",
		} {
			t.Run(path+"/"+name, func(t *testing.T) {
				defer assert.PushTester(t)()
				var challenges, accepts atomic.Int64
				f := newExchange(t, func(next http.Handler) http.Handler {
					return http.HandlerFunc(
						func(w http.ResponseWriter, r *http.Request) {
							if r.URL.Path == challengePath {
								challenges.Add(1)
							}
							if r.URL.Path == acceptPath {
								accepts.Add(1)
							}
							if r.URL.Path != path {
								next.ServeHTTP(w, r)
								return
							}
							reply := httptest.NewRecorder()
							next.ServeHTTP(reply, r)
							corruptExchangeReply(w, reply, name, path)
						},
					)
				})
				before := f.snapshot(t)
				signed := len(f.a.signer.signed())
				assert.Equal(f.request(t.Context()), pw.ErrRemoteAcceptance)
				assert.Equal(challenges.Load(), int64(1))
				if path == challengePath {
					assert.Equal(accepts.Load(), int64(0))
					assert.Equal(
						len(f.a.signer.signed()),
						signed+1,
					) // Probe only.
				} else {
					assert.Equal(accepts.Load(), int64(1))
				}
				assert.DeepEqual(f.snapshot(t), before)
			})
		}
	}
}

func corruptExchangeReply(w http.ResponseWriter,
	reply *httptest.ResponseRecorder, name, path string,
) {
	maps.Copy(w.Header(), reply.Header())
	data := reply.Body.String()
	field := "challenge"
	if path == acceptPath {
		field = "acceptor_proof"
	}
	switch name {
	case "refused":
		w.WriteHeader(409)
		return
	case "capacity":
		w.WriteHeader(429)
		return
	case "redirect":
		w.Header().Set("Location", "http://example.invalid:80/peer/pw/accept")
		w.WriteHeader(307)
		return
	case "media":
		w.Header().Set("Content-Type", "text/plain")
	case "duplicate media":
		w.Header().Add("Content-Type", "application/json")
	case "missing media":
		w.Header().Del("Content-Type")
	case "cache":
		w.Header().Del("Cache-Control")
	case "duplicate cache":
		w.Header().Add("Cache-Control", "no-store")
	case "encoding":
		w.Header().Set("Content-Encoding", "gzip")
	case "headers":
		w.Header().Set("X-Large", strings.Repeat("x", 2048))
	case "missing":
		data = ""
	case "oversized", "chunked oversized":
		data += strings.Repeat(" ", 1025)
	case "long length":
		w.Header().Set("Content-Length", "1024")
	case "short length":
		w.Header().Set("Content-Length", "1")
	case "trailer":
		w.Header().Set("Trailer", "X-Late")
	case "duplicate":
		data = strings.TrimSuffix(data, "}") + `,"version":1}`
	case "unknown":
		data = strings.TrimSuffix(data, "}") + `,"private_remote_diagnostic":1}`
	case "case alias":
		data = strings.Replace(data, `"version"`, `"Version"`, 1)
	case "version float":
		data = strings.Replace(data, `"version":1`, `"version":1.0`, 1)
	case "version exponent":
		data = strings.Replace(data, `"version":1`, `"version":1e0`, 1)
	case "version string":
		data = strings.Replace(data, `"version":1`, `"version":"1"`, 1)
	case "version absent":
		data = strings.Replace(data, `"version":1,`, "", 1)
	case "trailing":
		data += `{}`
	case "invalid UTF8":
		data = strings.Replace(data, `"version"`, "\"\xff\"", 1)
	case "null":
		data = "null"
	case "array":
		data = "[]"
	default:
		var fields map[string]any
		if json.Unmarshal([]byte(data), &fields) != nil {
			w.WriteHeader(500)
			return
		}
		switch name {
		case "base64":
			fields[field] = "!!!!"
		case "pad bits":
			fields[field] = "AR=="
		case "base64 newline":
			fields[field] = fields[field].(string) + "\n"
		case "empty bytes":
			fields[field] = ""
		case "short bytes":
			fields[field] = []byte{1}
		case "long bytes":
			fields[field] = make([]byte, 73)
		}
		encoded, err := json.Marshal(fields)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		data = string(encoded)
	}
	if name == "chunked oversized" {
		w.(http.Flusher).Flush()
	}
	_, _ = io.WriteString(w, data)
	if name == "trailer" {
		w.Header().Set("X-Late", "value")
	}
}

func TestRequestRemoteAcceptanceRejectsPeerExpiry(t *testing.T) {
	for _, value := range []string{"expired", "future", "overflow", "float", "string", "absent", "zero"} {
		t.Run(value, func(t *testing.T) {
			defer assert.PushTester(t)()
			var accepts atomic.Int64
			f := newExchange(t, func(next http.Handler) http.Handler {
				return http.HandlerFunc(
					func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path == acceptPath {
							accepts.Add(1)
						}
						if r.URL.Path != challengePath {
							next.ServeHTTP(w, r)
							return
						}
						reply := httptest.NewRecorder()
						next.ServeHTTP(reply, r)
						var fields map[string]json.RawMessage
						if json.Unmarshal(reply.Body.Bytes(), &fields) != nil {
							w.WriteHeader(500)
							return
						}
						var expiry any
						switch value {
						case "expired":
							expiry = time.Now().Add(-time.Second).UnixNano()
						case "future":
							expiry = time.Now().Add(time.Minute).UnixNano()
						case "overflow":
							expiry = json.Number("9223372036854775808")
						case "float":
							expiry = json.Number("1.0")
						case "string":
							expiry = "2000000000000000000"
						default:
							expiry = 0
						}
						encoded, _ := json.Marshal(expiry)
						fields["expires_unix_nano"] = encoded
						if value == "absent" {
							delete(fields, "expires_unix_nano")
						}
						data, _ := json.Marshal(fields)
						reply.Body = bytes.NewBuffer(data)
						copyReply(w, reply)
					},
				)
			})
			signed := len(f.a.signer.signed())
			assert.Equal(f.request(t.Context()), pw.ErrRemoteAcceptance)
			assert.Equal(len(f.a.signer.signed()), signed+1)
			assert.Equal(accepts.Load(), int64(0))
		})
	}
}

func TestRequestRemoteAcceptanceIgnoresProxyEnvironment(t *testing.T) {
	defer assert.PushTester(t)()
	var calls atomic.Int64
	proxy := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(502)
		}),
	)
	defer proxy.Close()
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy"} {
		t.Setenv(name, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	f := newExchange(t, nil)
	try.To(f.request(t.Context()))
	assert.Equal(calls.Load(), int64(0))
}
