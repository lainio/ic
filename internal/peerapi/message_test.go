package peerapi

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/internal/pw"
)

const messagePath = "/peer/pw/message"
const messageBody = `{"version":1,"envelope":"AQ=="}`

func TestMessageStrictPeerJSON(t *testing.T) {
	defer assert.PushTester(t)()
	calls := 0
	h := NewMessageHandler(func(version int, raw []byte) ([]byte, error) {
		calls++
		assert.Equal(version, 1)
		assert.DeepEqual(raw, []byte{1})
		return raw, errors.New("secret plaintext IDs keys bearer diagnostic")
	}, http.NotFoundHandler())
	for _, body := range []string{
		`{}`, `[]`, `null`, `true`, `1`, `"x"`, "",
		`{"version":1}`, `{"envelope":"AQ=="}`,
		`{"version":1,"envelope":null}`, `{"version":1,"envelope":[]}`,
		`{"version":1,"envelope":{}}`, `{"version":1,"envelope":1}`,
		`{"version":1,"envelope":true}`, `{"version":1,"envelope":""}`,
		`{"version":3,"envelope":"AQ=="}`,
		`{"version":1.0,"envelope":"AQ=="}`,
		`{"version":1e0,"envelope":"AQ=="}`,
		`{"version":"1","envelope":"AQ=="}`,
		`{"version":true,"envelope":"AQ=="}`,
		`{"version":null,"envelope":"AQ=="}`,
		`{"version":1,"version":1,"envelope":"AQ=="}`,
		`{"version":1,"envelope":"AQ==","envelope":"AQ=="}`,
		`{"version":1,"envelope":"AQ==","Envelope":"AQ=="}`,
		`{"version":1,"envelope":"AQ==","env\u0065lope":"AQ=="}`,
		`{"version":1,"env\u0065lope":"AQ=="}`,
		`{"vers\u0069on":1,"envelope":"AQ=="}`,
		`{"version":1,"envelope":"AQ==","root":"x"}`,
		`{"version":1,"envelope":"AQ==","recipient":"x"}`,
		messageBody + `{}`, messageBody + ` null`, messageBody + ` garbage`,
		`{"version":1,"envelope":"AQ==",}`,
		`{"version":1,"envelope":"AR=="}`,
		`{"version":1,"envelope":"AQ"}`,
		`{"version":1,"envelope":"AQ="}`,
		`{"version":1,"envelope":"AQ==="}`,
		`{"version":1,"envelope":"-w=="}`,
		`{"version":1,"envelope":"_w=="}`,
		`{"version":1,"envelope":"AQ==\n"}`,
		`{"version":1,"envelope":"AQ==\r"}`,
		`{"version":1,"envelope":" AQ=="}`,
		`{"version":1,"envelope":"\ud800"}`,
		"{\"version\":1,\"envelope\":\"\xff\"}",
		`{"version":1,"envelope":"` + base64.StdEncoding.EncodeToString(
			make([]byte, pw.MaxMessageEnvelopeBytes+1)) + `"}`,
	} {
		w := messageRequest(h, body)
		assert.Equal(w.Code, 400, body)
		assert.Equal(w.Body.String(), "Bad Request\n")
		assert.Equal(w.Header().Get("Cache-Control"), "no-store")
	}
	assert.Equal(calls, 0)
	w := messageRequest(h, messageBody)
	assert.Equal(w.Code, 409)
	assert.Equal(w.Body.String(), "Conflict\n")
	assert.Equal(calls, 1)
	w = messageRequest(h, strings.Repeat(" ", maxMessageRequestBytes+1))
	assert.Equal(w.Code, 413)
	assert.Equal(w.Body.String(), "Request Entity Too Large\n")
	assert.Equal(calls, 1)
}

func messageRequest(h http.Handler, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", messagePath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestMessageStrictPeerHeadersAndRouting(t *testing.T) {
	defer assert.PushTester(t)()
	calls, fallthroughs := 0, 0
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fallthroughs++
		w.WriteHeader(404)
	})
	h := NewMessageHandler(func(int, []byte) ([]byte, error) {
		calls++
		return nil, errors.New("private diagnostic")
	}, next)
	for _, mode := range []string{"GET", "PUT", "HEAD", "query", "force query",
		"fragment", "raw fragment", "encoding", "empty encoding",
		"transfer encoding", "transfer header",
		"trailer header", "trailer map", "late trailer", "read error",
		"duplicate media", "wrong media", "no media", "comma media",
		"nil body", "escaped path", "opaque", "owner", "suffix", "nil"} {
		r := httptest.NewRequest(
			"POST",
			messagePath,
			strings.NewReader(messageBody),
		)
		r.Header.Set("Content-Type", "application/json")
		want, handler := 400, h
		switch mode {
		case "GET", "PUT", "HEAD":
			r.Method, want = mode, 405
		case "query":
			r.URL.RawQuery = "x=y"
		case "force query":
			r.URL.ForceQuery = true
		case "fragment":
			r.URL.Fragment = "x"
		case "raw fragment":
			r.URL.RawFragment = "%78"
		case "encoding":
			r.Header.Set("Content-Encoding", "gzip")
		case "empty encoding":
			r.Header.Set("Content-Encoding", "")
		case "transfer encoding":
			r.TransferEncoding = []string{"chunked"}
		case "transfer header":
			r.Header.Set("Transfer-Encoding", "chunked")
		case "trailer header":
			r.Header.Set("Trailer", "X-Test")
		case "trailer map":
			r.Trailer = http.Header{"X-Test": nil}
		case "late trailer":
			r.Body = &messageBodyReader{Reader: strings.NewReader(messageBody),
				onEnd: func() { r.Trailer = http.Header{"X-Test": {"secret"}} }}
		case "read error":
			r.Body = &messageBodyReader{Reader: strings.NewReader(messageBody),
				err: errors.New("secret read diagnostic")}
		case "duplicate media":
			r.Header.Add("Content-Type", "application/json")
			want = 415
		case "wrong media":
			r.Header.Set("Content-Type", "text/plain")
			want = 415
		case "no media":
			r.Header.Del("Content-Type")
			want = 415
		case "comma media":
			r.Header.Set("Content-Type", "application/json,application/json")
			want = 415
		case "nil body":
			r.Body = nil
		case "escaped path":
			r.URL.RawPath, want = "/peer/pw/%6dessage", 404
		case "opaque":
			r.URL.Opaque, want = messagePath, 404
		case "owner":
			r.URL.Path, want = "/owner/pw/message", 404
		case "suffix":
			r.URL.Path, want = messagePath+"/", 404
		case "nil":
			handler, want = NewMessageHandler(nil, next), 404
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		assert.Equal(w.Code, want, mode)
		if mode != "owner" && mode != "suffix" {
			assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
		}
		assert.Equal(w.Header().Get("WWW-Authenticate"), "")
		if want == 405 {
			assert.Equal(w.Header().Get("Allow"), "POST")
		}
	}
	assert.Equal(calls, 0)
	assert.Equal(fallthroughs, 2)
}

type messageBodyReader struct {
	io.Reader
	onEnd func()
	err   error
}

func (r *messageBodyReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err == io.EOF {
		if r.onEnd != nil {
			r.onEnd()
		}
		if r.err != nil {
			err = r.err
		}
	}
	return n, err
}

func (*messageBodyReader) Close() error { return nil }

func TestMessageInvalidLocalCallbackOutput(t *testing.T) {
	defer assert.PushTester(t)()
	for _, output := range [][]byte{nil, {}, {1}, []byte("private output"),
		make([]byte, pw.MaxMessageReceiptBytes+1)} {
		calls := 0
		h := NewMessageHandler(func(int, []byte) ([]byte, error) {
			calls++
			return output, nil
		}, http.NotFoundHandler())
		w := messageRequest(h, messageBody)
		assert.Equal(calls, 1)
		assert.Equal(w.Code, 500)
		assert.Equal(w.Body.String(), "Internal Server Error\n")
		assert.Equal(w.Header().Get("Cache-Control"), "no-store")
	}
}
