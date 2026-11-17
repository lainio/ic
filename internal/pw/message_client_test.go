package pw

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/pw/internal/messagehttp"
)

func TestMessageClientExactRequestAndUntrustedResponse(t *testing.T) {
	defer assert.PushTester(t)()
	saved := savedMessageTransmit{envelope: "private envelope bytes"}
	type captured struct {
		request *http.Request
		body    []byte
		err     error
	}
	requests := make(chan captured, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request,
	) {
		body, err := io.ReadAll(r.Body)
		requests <- captured{r, body, err}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, `{"version":1,"receipt":"/w=="}`)
	}))
	defer server.Close()
	var proxyCalls atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter,
		*http.Request,
	) {
		proxyCalls.Add(1)
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("ALL_PROXY", proxy.URL)

	got := try.To1(
		sendMessageOnce(t.Context(), saved, server.URL+messagehttp.Path),
	)
	assert.DeepEqual(got, []byte{0xff}) // Intentionally unauthenticated CBOR.
	r := <-requests
	try.To(r.err)
	assert.Equal(r.request.Method, "POST")
	assert.Equal(r.request.RequestURI, messagehttp.Path)
	assert.Equal(string(r.body), `{"version":1,"envelope":"`+
		base64.StdEncoding.EncodeToString([]byte(saved.envelope))+`"}`)
	assert.Equal(r.request.ContentLength, int64(len(r.body)))
	assert.SNil(r.request.TransferEncoding)
	assert.Equal(r.request.Header.Get("Content-Type"), "application/json")
	assert.That(r.request.Close)
	for _, name := range []string{"Cookie", "Authorization", "Proxy-Authorization",
		"Accept-Encoding", "Content-Encoding", "User-Agent"} {
		assert.Equal(r.request.Header.Get(name), "", name)
	}
	assert.Equal(proxyCalls.Load(), 0)
}

func TestMessageClientDestinationAndPreflight(t *testing.T) {
	defer assert.PushTester(t)()
	for _, value := range []string{
		"http://127.0.0.1:1", "http://127.0.0.2:65535", "http://[::1]:8080",
	} {
		assert.That(messagehttp.ValidURL(value + messagehttp.Path))
	}
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter,
		*http.Request,
	) {
		calls.Add(1)
	}))
	defer server.Close()
	valid := server.URL + messagehttp.Path
	invalid := []string{
		"", "http://localhost:80", "http://127.1:80", "http://127.0.0.01:80",
		"http://0.0.0.0:80", "http://192.0.2.1:80", "http://example.test:80",
		"http://[::]:80", "http://[::ffff:127.0.0.1]:80",
		"http://[0:0:0:0:0:0:0:1]:80", "http://[::1%lo]:80",
		"http://127.0.0.1", "http://127.0.0.1:0", "http://127.0.0.1:65536",
		"http://127.0.0.1:080", "http://127.0.0.1:+80", "http://127.0.0.1:http",
		"HTTP://127.0.0.1:80", "https://127.0.0.1:80",
		"http://sensitive@127.0.0.1:80", "http://127.0.0.1:80/sensitive",
	}
	for _, prefix := range invalid {
		invalidURL := prefix + messagehttp.Path
		raw, err := sendMessageOnce(t.Context(), savedMessageTransmit{
			envelope: "sensitive bytes"}, invalidURL)
		assert.Equal(err, errMessageNotDispatched)
		assert.SNil(raw)
	}
	for _, suffix := range []string{"?", "?sensitive", "#", "#sensitive", "/"} {
		assert.ThatNot(messagehttp.ValidURL(valid + suffix))
	}
	assert.ThatNot(
		messagehttp.ValidURL(
			strings.Replace(valid, "/message", "/%6dessage", 1),
		),
	)
	assert.ThatNot(messagehttp.ValidURL(strings.Repeat("a", 257)))
	for _, saved := range []savedMessageTransmit{{}, {
		envelope: strings.Repeat("x", maxMessageEnvelopeBytes+1),
	}} {
		raw, err := sendMessageOnce(t.Context(), saved, valid)
		assert.Equal(err, errMessageNotDispatched)
		assert.SNil(raw)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		raw, err := sendMessageOnce(
			ctx,
			savedMessageTransmit{envelope: "x"},
			valid,
		)
		assert.Equal(err, errMessageNotDispatched)
		assert.SNil(raw)
	}
	for _, version := range []int{-1, 0, 3} {
		raw, err := sendMessageVersionOnce(t.Context(), "x", valid, version)
		assert.Equal(err, errMessageNotDispatched)
		assert.SNil(raw)
	}
	assert.Equal(calls.Load(), 0)
}

func TestMessageClientVersionSelectionAndReceiptLimits(t *testing.T) {
	for _, version := range []int{1, 2} {
		limit := maxMessageReceiptBytes
		if version == 2 {
			limit = maxMessageReceiptBytesV2
		}
		for _, tc := range []struct {
			name            string
			responseVersion int
			receiptSize     int
		}{
			{"untrusted", version, 1},
			{"limit", version, limit},
			{"over limit", version, limit + 1},
			{"wrong version", 3 - version, 1},
		} {
			t.Run(fmt.Sprintf("v%d/%s", version, tc.name), func(t *testing.T) {
				defer assert.PushTester(t)()
				envelope := strings.Repeat("x", maxMessageEnvelopeBytes)
				want := bytes.Repeat([]byte{0xff}, tc.receiptSize)
				var calls atomic.Int64
				type captured struct {
					body []byte
					err  error
				}
				requests := make(chan captured, 1)
				server := httptest.NewServer(http.HandlerFunc(
					func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						body, err := io.ReadAll(r.Body)
						requests <- captured{body, err}
						w.Header().Set("Content-Type", "application/json")
						w.Header().Set("Cache-Control", "no-store")
						_, _ = fmt.Fprintf(
							w,
							`{"version":%d,"receipt":"%s"}`,
							tc.responseVersion,
							base64.StdEncoding.EncodeToString(want),
						)
					},
				))
				defer server.Close()
				destination := server.URL + messagehttp.Path
				var raw []byte
				var err error
				if version == 1 {
					var receipt MessageSendReceipt
					receipt, err = SendMessageOnce(
						t.Context(),
						PreparedMessageSend{
							saved: savedMessageTransmit{
								envelope: envelope,
							}},
						destination,
					)
					raw = []byte(receipt.raw)
				} else {
					raw, err = SendMessageOnceV2(t.Context(), PreparedMessageSendV2{
						saved: savedMessageTransmitV2{envelope, destination}})
				}
				if tc.responseVersion != version || tc.receiptSize > limit {
					assert.Equal(err, errMessageOutcomeUnknown)
					assert.Equal(err, messagehttp.ErrOutcomeUnknown)
					assert.Equal(len(raw), 0)
				} else {
					assert.NoError(err)
					assert.DeepEqual(raw, want)
				}
				assert.Equal(calls.Load(), 1)
				request := <-requests
				try.To(request.err)
				assert.Equal(string(request.body), fmt.Sprintf(
					`{"version":%d,"envelope":"%s"}`, version,
					base64.StdEncoding.EncodeToString([]byte(envelope))))
			})
		}
	}
}

func TestMessageClientErrorIdentity(t *testing.T) {
	defer assert.PushTester(t)()
	assert.Equal(ErrMessageNotDispatched, errMessageNotDispatched)
	assert.Equal(errMessageNotDispatched, messagehttp.ErrNotDispatched)
	assert.Equal(errMessageOutcomeUnknown, messagehttp.ErrOutcomeUnknown)

	receipt, err := SendMessageOnce(t.Context(), PreparedMessageSend{}, "")
	assert.Equal(err, ErrMessageNotDispatched)
	assert.Equal(receipt, MessageSendReceipt{})
	raw, err := SendMessageOnceV2(t.Context(), PreparedMessageSendV2{})
	assert.Equal(err, ErrMessageNotDispatched)
	assert.SNil(raw)
}

func TestMessageClientHostileHTTP(t *testing.T) {
	for _, mode := range []string{"redirect", "created", "refused", "server error",
		"missing media", "bad media", "duplicate media", "missing cache",
		"duplicate cache", "encoding", "empty encoding", "trailer",
		"large header", "large declared body", "large body", "short body",
		"malformed JSON", "bad status", "bad transfer encoding"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			var calls, redirected atomic.Int64
			sink := httptest.NewServer(
				http.HandlerFunc(func(http.ResponseWriter,
					*http.Request,
				) {
					redirected.Add(1)
				}),
			)
			defer sink.Close()
			worker := make(chan error, 1)
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter,
					_ *http.Request,
				) {
					calls.Add(1)
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Cache-Control", "no-store")
					body, status := `{"version":1,"receipt":"AA=="}`, 200
					switch mode {
					case "redirect":
						w.Header().Set("Location", sink.URL)
						status = 307
					case "created":
						status = 201
					case "refused":
						status = 409
					case "server error":
						status = 500
					case "missing media":
						w.Header()["Content-Type"] = nil
					case "bad media":
						w.Header().
							Set("Content-Type", "application/json; sensitive")
					case "duplicate media":
						w.Header().Add("Content-Type", "application/json")
					case "missing cache":
						w.Header().Del("Cache-Control")
					case "duplicate cache":
						w.Header().Add("Cache-Control", "no-store")
					case "encoding":
						w.Header().Set("Content-Encoding", "gzip")
					case "empty encoding":
						w.Header().Set("Content-Encoding", "")
					case "trailer":
						w.Header().Set("Trailer", "X-Sensitive")
					case "large header":
						w.Header().Set("X-Sensitive", strings.Repeat("x", 2048))
					case "large declared body":
						w.Header().Set("Content-Length", "1000000")
					case "large body":
						// Exceed the fixed 2 KiB HTTP response limit.
						body = strings.Repeat("x", 2049)
						w.WriteHeader(status)
						w.(http.Flusher).Flush() // Exercise the read bound, not length.
						_, _ = io.WriteString(w, body)
						return
					case "short body":
						w.Header().Set("Content-Length", "1000")
					case "malformed JSON":
						body = `{"version":1,"receipt":"sensitive"}`
					case "bad status", "bad transfer encoding":
						conn, _, err := w.(http.Hijacker).Hijack()
						if err == nil {
							header := "HTTP/1.1 sensitive\r\n\r\n"
							if mode == "bad transfer encoding" {
								header = "HTTP/1.1 200 OK\r\nTransfer-Encoding: sensitive\r\n\r\n"
							}
							_, err = io.WriteString(conn, header)
							closeErr := conn.Close()
							if err == nil {
								err = closeErr
							}
						}
						worker <- err
						return
					}
					w.WriteHeader(status)
					_, _ = io.WriteString(w, body)
				}),
			)
			defer server.Close()
			raw, err := sendMessageOnce(t.Context(), savedMessageTransmit{
				envelope: "sensitive input"}, server.URL+messagehttp.Path)
			assert.Equal(err, errMessageOutcomeUnknown)
			assert.SNil(raw)
			assert.Equal(calls.Load(), 1)
			assert.Equal(redirected.Load(), 0)
			if mode == "bad status" || mode == "bad transfer encoding" {
				try.To(<-worker)
			}
		})
	}
}

func TestMessageClientCancellationAfterDispatch(t *testing.T) {
	defer assert.PushTester(t)()
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter,
		*http.Request,
	) {
		close(entered)
		<-release
	}))
	defer server.Close()
	defer close(release)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := sendMessageOnce(ctx, savedMessageTransmit{envelope: "x"},
			server.URL+messagehttp.Path)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not arrive")
	}
	cancel()
	select {
	case err := <-done:
		assert.Equal(err, errMessageOutcomeUnknown)
	case <-time.After(time.Second):
		t.Fatal("cancellation did not bound request")
	}
}

func TestMessageClientSensitiveRefusal(t *testing.T) {
	defer assert.PushTester(t)()
	for _, destination := range []string{
		"http://sensitive:password@127.0.0.1:80" + messagehttp.Path,
		"http://127.0.0.1:sensitive" + messagehttp.Path,
	} {
		_, err := sendMessageOnce(t.Context(), savedMessageTransmit{
			envelope: "sensitive plaintext"}, destination)
		assert.Equal(err, errMessageNotDispatched)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		_ *http.Request,
	) {
		w.Header().Set("Content-Type", "sensitive header")
		_, _ = w.Write(bytes.Repeat([]byte("sensitive payload"), 10))
	}))
	_, err := sendMessageOnce(t.Context(), savedMessageTransmit{
		envelope: "sensitive plaintext"}, server.URL+messagehttp.Path)
	assert.Equal(err, errMessageOutcomeUnknown)
	server.Close()
	_, err = sendMessageOnce(t.Context(), savedMessageTransmit{
		envelope: "sensitive plaintext"}, server.URL+messagehttp.Path)
	assert.Equal(err, errMessageOutcomeUnknown)
}

func TestMessageClientTimeout(t *testing.T) {
	defer assert.PushTester(t)()
	var calls atomic.Int64
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter,
		*http.Request,
	) {
		calls.Add(1)
		<-release
	}))
	defer server.Close()
	defer close(release)
	// The outer deadline bounds a regression; the client's five-second bound
	// must fire first even when the peer never supplies response headers.
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	start := time.Now()
	raw, err := sendMessageOnce(ctx, savedMessageTransmit{envelope: "x"},
		server.URL+messagehttp.Path)
	assert.Equal(err, errMessageOutcomeUnknown)
	assert.SNil(raw)
	assert.Equal(calls.Load(), 1)
	assert.That(time.Since(start) < 9*time.Second)
}
