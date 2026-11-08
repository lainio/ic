package ownerapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/storage"
)

func messageSendOwner(t *testing.T) (establishmentOwnerFixture,
	http.Handler, string, *firstUseHandler,
) {
	t.Helper()
	defer assert.PushTester(t)()
	f, _, body := firstUseOwnerTarget(t)
	assert.Equal(deviceRequest(f.peer, "", "POST",
		"/peer/pw/first-use", body).Code, 200)
	h, auth := deleteHeldCredential(t, f.vault, f.root, f.child, f.signer)
	return f, h, auth, h.(*authenticatedStatusHandler).next.(*firstUseHandler)
}

func messageSendBody(t *testing.T, text, url string) string {
	t.Helper()
	defer assert.PushTester(t)()
	return string(try.To1(json.Marshal(map[string]string{
		"text": text, "peer_message_url": url,
	})))
}

func messageSendRows(t *testing.T, v *storage.Vault) (rows [4][]byte) {
	t.Helper()
	defer assert.PushTester(t)()
	try.To(v.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		for i, name := range []string{
			"local-pw-message-outgoing-v1", "local-pw-message-envelope-v1",
			"local-pw-message-sent-v1", "local-pw-message-ack-v1",
		} {
			rows[i], _ = try.To2(tx.Get([]byte(name)))
		}
		return nil
	}))
	return rows
}

func TestOwnerMessageSendTextAndCanonicalURLBounds(t *testing.T) {
	defer assert.PushTester(t)()
	for _, url := range []string{"http://127.0.0.1:1/peer/pw/message",
		"http://127.0.0.2:65535/peer/pw/message",
		"http://[::1]:8080/peer/pw/message"} {
		for _, text := range []string{"x", strings.Repeat("é", 512)} {
			body := messageSendBody(t, text, url)
			body += strings.Repeat(" ", maxMessageSendRequestBytes-len(body))
			r := httptest.NewRequest("POST", messageSendPath, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			input, status := readMessageSendRequest(httptest.NewRecorder(), r)
			assert.Equal(status, 0)
			assert.Equal(input.version, 1)
			assert.Equal(input.text, text)
			assert.Equal(input.peerURL, url)
		}
	}
}

func TestOwnerMessageSendInvalidPreflightNeverWritesOrPosts(t *testing.T) {
	defer assert.PushTester(t)()
	f, h, auth, _ := messageSendOwner(t)
	defer f.unchanged(t)()
	var posts atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter,
		*http.Request,
	) {
		posts.Add(1)
	}))
	defer s.Close()
	url := s.URL + "/peer/pw/message"
	good := messageSendBody(t, "text", url)
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"empty", "", 400}, {"array", "[]", 400}, {"null", "null", 400},
		{"missing text", `{"peer_message_url":"` + url + `"}`, 400},
		{"missing URL", `{"text":"hello"}`, 400},
		{"unknown", good[:len(good)-1] + `,"extra":true}`, 400},
		{"duplicate text", good[:len(good)-1] + `,"text":"text"}`, 400},
		{"duplicate URL", good[:len(good)-1] + `,"peer_message_url":"` + url + `"}`, 400},
		{"alias", strings.Replace(good, `"text"`, `"te\u0078t"`, 1), 400},
		{"URL alias", strings.Replace(good, `"peer_message_url"`, `"peer_message_ur\u006c"`, 1), 400},
		{"case", strings.Replace(good, `"text"`, `"Text"`, 1), 400},
		{"number", strings.Replace(good, `:"text"`, `:1`, 1), 400},
		{"boolean", strings.Replace(good, `:"text"`, `:true`, 1), 400},
		{"null text", strings.Replace(good, `:"text"`, `:null`, 1), 400},
		{"object text", strings.Replace(good, `:"text"`, `:{}`, 1), 400},
		{"URL type", `{"text":"text","peer_message_url":[]}`, 400},
		{"trailing", good + " {}", 400},
		{"malformed", good[:len(good)-1], 400},
		{"UTF8", strings.Replace(good, `:"text"`, ":\"\xff\"", 1), 400},
		{"empty text", messageSendBody(t, "", url), 400},
		{"text bytes", messageSendBody(t, strings.Repeat("é", 513), url), 400},
		{"text ASCII", messageSendBody(t, strings.Repeat("x", 1025), url), 400},
		{"too large", good + strings.Repeat(" ", 2048), 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			w := deviceRequest(h, auth, "POST", messageSendPath, tc.body)
			assert.Equal(w.Code, tc.status)
			assert.Equal(w.Body.String(), http.StatusText(tc.status)+"\n")
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
		})
	}
	for _, badURL := range []string{
		"", s.URL, url + "?", url + "?x=1", url + "#x",
		"http://localhost:80/peer/pw/message",
		"https://127.0.0.1:80/peer/pw/message",
		"http://127.0.0.1:0/peer/pw/message",
		"http://127.0.0.1:080/peer/pw/message",
		"http://192.0.2.1:80/peer/pw/message",
		"http://user@127.0.0.1:80/peer/pw/message",
		"http://[0:0:0:0:0:0:0:1]:80/peer/pw/message",
		"http://[::ffff:127.0.0.1]:80/peer/pw/message",
		"http://[::1%lo]:80/peer/pw/message",
	} {
		assert.Equal(deviceRequest(h, auth, "POST", messageSendPath,
			messageSendBody(t, "text", badURL)).Code, 400)
	}
	for _, mode := range []string{"no auth", "bad auth", "duplicate auth",
		"method", "media", "duplicate media", "encoding", "trailer",
		"trailer map", "transfer", "transfer header", "query", "fragment",
		"raw fragment", "escaped", "opaque", "nil body", "canceled",
		"unknown length oversized", "declared oversized"} {
		r := httptest.NewRequest(
			"POST",
			messageSendPath,
			strings.NewReader(good),
		)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", auth)
		want := 400
		switch mode {
		case "no auth":
			r.Header.Del("Authorization")
			want = 401
		case "bad auth":
			r.Header.Set("Authorization", "Bearer wrong")
			want = 401
		case "duplicate auth":
			r.Header.Add("Authorization", auth)
			want = 401
		case "method":
			r.Method = "GET"
			want = 405
		case "media":
			r.Header.Set("Content-Type", "text/plain")
			want = 415
		case "duplicate media":
			r.Header.Add("Content-Type", "application/json")
			want = 415
		case "encoding":
			r.Header.Set("Content-Encoding", "identity")
		case "trailer":
			r.Header.Set("Trailer", "X-Test")
		case "trailer map":
			r.Trailer = http.Header{"X-Test": nil}
		case "transfer":
			r.TransferEncoding = []string{"chunked"}
		case "transfer header":
			r.Header.Set("Transfer-Encoding", "chunked")
		case "query":
			r.URL.ForceQuery = true
		case "fragment":
			r.URL.Fragment = "x"
		case "raw fragment":
			r.URL.RawFragment = "%78"
		case "escaped":
			r.URL.RawPath = "/owner/pw/message/%73end"
			want = 404
		case "opaque":
			r.URL.Opaque = "//localhost" + messageSendPath
			want = 404
		case "nil body":
			r.Body = nil
		case "canceled":
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			r = r.WithContext(ctx)
			want = 409
		case "unknown length oversized":
			r = httptest.NewRequest("POST", messageSendPath,
				strings.NewReader(good+strings.Repeat(" ", 2048)))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", auth)
			r.ContentLength = -1
			want = 413
		case "declared oversized":
			r.ContentLength = 2049
			want = 413
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assert.Equal(w.Code, want, mode)
		assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
	}
	assert.Equal(posts.Load(), 0)
	assert.DeepEqual(messageSendRows(t, f.vault), [4][]byte{})
}

func TestOwnerMessageSendPartialPreparationAndExplicitRecovery(t *testing.T) {
	for seals := range int64(3) {
		t.Run(fmt.Sprint(seals), func(t *testing.T) {
			defer assert.PushTester(t)()
			f, h, auth, target := messageSendOwner(t)
			var posts atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
				_ *http.Request,
			) {
				posts.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				_, _ = w.Write([]byte(`{"version":1,"receipt":"/w=="}`))
			}))
			defer s.Close()
			body := messageSendBody(t, "retained", s.URL+"/peer/pw/message")
			f.lease.remaining.Store(seals)
			w := deviceRequest(h, auth, "POST", messageSendPath, body)
			assert.Equal(w.Code, 409)
			assert.Equal(posts.Load(), 0)
			before := messageSendRows(t, f.vault)
			for i, row := range before {
				assert.Equal(len(row) > 0, int64(i) < seals)
			}
			f.lease.remaining.Store(16)
			r := httptest.NewRequest(
				"POST",
				messageSendPath,
				strings.NewReader(body),
			)
			r.Header.Set("Authorization", auth)
			r.Header.Set("Content-Type", "application/json")
			writer := &establishmentWriter{
				ResponseRecorder: httptest.NewRecorder(),
				onHeader: func() {
					assert.That(target.mutations.TryLock())
					target.mutations.Unlock()
				},
			}
			h.ServeHTTP(writer, r)
			assert.Equal(writer.Code, 502) // HTTP 200 with invalid receipt.
			assert.Equal(posts.Load(), 1)
			after := messageSendRows(t, f.vault)
			for i := range 3 {
				assert.SNotEmpty(after[i])
				if before[i] != nil {
					assert.DeepEqual(after[i], before[i])
				}
			}
			assert.SNil(after[3])
		})
	}
}
