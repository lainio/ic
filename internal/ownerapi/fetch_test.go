package ownerapi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

const fetchPath = "/owner/introductions/fetch"

func TestPeerIntroductionURL(t *testing.T) {
	defer assert.PushTester(t)()

	for _, tc := range []struct{ input, want string }{
		{"http://localhost:0080/peer/introduction", "http://127.0.0.1:80/peer/introduction"},
		{"http://127.0.0.2:65535/peer/introduction", "http://127.0.0.2:65535/peer/introduction"},
		{"http://[0:0:0:0:0:0:0:1]:1/peer/introduction", "http://[::1]:1/peer/introduction"},
		{"http://[::ffff:127.0.0.1]:80/peer/introduction", "http://127.0.0.1:80/peer/introduction"},
	} {
		assert.Equal(try.To1(peerIntroductionURL(tc.input)), tc.want)
	}
}

func TestFetchInvalidDestinationsNeverDial(t *testing.T) {
	defer assert.PushTester(t)()

	// Client traces travel with the owner context into outbound HTTP. Invalid
	// destinations must never reach DNS or dialing, even on failure paths.
	var dials, lookups atomic.Int32
	ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) { dials.Add(1) },
		DNSStart:     func(httptrace.DNSStartInfo) { lookups.Add(1) },
	})
	for _, destination := range []string{
		"", "http://127.0.0.1/peer/introduction", "//127.0.0.1:80/peer/introduction",
		"https://127.0.0.1:80/peer/introduction", "HTTP://127.0.0.1:80/peer/introduction",
		"file:///peer/introduction", "http://:80/peer/introduction",
		"http://0.0.0.0:80/peer/introduction", "http://[::]:80/peer/introduction",
		"http://192.168.1.1:80/peer/introduction", "http://169.254.169.254:80/peer/introduction",
		"http://[2001:db8::1]:80/peer/introduction", "http://example.com:80/peer/introduction",
		"http://localhost.:80/peer/introduction", "http://LOCALHOST:80/peer/introduction",
		"http://127.1:80/peer/introduction", "http://2130706433:80/peer/introduction",
		"http://[127.0.0.1]:80/peer/introduction", "http://[localhost]:80/peer/introduction",
		"http://::1:80/peer/introduction", "http://[::1%25lo]:80/peer/introduction",
		"http://user:secret@127.0.0.1:80/peer/introduction", "http://@127.0.0.1:80/peer/introduction",
		"http://127.0.0.1:0/peer/introduction", "http://127.0.0.1:65536/peer/introduction",
		"http://127.0.0.1:-1/peer/introduction", "http://127.0.0.1:+80/peer/introduction",
		"http://127.0.0.1:http/peer/introduction", "http://127.0.0.1:/peer/introduction",
		"http://127.0.0.1:80/owner/introduction", "http://127.0.0.1:80/peer/introduction/",
		"http://127.0.0.1:80/peer/../peer/introduction", "http://127.0.0.1:80//peer/introduction",
		"http://127.0.0.1:80/peer/%69ntroduction", "http://127.0.0.1:80/peer%2fintroduction",
		"http://127.0.0.1:80/peer/introduction?", "http://127.0.0.1:80/peer/introduction?x=1",
		"http://127.0.0.1:80/peer/introduction#", "http://127.0.0.1:80/peer/introduction#fragment",
		" http://127.0.0.1:80/peer/introduction", "http://127.0.0.1:80/peer/introduction\n",
	} {
		t.Run(destination, func(t *testing.T) {
			defer assert.PushTester(t)()

			data := try.To1(json.Marshal(map[string]string{"peer_url": destination}))
			r := httptest.NewRequestWithContext(ctx, http.MethodPost, fetchPath, bytes.NewReader(data))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			newEvidenceHandler(nil, nil, nil).ServeHTTP(w, r)
			assert.Equal(w.Code, http.StatusBadRequest)
			assert.Equal(w.Body.String(), "Bad Request\n")
		})
	}
	assert.Equal(dials.Load(), int32(0))
	assert.Equal(lookups.Load(), int32(0))
}

func TestFetchStrictOwnerEnvelope(t *testing.T) {
	defer assert.PushTester(t)()

	for _, body := range []string{
		`{}`, `null`, `[]`, `{"peer_url":null}`, `{"peer_url":1}`, `{"peer_url":{}}`,
		`{"peer_url":""}`, `{"Peer_URL":"http://127.0.0.1:1/peer/introduction"}`,
		`{"peer_url":"http://127.0.0.1:1/peer/introduction","peer_url":"x"}`,
		`{"peer_url":"http://127.0.0.1:1/peer/introduction","root":"x"}`,
		`{"peer_url":"http://127.0.0.1:1/peer/introduction","headers":{}}`,
		`{"peer_url":"http://127.0.0.1:1/peer/introduction"} {}`,
		`{"peer_url":"http://127.0.0.1:1/peer/introduction"`,
		"{\"peer_url\":\"\xff\"}",
	} {
		r := httptest.NewRequest(http.MethodPost, fetchPath, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		newEvidenceHandler(nil, nil, nil).ServeHTTP(w, r)
		assert.Equal(w.Code, http.StatusBadRequest)
	}
	// Bound actual bytes even when Content-Length claims a tiny body.
	reader := strings.NewReader(strings.Repeat(" ", 4096))
	r := httptest.NewRequest(http.MethodPost, fetchPath, reader)
	r.ContentLength = 1
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	newEvidenceHandler(nil, nil, nil).ServeHTTP(w, r)
	assert.Equal(w.Code, http.StatusRequestEntityTooLarge)
	assert.Equal(reader.Len(), 4096-maxFetchRequestBytes-1)
}

func TestFetchAuthMethodAndPathBoundary(t *testing.T) {
	defer assert.PushTester(t)()

	token := bytes.Repeat([]byte{0xab}, ownerStatusTokenSize)
	authorization := "Bearer " + hex.EncodeToString(token)
	handler := try.To1(newAuthenticatedHandler(newEvidenceHandler(nil, nil, nil), token))
	for _, tc := range []struct {
		method, path, media string
		status              int
	}{
		{"GET", fetchPath, "application/json", 405},
		{"HEAD", fetchPath, "application/json", 405},
		{"PUT", fetchPath, "application/json", 405},
		{"DELETE", fetchPath, "application/json", 405},
		{"OPTIONS", fetchPath, "application/json", 405},
		{"POST", fetchPath + "/", "application/json", 404},
		{"POST", "/owner/introductions/%66etch", "application/json", 404},
		{"POST", "/owner//introductions/fetch", "application/json", 404},
		{"POST", "/peer/introduction", "application/json", 404},
		{"POST", fetchPath + "?", "application/json", 400},
		{"POST", fetchPath + "?root=other", "application/json", 400},
		{"POST", fetchPath, "", 415},
		{"POST", fetchPath, "text/plain", 415},
		{"POST", fetchPath, "application/json, application/json", 415},
	} {
		for _, auth := range []string{"", "Bearer wrong", authorization} {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			r.Header.Set("Authorization", auth)
			r.Header.Set("Content-Type", tc.media)
			body := &ownerStatusUnreadBody{}
			r.Body = io.NopCloser(body)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			want := http.StatusUnauthorized
			if auth == authorization {
				want = tc.status
			}
			assert.Equal(w.Code, want)
			assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
			assert.Equal(body.reads, 0)
			if want == http.StatusMethodNotAllowed {
				assert.Equal(w.Header().Get("Allow"), http.MethodPost)
			}
		}
	}
}
