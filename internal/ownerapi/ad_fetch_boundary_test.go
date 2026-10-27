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

const adFetchPath = "/owner/ads/fetch"

func TestPeerAdURL(t *testing.T) {
	defer assert.PushTester(t)()

	for _, tc := range []struct{ input, want string }{
		{"http://localhost:0080/peer/ad", "http://127.0.0.1:80/peer/ad"},
		{"http://127.0.0.2:65535/peer/ad", "http://127.0.0.2:65535/peer/ad"},
		{"http://[0:0:0:0:0:0:0:1]:1/peer/ad", "http://[::1]:1/peer/ad"},
		{"http://[::ffff:127.0.0.1]:80/peer/ad", "http://127.0.0.1:80/peer/ad"},
	} {
		assert.Equal(try.To1(peerFetchURL(tc.input, "/peer/ad")), tc.want)
	}
}

func TestAdFetchInvalidDestinationsNeverDial(t *testing.T) {
	defer assert.PushTester(t)()

	// Client traces travel with the owner context into outbound HTTP. Invalid
	// destinations must never reach DNS or dialing, even on failure paths.
	var dials, lookups atomic.Int32
	ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) { dials.Add(1) },
		DNSStart:     func(httptrace.DNSStartInfo) { lookups.Add(1) },
	})
	for _, destination := range []string{
		"", "http://127.0.0.1/peer/ad", "//127.0.0.1:80/peer/ad",
		"https://127.0.0.1:80/peer/ad", "HTTP://127.0.0.1:80/peer/ad",
		"file:///peer/ad", "http://:80/peer/ad",
		"http://0.0.0.0:80/peer/ad", "http://[::]:80/peer/ad",
		"http://192.168.1.1:80/peer/ad", "http://169.254.169.254:80/peer/ad",
		"http://[2001:db8::1]:80/peer/ad", "http://example.com:80/peer/ad",
		"http://localhost.:80/peer/ad", "http://LOCALHOST:80/peer/ad",
		"http://127.1:80/peer/ad", "http://2130706433:80/peer/ad",
		"http://[127.0.0.1]:80/peer/ad", "http://[localhost]:80/peer/ad",
		"http://::1:80/peer/ad", "http://[::1%25lo]:80/peer/ad",
		"http://user:secret@127.0.0.1:80/peer/ad", "http://@127.0.0.1:80/peer/ad",
		"http://127.0.0.1:0/peer/ad", "http://127.0.0.1:65536/peer/ad",
		"http://127.0.0.1:-1/peer/ad", "http://127.0.0.1:+80/peer/ad",
		"http://127.0.0.1:http/peer/ad", "http://127.0.0.1:/peer/ad",
		"http://127.0.0.1:80/owner/introduction", "http://127.0.0.1:80/peer/ad/",
		"http://127.0.0.1:80/peer/../peer/ad", "http://127.0.0.1:80//peer/ad",
		"http://127.0.0.1:80/peer/%69ntroduction", "http://127.0.0.1:80/peer%2fintroduction",
		"http://127.0.0.1:80/peer/ad?", "http://127.0.0.1:80/peer/ad?x=1",
		"http://127.0.0.1:80/peer/ad#", "http://127.0.0.1:80/peer/ad#fragment",
		"http://127.0.0.1:80/peer/ad ", "http://127.0.0.1:80/peer\\ad", "http://127.0.0.1:80/peer/introduction",
		" http://127.0.0.1:80/peer/ad", "http://127.0.0.1:80/peer/ad\n",
	} {
		t.Run(destination, func(t *testing.T) {
			defer assert.PushTester(t)()

			data := try.To1(json.Marshal(map[string]string{"peer_url": destination}))
			r := httptest.NewRequestWithContext(ctx, http.MethodPost, adFetchPath, bytes.NewReader(data))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			(&publicationHandler{deviceHandler: newDeviceHandler(nil, nil, nil, nil)}).ServeHTTP(w, r)
			assert.Equal(w.Code, http.StatusBadRequest)
			assert.Equal(w.Body.String(), "Bad Request\n")
		})
	}
	assert.Equal(dials.Load(), int32(0))
	assert.Equal(lookups.Load(), int32(0))
}

func TestAdFetchStrictOwnerEnvelope(t *testing.T) {
	defer assert.PushTester(t)()

	for _, body := range []string{
		`{}`, `null`, `[]`, `{"peer_url":null}`, `{"peer_url":1}`, `{"peer_url":{}}`,
		`{"peer_url":""}`, `{"Peer_URL":"http://127.0.0.1:1/peer/ad"}`,
		`{"peer_url":"http://127.0.0.1:1/peer/ad","peer_url":"x"}`,
		`{"peer_url":"http://127.0.0.1:1/peer/ad","root":"x"}`,
		`{"peer_url":"http://127.0.0.1:1/peer/ad","headers":{}}`,
		`{"peer_url":"http://127.0.0.1:1/peer/ad"} {}`,
		`{"peer_url":"http://127.0.0.1:1/peer/ad"`,
		"{\"peer_url\":\"\xff\"}",
	} {
		r := httptest.NewRequest(http.MethodPost, adFetchPath, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		(&publicationHandler{deviceHandler: newDeviceHandler(nil, nil, nil, nil)}).ServeHTTP(w, r)
		assert.Equal(w.Code, http.StatusBadRequest)
	}
	// Bound actual bytes even when Content-Length claims a tiny body.
	reader := strings.NewReader(strings.Repeat(" ", 4096))
	r := httptest.NewRequest(http.MethodPost, adFetchPath, reader)
	r.ContentLength = 1
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	(&publicationHandler{deviceHandler: newDeviceHandler(nil, nil, nil, nil)}).ServeHTTP(w, r)
	assert.Equal(w.Code, http.StatusRequestEntityTooLarge)
	assert.Equal(reader.Len(), 4096-maxFetchRequestBytes-1)
}

func TestAdFetchAuthMethodAndPathBoundary(t *testing.T) {
	defer assert.PushTester(t)()

	token := bytes.Repeat([]byte{0xab}, ownerStatusTokenSize)
	authorization := "Bearer " + hex.EncodeToString(token)
	handler := try.To1(newAuthenticatedHandler((&publicationHandler{deviceHandler: newDeviceHandler(nil, nil, nil, nil)}), token))
	for _, tc := range []struct {
		method, path, media string
		status              int
	}{
		{"GET", adFetchPath, "application/json", 405},
		{"HEAD", adFetchPath, "application/json", 405},
		{"PUT", adFetchPath, "application/json", 405},
		{"DELETE", adFetchPath, "application/json", 405},
		{"OPTIONS", adFetchPath, "application/json", 405},
		{"POST", adFetchPath + "/", "application/json", 404},
		{"POST", "/owner/ads/%66etch", "application/json", 404},
		{"POST", "/owner//ads/fetch", "application/json", 404},
		{"POST", "/peer/ad", "application/json", 404},
		{"POST", adFetchPath + "?", "application/json", 400},
		{"POST", adFetchPath + "?root=other", "application/json", 400},
		{"POST", adFetchPath, "", 415},
		{"POST", adFetchPath, "text/plain", 415},
		{"POST", adFetchPath, "application/json, application/json", 415},
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

func TestAdFetchExtraRequestSelectors(t *testing.T) {
	defer assert.PushTester(t)()
	h, auth, _ := publicationCredential(t, nil, nil, nil, nil)
	for _, selector := range []string{"fragment", "raw fragment", "opaque", "duplicate media", "duplicate authorization"} {
		r := adFetchRequest(auth, "http://127.0.0.1:1")
		body := &ownerStatusUnreadBody{}
		r.Body = io.NopCloser(body)
		want := 400
		switch selector {
		case "fragment":
			r.URL.Fragment = "selector"
		case "raw fragment":
			r.URL.RawFragment = "%73elector"
		case "opaque":
			r.URL.Opaque = "//127.0.0.1:1/owner/ads/fetch"
			want = 404
		case "duplicate media":
			r.Header.Add("Content-Type", "application/json")
			want = 415
		case "duplicate authorization":
			r.Header.Add("Authorization", auth)
			want = 401
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assert.Equal(w.Code, want)
		assert.Equal(body.reads, 0)
	}
}
