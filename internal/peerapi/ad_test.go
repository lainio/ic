package peerapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestAdRequestBoundaryBeforeVaultReads(t *testing.T) {
	defer assert.PushTester(t)()
	// A nil Vault cannot successfully answer any valid read.
	h := NewAdHandler(nil, nil, nil, "http://127.0.0.1:1/peer/introduction")
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/", "", 404},
		{"GET", "/peer/ad/", "", 404},
		{"GET", "/peer//ad", "", 404},
		{"GET", "/peer/../peer/ad", "", 404},
		{"GET", "/peer/%61d", "", 404},
		{"GET", "/peer%2fad", "", 404},
		{"GET", "/peer/ad;slot=1", "", 404},
		{"HEAD", "/peer/ad", "", 405},
		{"POST", "/peer/ad", "{}", 405},
		{"PUT", "/peer/ad", "", 405},
		{"DELETE", "/peer/ad", "", 405},
		{"OPTIONS", "/peer/ad", "", 405},
		{"GET", "/peer/ad?", "", 400},
		{"GET", "/peer/ad?root=x&subject=x&slot=1&device=x&now=0&ad=x&token=x", "", 400},
		{"GET", "/peer/ad", "{}", 400},
		{"GET", "/owner/status", "", 404},
		{"GET", "/owner/introduction", "", 404},
		{"POST", "/owner/introduction/check", "{}", 404},
		{"GET", "/owner/introductions", "", 404},
		{"POST", "/owner/introductions", "{}", 404},
		{"POST", "/owner/introductions/fetch", "{}", 404},
		{"POST", "/owner/introductions/verify", "{}", 404},
		{"POST", "/owner/device/bootstrap", "{}", 404},
		{"POST", "/owner/ads/publish", "{}", 404},
	} {
		for _, bearer := range []string{"", "Bearer copied-owner-credential"} {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Authorization", bearer)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			assert.Equal(w.Code, tc.status, tc.path)
			assert.Equal(w.Body.String(), http.StatusText(tc.status)+"\n")
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
			assert.Equal(string(try.To1(io.ReadAll(r.Body))), tc.body)
			if tc.status == 405 {
				assert.Equal(w.Header().Get("Allow"), "GET")
			}
		}
	}
	for _, scenario := range []string{"fragment", "raw fragment", "raw path", "opaque", "unknown length", "chunked", "hidden body"} {
		r := httptest.NewRequest(http.MethodGet, "/peer/ad", nil)
		want := 400
		switch scenario {
		case "fragment":
			r.URL.Fragment = "selector"
		case "raw fragment":
			r.URL.RawFragment = "%73elector"
		case "raw path":
			r.URL.RawPath, want = "/peer/ad", 404
		case "opaque":
			r.URL.Opaque, want = "/peer/ad", 404
		case "unknown length":
			r.ContentLength = -1
		case "chunked":
			r.TransferEncoding = []string{"chunked"}
		case "hidden body":
			r.Body = io.NopCloser(strings.NewReader("selector"))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assert.Equal(w.Code, want, scenario)
		assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
	}
}
