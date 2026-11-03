package ownerapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lainio/err2/assert"
)

func TestDenyAuthAndRoutingBeforeBody(t *testing.T) {
	defer assert.PushTester(t)()
	h, auth := deleteHeldCredential(t, nil, nil, nil, nil)
	for _, tc := range []struct {
		method, path, media, extra string
		status                     int
	}{
		{"POST", denyPath, "application/json", "auth", 401},
		{"GET", denyPath, "application/json", "", 405},
		{"HEAD", denyPath, "application/json", "", 405},
		{"PUT", denyPath, "application/json", "", 405},
		{"DELETE", denyPath, "application/json", "", 405},
		{"OPTIONS", denyPath, "application/json", "", 405},
		{"POST", denyPath + "/", "application/json", "", 404},
		{"POST", "/owner/policy/%64eny", "application/json", "", 404},
		{"POST", "/owner//policy/deny", "application/json", "", 404},
		{"POST", "/owner/policy/../policy/deny", "application/json", "", 404},
		{"POST", denyPath + "?", "application/json", "", 400},
		{"POST", denyPath + "?root=x", "application/json", "", 400},
		{"POST", denyPath, "", "", 415},
		{"POST", denyPath, "text/plain", "", 415},
		{"POST", denyPath, "application/json, application/json", "", 415},
		{"POST", denyPath, "application/json", "media", 415},
		{"POST", denyPath, "application/json", "fragment", 400},
		{"POST", denyPath, "application/json", "raw fragment", 400},
		{"POST", denyPath, "application/json", "opaque", 404},
	} {
		for _, credential := range []string{"", "Bearer wrong", auth} {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			r.Header.Set("Authorization", credential)
			r.Header.Set("Content-Type", tc.media)
			switch tc.extra {
			case "auth":
				r.Header.Add("Authorization", auth)
			case "media":
				r.Header.Add("Content-Type", "application/json")
			case "fragment":
				r.URL.Fragment = "x"
			case "raw fragment":
				r.URL.RawFragment = "%78"
			case "opaque":
				r.URL.Opaque = "//localhost" + denyPath
			}
			body := &ownerStatusUnreadBody{}
			r.Body = io.NopCloser(body)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := tc.status
			if credential != auth {
				want = 401
			}
			assert.Equal(w.Code, want)
			assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
			assert.Equal(body.reads, 0)
			if want == 405 {
				assert.Equal(w.Header().Get("Allow"), "POST")
			}
		}
	}
}
