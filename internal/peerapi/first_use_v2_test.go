package peerapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
)

func TestFirstUseVersionedPeerEnvelope(t *testing.T) {
	defer assert.PushTester(t)()
	for _, version := range []string{"1", "2"} {
		calls := 0
		h := NewFirstUseHandler(func(v int, raw []byte) ([]byte, error) {
			calls++
			assert.Equal(v, int(version[0]-'0'))
			assert.DeepEqual(raw, []byte{1})
			return []byte{2}, nil
		}, http.NotFoundHandler())
		valid := `{"version":` + version + `,"request":"AQ=="}`
		for _, body := range []string{
			valid[:len(valid)-1] + `,"version":` + version + `}`,
			valid[:len(valid)-1] + `,"request":"AQ=="}`,
			valid[:len(valid)-1] + `,"runtime":true}`,
			strings.Replace(valid, `"version"`, `"ver\u0073ion"`, 1),
			strings.Replace(valid, `"request"`, `"reque\u0073t"`, 1),
			strings.Replace(valid, `,"request"`, `.0,"request"`, 1),
			strings.Replace(valid, `,"request"`, `e0,"request"`, 1),
			strings.Replace(valid, `AQ==`, `AR==`, 1),
			strings.Replace(valid, `AQ==`, `AQ==\n`, 1),
			valid + `{}`, "", "null", "[]",
			`{"version":3,"request":"AQ=="}`,
		} {
			r := httptest.NewRequest("POST", "/peer/pw/first-use",
				strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			assert.Equal(w.Code, 400)
			assert.Equal(w.Body.String(), "Bad Request\n")
		}
		assert.Equal(calls, 0)
		r := httptest.NewRequest("POST", "/peer/pw/first-use",
			strings.NewReader(valid))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assert.Equal(w.Code, 200)
		assert.Equal(w.Body.String(),
			`{"version":`+version+`,"response":"Ag=="}`)
		assert.Equal(w.Header().Get("Cache-Control"), "no-store")
		assert.Equal(calls, 1)
	}
}
