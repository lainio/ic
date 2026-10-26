package ownerapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/peerapi"
)

const verifyPath = "/owner/introductions/verify"

func TestVerifyCredentialAndRequestBoundary(t *testing.T) {
	defer assert.PushTester(t)()

	// Nil Vault makes any accidental storage access fail, including before auth.
	h, file := try.To2(NewEvidenceCredentials(t.Context(), nil, nil, nil, t.TempDir()))
	auth := strings.TrimSpace(strings.TrimPrefix(string(try.To1(os.ReadFile(file))), "Authorization: "))
	for _, tc := range []struct {
		method, path, body, media string
		status                    int
	}{
		{"GET", verifyPath, "{}", "application/json", 405},
		{"HEAD", verifyPath, "{}", "application/json", 405},
		{"PUT", verifyPath, "{}", "application/json", 405},
		{"DELETE", verifyPath, "{}", "application/json", 405},
		{"POST", verifyPath + "/", "{}", "application/json", 404},
		{"POST", "/owner/introductions/%76erify", "{}", "application/json", 404},
		{"POST", "/owner/introductions/../introductions/verify", "{}", "application/json", 404},
		{"POST", verifyPath + "?", "{}", "application/json", 400},
		{"POST", verifyPath + "?root=other", "{}", "application/json", 400},
		{"POST", verifyPath + "?subject=other", "{}", "application/json", 400},
		{"POST", verifyPath, "{}", "", 415},
		{"POST", verifyPath, "{}", "text/plain", 415},
		{"POST", verifyPath, "{}", "application/json, application/json", 415},
		{"POST", verifyPath, "", "application/json", 400},
		{"POST", verifyPath, "null", "application/json", 400},
		{"POST", verifyPath, "[]", "application/json", 400},
		{"POST", verifyPath, `{"root":"x"}`, "application/json", 400},
		{"POST", verifyPath, `{"subject":"x"}`, "application/json", 400},
		{"POST", verifyPath, `{"peer_url":"x"}`, "application/json", 400},
		{"POST", verifyPath, `{"x":0,"x":1}`, "application/json", 400},
		{"POST", verifyPath, "{} {}", "application/json", 400},
		{"POST", verifyPath, "{}x", "application/json", 400},
		{"POST", verifyPath, strings.Repeat(" ", 65), "application/json", 413},
	} {
		for _, credential := range []string{"", "Bearer wrong", auth} {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Authorization", credential)
			r.Header.Set("Content-Type", tc.media)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := tc.status
			if credential != auth {
				want = http.StatusUnauthorized
				assert.Equal(string(try.To1(io.ReadAll(r.Body))), tc.body)
			}
			assert.Equal(w.Code, want)
			assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
			if want == 405 {
				assert.Equal(w.Header().Get("Allow"), "POST")
			}
		}
	}
	for _, invalid := range []string{"duplicate media", "fragment", "raw fragment"} {
		r := httptest.NewRequest(http.MethodPost, verifyPath, strings.NewReader("{}"))
		r.Header.Set("Authorization", auth)
		r.Header.Set("Content-Type", "application/json")
		want := http.StatusBadRequest
		switch invalid {
		case "duplicate media":
			r.Header.Add("Content-Type", "application/json")
			want = http.StatusUnsupportedMediaType
		case "fragment":
			r.URL.Fragment = "selector"
		default:
			r.URL.RawFragment = "%73elector"
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assert.Equal(w.Code, want)
		assert.Equal(string(try.To1(io.ReadAll(r.Body))), "{}")
	}
}

func TestVerifyUnavailableToReadStatusAndPeer(t *testing.T) {
	defer assert.PushTester(t)()

	read, readFile := try.To2(NewReadCredentials(t.Context(), nil, nil, nil, t.TempDir()))
	status, statusFile := try.To2(NewStatusCredentials(t.Context(), nil, nil, nil, t.TempDir()))
	for _, tc := range []struct {
		handler http.Handler
		file    string
	}{
		{read, readFile}, {status, statusFile}, {peerapi.NewHandler(nil, nil, nil), ""},
	} {
		for _, method := range []string{http.MethodPost, http.MethodGet} {
			r := httptest.NewRequest(method, verifyPath, strings.NewReader("{}"))
			r.Header.Set("Content-Type", "application/json")
			if tc.file != "" {
				r.Header.Set("Authorization", strings.TrimSpace(strings.TrimPrefix(
					string(try.To1(os.ReadFile(tc.file))), "Authorization: ")))
			}
			w := httptest.NewRecorder()
			tc.handler.ServeHTTP(w, r)
			assert.Equal(w.Code, http.StatusNotFound)
			assert.Equal(string(try.To1(io.ReadAll(r.Body))), "{}")
		}
	}
}

func TestVerifyRequestBodyBound(t *testing.T) {
	defer assert.PushTester(t)()

	reader := strings.NewReader(strings.Repeat(" ", 1024))
	r := httptest.NewRequest(http.MethodPost, verifyPath, reader)
	r.ContentLength = 1
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	newEvidenceHandler(nil, nil, nil).ServeHTTP(w, r)
	assert.Equal(w.Code, http.StatusRequestEntityTooLarge)
	assert.Equal(reader.Len(), 1024-65)
}
