package peerapi

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/internal/pw"
)

const establishPath = "/peer/pw/establish"

func TestEstablishmentStrictEnvelope(t *testing.T) {
	defer assert.PushTester(t)()
	const valid = `{"version":1,"request":"AQ=="}`
	calls := 0
	h := NewEstablishmentHandler(func(int, []byte) ([]byte, error) {
		calls++
		return nil, errors.New("private request/response diagnostic")
	}, http.NotFoundHandler())
	request := func(method, path, body string, mutate func(*http.Request),
	) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if mutate != nil {
			mutate(r)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, body := range []string{
		"", "null", "[]", "{}", "{", valid + " {}", valid + "x",
		`{"version":1}`, `{"request":"AQ=="}`,
		`{"version":1,"request":"AQ==","extra":null}`,
		`{"version":1,"version":1,"request":"AQ=="}`,
		`{"version":1,"request":"AQ==","request":"AQ=="}`,
		`{"version":1,"request":"AQ==","reque\u0073t":"AQ=="}`,
		`{"Version":1,"request":"AQ=="}`,
		`{"version":1,"Request":"AQ=="}`,
		`{"version":1,"request":"AQ==","REQUEST":"AQ=="}`,
		`{"version":1.0,"request":"AQ=="}`,
		`{"version":1e0,"request":"AQ=="}`,
		`{"version":3,"request":"AQ=="}`,
		`{"version":"1","request":"AQ=="}`,
		`{"version":true,"request":"AQ=="}`,
		`{"version":1,"request":null}`, `{"version":1,"request":[]}`,
		`{"version":1,"request":{}}`, `{"version":1,"request":1}`,
		`{"version":1,"request":""}`, `{"version":1,"request":"??"}`,
		`{"version":1,"request":"AQ"}`, `{"version":1,"request":"AR=="}`,
		`{"version":1,"request":"AQ==\n"}`,
		`{"version":1,"request":"` + base64.StdEncoding.EncodeToString(
			make([]byte, pw.MaxEstablishmentBytes+1)) + `"}`,
		string([]byte{0xff}) + valid,
	} {
		w := request("POST", establishPath, body, nil)
		assert.Equal(w.Code, 400, body)
		assert.Equal(w.Body.String(), "Bad Request\n")
		assert.Equal(w.Header().Get("Cache-Control"), "no-store")
	}
	for _, method := range []string{"GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		w := request(method, establishPath, valid, nil)
		assert.Equal(w.Code, 405)
		assert.Equal(w.Header().Get("Allow"), "POST")
	}
	for _, path := range []string{
		establishPath + "/", "/owner/pw/establish", "/peer//pw/establish",
		"/peer/pw/../pw/establish", "/peer/%70w/establish",
	} {
		assert.Equal(request("POST", path, valid, nil).Code, 404)
	}
	for _, path := range []string{establishPath + "?", establishPath + "?version=1"} {
		assert.Equal(request("POST", path, valid, nil).Code, 400)
	}
	for _, media := range []string{
		"", "text/plain", "application/json, application/json",
		"application/json; charset", "application/json; charset=\"",
		"application/json; charset=utf-8; charset=ascii",
	} {
		w := request("POST", establishPath, valid, func(r *http.Request) {
			r.Header.Set("Content-Type", media)
		})
		assert.Equal(w.Code, 415)
	}
	for _, tc := range []struct {
		mutate func(*http.Request)
		status int
	}{
		{func(r *http.Request) { r.URL.Fragment = "x" }, 400},
		{func(r *http.Request) { r.URL.RawFragment = "x" }, 400},
		{func(r *http.Request) { r.URL.RawPath = establishPath }, 404},
		{func(r *http.Request) { r.URL.Opaque = "//peer" }, 404},
		{func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }, 415},
		{func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, 415},
		{func(r *http.Request) { r.Body = nil }, 400},
	} {
		assert.Equal(
			request("POST", establishPath, valid, tc.mutate).Code,
			tc.status,
		)
	}
	for _, length := range []int64{-1, 1} {
		w := request("POST", establishPath, strings.Repeat(" ", 4096),
			func(r *http.Request) { r.ContentLength = length })
		assert.Equal(w.Code, 413)
	}
	assert.Equal(calls, 0)
	// Credentials confer no exception to the signed-request capability.
	for _, auth := range []string{"", "Bearer owner-secret", "Basic bad"} {
		w := request("POST", establishPath, valid, func(r *http.Request) {
			r.Header.Set("Authorization", auth)
		})
		assert.Equal(w.Code, 409)
		assert.Equal(w.Body.String(), "Conflict\n")
	}
	assert.Equal(calls, 3)
}

func TestEstablishmentBoundsCapabilityResult(t *testing.T) {
	defer assert.PushTester(t)()
	for _, result := range [][]byte{nil, make([]byte, pw.MaxEstablishmentBytes+1)} {
		h := NewEstablishmentHandler(func(int, []byte) ([]byte, error) {
			return result, nil
		}, http.NotFoundHandler())
		r := httptest.NewRequest("POST", establishPath,
			strings.NewReader(`{"version":1,"request":"AQ=="}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assert.Equal(w.Code, 500)
		assert.Equal(w.Body.String(), "Internal Server Error\n")
	}
}

func TestEstablishmentV2Envelope(t *testing.T) {
	defer assert.PushTester(t)()
	calls := 0
	h := NewEstablishmentHandler(func(version int, raw []byte) ([]byte, error) {
		calls++
		assert.Equal(version, 2)
		assert.DeepEqual(raw, []byte{1})
		return []byte{2}, nil
	}, http.NotFoundHandler())
	for _, body := range []string{
		`{"version":2,"version":2,"request":"AQ=="}`,
		`{"version":2,"request":"AQ==","request":"AQ=="}`,
		`{"version":2,"request":"AQ==","acceptance":"AQ=="}`,
		`{"version":2,"request":"AQ==","endpoint":"http://127.0.0.1:1"}`,
		`{"Version":2,"request":"AQ=="}`,
		`{"ver\u0073ion":2,"request":"AQ=="}`,
		`{"version":2,"reque\u0073t":"AQ=="}`,
		`{"version":2.0,"request":"AQ=="}`,
		`{"version":2e0,"request":"AQ=="}`,
		`{"version":"2","request":"AQ=="}`,
	} {
		r := httptest.NewRequest("POST", establishPath, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assert.Equal(w.Code, 400)
	}
	assert.Equal(calls, 0)
	r := httptest.NewRequest("POST", establishPath,
		strings.NewReader(`{"version":2,"request":"AQ=="}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(w.Code, 200)
	assert.Equal(w.Body.String(), `{"version":2,"acceptance":"Ag=="}`)
	assert.Equal(w.Header().Get("Cache-Control"), "no-store")
	assert.Equal(calls, 1)
}
