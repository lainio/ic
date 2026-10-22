package ownerapi

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestOwnerStatusTokenDelegatesOnce(t *testing.T) {
	token := hex.EncodeToString(
		bytes.Repeat([]byte{0xab}, ownerStatusTokenSize),
	)
	for _, authorization := range []string{
		"Bearer " + token,
		"bEaReR    " + token,
		" \tBEARER  " + token + "\t ",
	} {
		t.Run(strings.Fields(authorization)[0], func(t *testing.T) {
			defer assert.PushTester(t)()

			request := httptest.NewRequest(
				http.MethodPost,
				"/unchanged?root=other&child=other",
				strings.NewReader("payload"),
			)
			request.Header.Set("Authorization", authorization)
			request.Header.Set("X-Request-Data", "unchanged")
			headers := request.Header.Clone()
			body := request.Body
			calls := 0
			handler := &authenticatedStatusHandler{
				token: token,
				next: http.HandlerFunc(
					func(w http.ResponseWriter, r *http.Request) {
						calls++
						assert.Equal(r, request)
						assert.Equal(r.Method, http.MethodPost)
						assert.Equal(
							r.URL.String(),
							"/unchanged?root=other&child=other",
						)
						assert.DeepEqual(r.Header, headers)
						assert.Equal(r.Body, body)
						assert.Equal(
							string(try.To1(io.ReadAll(r.Body))),
							"payload",
						)
						w.Header().Set("X-Downstream", "once")
						w.WriteHeader(http.StatusAccepted)
					},
				),
			}

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assert.Equal(calls, 1)
			assert.Equal(response.Code, http.StatusAccepted)
			assert.Equal(response.Header().Get("X-Downstream"), "once")
			assert.Equal(response.Header().Get("WWW-Authenticate"), "")
		})
	}
}

func TestOwnerStatusTokenDenials(t *testing.T) {
	token := hex.EncodeToString(
		bytes.Repeat([]byte{0xab}, ownerStatusTokenSize),
	)
	valid := "Bearer " + token
	for _, tc := range []struct {
		name   string
		values []string
	}{
		{"missing", nil},
		{"empty", []string{""}},
		{"whitespace", []string{" \t "}},
		{"scheme only", []string{"Bearer"}},
		{"empty token", []string{"Bearer   "}},
		{"wrong scheme", []string{"Basic " + token}},
		{"wrong token", []string{"Bearer " + strings.Repeat("cd", ownerStatusTokenSize)}},
		{"short", []string{valid[:len(valid)-1]}},
		{"long", []string{valid + "a"}},
		{"uppercase token", []string{"Bearer " + strings.ToUpper(token)}},
		{"nonhex", []string{"Bearer g" + token[1:]}},
		{"extra word", []string{valid + " extra"}},
		{"combined", []string{valid + ", " + valid}},
		{"comma", []string{valid + ","}},
		{"embedded comma", []string{"Bearer " + token[:31] + "," + token[32:]}},
		{"embedded space", []string{"Bearer " + token[:31] + " " + token[32:]}},
		{"embedded tab", []string{"Bearer " + token[:31] + "\t" + token[32:]}},
		{"tab separator", []string{"Bearer\t" + token}},
		{"mixed separator", []string{"Bearer \t" + token}},
		{"newline", []string{valid + "\n"}},
		{"non HTTP whitespace", []string{"\u00a0" + valid}},
		{"quoted token", []string{`Bearer "` + token + `"`}},
		{"duplicate", []string{valid, valid}},
		{"valid then empty", []string{valid, ""}},
		{"empty then valid", []string{"", valid}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			calls := 0
			handler := &authenticatedStatusHandler{
				token: token,
				next: http.HandlerFunc(
					func(http.ResponseWriter, *http.Request) {
						calls++
					},
				),
			}
			request := httptest.NewRequest(http.MethodGet, "/owner/status", nil)
			for _, value := range tc.values {
				request.Header.Add("Authorization", value)
			}
			body := &ownerStatusUnreadBody{}
			request.Body = io.NopCloser(body)

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assert.Equal(calls, 0)
			assert.Equal(body.reads, 0)
			assert.Equal(response.Code, http.StatusUnauthorized)
			assert.Equal(response.Body.String(), "Unauthorized\n")
			assert.Equal(response.Header().Get("WWW-Authenticate"),
				`Bearer realm="owner-status"`)
			assert.Equal(response.Header().Get("Cache-Control"), "no-store")
			assert.Equal(response.Header().Get("Content-Type"),
				"text/plain; charset=utf-8")
		})
	}
}

func TestOwnerStatusTokenHeaderOnly(t *testing.T) {
	token := hex.EncodeToString(
		bytes.Repeat([]byte{0xab}, ownerStatusTokenSize),
	)
	for _, source := range []string{"query", "cookie", "body", "forwarded"} {
		t.Run(source, func(t *testing.T) {
			defer assert.PushTester(t)()

			request := httptest.NewRequest(http.MethodGet, "/owner/status", nil)
			switch source {
			case "query":
				request.URL.RawQuery = "access_token=" + token
			case "cookie":
				request.AddCookie(
					&http.Cookie{Name: "access_token", Value: token},
				)
			case "body":
				request.Body = io.NopCloser(
					strings.NewReader("access_token=" + token),
				)
				request.Header.Set(
					"Content-Type",
					"application/x-www-form-urlencoded",
				)
			case "forwarded":
				request.Header.Set("X-Forwarded-Authorization", "Bearer "+token)
				request.Header.Set("X-Forwarded-For", "127.0.0.1")
			}
			request.RemoteAddr = "127.0.0.1:1234"
			calls := 0
			handler := &authenticatedStatusHandler{
				token: token,
				next: http.HandlerFunc(
					func(http.ResponseWriter, *http.Request) {
						calls++
					},
				),
			}

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assert.Equal(calls, 0)
			assert.Equal(response.Code, http.StatusUnauthorized)
			assert.Equal(response.Body.String(), "Unauthorized\n")
			if source == "body" {
				assert.Equal(string(try.To1(io.ReadAll(request.Body))),
					"access_token="+token)
			}
		})
	}
}

func TestOwnerStatusTokenConstructorRejectsLengths(t *testing.T) {
	defer assert.PushTester(t)()

	for _, token := range [][]byte{
		nil, {}, {0xab},
		bytes.Repeat([]byte{0xab}, ownerStatusTokenSize-1),
		bytes.Repeat([]byte{0xab}, ownerStatusTokenSize+1),
		bytes.Repeat([]byte{0xab}, 2*ownerStatusTokenSize),
	} {
		handler, err := NewAuthenticatedStatusHandler(nil, nil, nil, token)
		assert.INil(handler)
		assert.Error(err)
		assert.Equal(err.Error(), "invalid owner status token configuration")
	}
}

func TestOwnerStatusTokenConstructorOwnsCredential(t *testing.T) {
	defer assert.PushTester(t)()

	token := bytes.Repeat([]byte{0xab}, ownerStatusTokenSize)
	original := "Bearer " + hex.EncodeToString(token)
	// A nil Vault is safe to borrow during construction and route dispatch.
	handler := try.To1(NewAuthenticatedStatusHandler(nil, nil, nil, token))
	token[0] ^= 1
	modified := "Bearer " + hex.EncodeToString(token)
	clear(token)
	cleared := "Bearer " + hex.EncodeToString(token)

	for _, tc := range []struct {
		authorization string
		status        int
	}{
		{original, http.StatusNotFound},
		{modified, http.StatusUnauthorized},
		{cleared, http.StatusUnauthorized},
	} {
		request := httptest.NewRequest(http.MethodGet, "/other", nil)
		request.Header.Set("Authorization", tc.authorization)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		assert.Equal(response.Code, tc.status)
		assert.Equal(response.Body.String(), http.StatusText(tc.status)+"\n")
	}
}

func TestOwnerStatusTokenBeforeRouting(t *testing.T) {
	defer assert.PushTester(t)()

	token := bytes.Repeat([]byte{0xab}, ownerStatusTokenSize)
	handler := try.To1(NewAuthenticatedStatusHandler(nil, nil, nil, token))
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, "/other", http.StatusNotFound},
		{http.MethodGet, "/owner/status/", http.StatusNotFound},
		{http.MethodPost, "/owner/status", http.StatusMethodNotAllowed},
		{http.MethodHead, "/owner/status", http.StatusMethodNotAllowed},
		{http.MethodOptions, "/owner/status", http.StatusMethodNotAllowed},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			defer assert.PushTester(t)()

			for _, authorization := range []string{
				"", "Bearer wrong", "Bearer " + hex.EncodeToString(token),
			} {
				request := httptest.NewRequest(tc.method, tc.path, nil)
				request.Header.Set("Authorization", authorization)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				status, allow := http.StatusUnauthorized, ""
				if authorization == "Bearer "+hex.EncodeToString(token) {
					status = tc.status
					if status == http.StatusMethodNotAllowed {
						allow = http.MethodGet
					}
				}
				assert.Equal(response.Code, status)
				assert.Equal(
					response.Body.String(),
					http.StatusText(status)+"\n",
				)
				assert.Equal(response.Header().Get("Allow"), allow)
				assert.Equal(response.Header().Get("Cache-Control"), "no-store")
			}
		})
	}
}

func TestOwnerStatusTokenDenialWriteFailure(t *testing.T) {
	defer assert.PushTester(t)()

	token := bytes.Repeat([]byte{0xab}, ownerStatusTokenSize)
	handler := try.To1(NewAuthenticatedStatusHandler(nil, nil, nil, token))
	failed := &ownerStatusFailedWriter{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeHTTP(failed, httptest.NewRequest(
		http.MethodGet, "/owner/status", nil,
	))
	assert.Equal(failed.Code, http.StatusUnauthorized)
	assert.Equal(failed.headerCalls, 1)
	assert.Equal(failed.writeCalls, 1)
	assert.Equal(failed.Header().Get("WWW-Authenticate"),
		`Bearer realm="owner-status"`)
	assert.Equal(failed.Header().Get("Cache-Control"), "no-store")
}

type ownerStatusUnreadBody struct {
	reads int
}

func (r *ownerStatusUnreadBody) Read([]byte) (int, error) {
	r.reads++
	return 0, errors.New("authorization must not read the request body")
}

type ownerStatusFailedWriter struct {
	*httptest.ResponseRecorder
	headerCalls int
	writeCalls  int
}

func (w *ownerStatusFailedWriter) WriteHeader(status int) {
	w.headerCalls++
	w.ResponseRecorder.WriteHeader(status)
}

func (w *ownerStatusFailedWriter) Write([]byte) (int, error) {
	w.writeCalls++
	return 0, errors.New("response write failed")
}
