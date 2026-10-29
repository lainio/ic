package peerapi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
)

const acceptancePath = "/peer/pw/accept"

func acceptanceJSON(t *testing.T, requester key.Public,
	ad, nonce []byte, proof key.Signature,
) string {
	t.Helper()
	defer assert.PushTester(t)()
	return string(try.To1(json.Marshal(map[string]any{
		"version": 1, "requester_public_key_hex": hex.EncodeToString(requester),
		"ad": ad, "challenge": nonce, "requester_proof": proof,
	})))
}

func acceptanceHTTPRequest(body string) *http.Request {
	r := httptest.NewRequest("POST", acceptancePath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// A real outstanding nonce must survive every refusal before authentication.
// The absent Vault and panic capability catch premature reads/signing too.
func acceptanceBoundary(t *testing.T) (*challengeHandler, string) {
	t.Helper()
	defer assert.PushTester(t)()
	local, ad, _ := proofInput(t)
	requester := key.Public(try.To1(key.New().CBORPublicKey()))
	h := NewAcceptanceHandler(nil, local, local, proofEndpoint,
		func(key.Public, []byte, []byte) (key.Signature, error) {
			panic("unadmitted request reached signer capability")
		}, NewHandler(nil, local, local)).(*challengeHandler)
	nonce, _, status := h.challenges.issue(requester, ad)
	assert.Equal(status, 0)
	t.Cleanup(func() {
		assert.Equal(len(h.challenges.entries), 1)
		assert.That(h.consumeChallenge(requester, ad, nonce))
	})
	return h, acceptanceJSON(t, requester, ad, nonce, key.Signature{1})
}

func TestAcceptanceRoutingAndHeaders(t *testing.T) {
	defer assert.PushTester(t)()
	h, body := acceptanceBoundary(t)
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"GET", acceptancePath, 405}, {"HEAD", acceptancePath, 405},
		{"PUT", acceptancePath, 405}, {"DELETE", acceptancePath, 405},
		{"OPTIONS", acceptancePath, 405}, {"PATCH", acceptancePath, 405},
		{"POST", acceptancePath + "/", 404},
		{"POST", "/peer//pw/accept", 404},
		{"POST", "/peer/pw/../pw/accept", 404},
		{"POST", "/peer/pw/%61ccept", 404},
		{"POST", "/peer%2fpw/accept", 404},
		{"POST", acceptancePath + ";x=1", 404},
		{"POST", acceptancePath + "?", 400},
		{"POST", acceptancePath + "?root=secret", 400},
		{"POST", "/peer/pw/consume", 404},
		{"POST", "/owner/ads/publish", 404},
	} {
		r := acceptanceHTTPRequest(body)
		r.Method = tc.method
		r.URL = httptest.NewRequest(tc.method, tc.path, nil).URL
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assertChallengeError(t, w, tc.status)
		assert.Equal(string(try.To1(io.ReadAll(r.Body))), body)
		if tc.status == 405 {
			assert.Equal(w.Header().Get("Allow"), "POST")
		}
	}
	for _, scenario := range []string{
		"fragment", "raw fragment", "opaque", "raw path", "missing media",
		"wrong media", "combined media", "duplicate media",
	} {
		r := acceptanceHTTPRequest(body)
		want := 400
		switch scenario {
		case "fragment":
			r.URL.Fragment = "private"
		case "raw fragment":
			r.URL.RawFragment = "%70rivate"
		case "opaque":
			r.URL.Opaque, want = acceptancePath, 404
		case "raw path":
			r.URL.RawPath, want = acceptancePath, 404
		case "missing media":
			r.Header.Del("Content-Type")
			want = 415
		case "wrong media":
			r.Header.Set("Content-Type", "text/plain")
			want = 415
		case "combined media":
			r.Header.Set("Content-Type", "application/json, application/json")
			want = 415
		case "duplicate media":
			r.Header.Add("Content-Type", "application/json")
			want = 415
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assertChallengeError(t, w, want)
		assert.Equal(string(try.To1(io.ReadAll(r.Body))), body)
	}
}

func TestAcceptanceStrictEnvelope(t *testing.T) {
	defer assert.PushTester(t)()
	h, good := acceptanceBoundary(t)
	cases := []string{"", "null", "[]", "{}", "{", good + "{}",
		good + "x", "\xff" + good, good + "\xff"}
	for _, value := range []string{
		`1.0`, `1e0`, `"1"`, `null`, `true`, `0`, `2`, `-1`, `[]`, `{}`,
	} {
		cases = append(cases,
			strings.Replace(good, `"version":1`, `"version":`+value, 1))
	}
	var fields map[string]json.RawMessage
	try.To(json.Unmarshal([]byte(good), &fields))
	for field, value := range fields {
		cases = append(cases,
			strings.TrimSuffix(good, "}")+`,"`+field+`":`+string(value)+`}`,
			strings.Replace(good, `"`+field+`":`,
				`"`+strings.ToUpper(field)+`":`, 1))
		delete(fields, field)
		cases = append(cases, string(try.To1(json.Marshal(fields))))
		fields[field] = value
	}
	for _, field := range []string{
		"nonce", "proof", "root", "peer_url", "signer", "clock", "purpose",
		"acceptor", "headers", "url", "callback",
	} {
		cases = append(cases,
			strings.TrimSuffix(good, "}")+`,"`+field+`":"private"}`)
	}
	cases = append(cases,
		strings.TrimSuffix(good, "}")+`,"\u0076ersion":1}`)
	for _, field := range []string{
		"ad", "requester_public_key_hex", "challenge", "requester_proof",
	} {
		original := fields[field]
		for _, value := range []string{
			`null`, `0`, `[]`, `{}`, `true`, `""`, `"AA"`, `"AA==\n"`,
			`"AB=="`, `"__=="`, `"private"`, `"\ud800"`, `"\udfff"`,
		} {
			fields[field] = json.RawMessage(value)
			cases = append(cases, string(try.To1(json.Marshal(fields))))
		}
		fields[field] = original
	}
	request, ok := decodeAcceptanceRequest([]byte(good))
	assert.That(ok)
	for _, bad := range []key.Public{
		h.local, nil, {0xff}, {0x80}, request.requester[:5],
		append(bytes.Clone(request.requester), 0),
		append([]byte{0xb8, 5}, request.requester[1:]...),
		make([]byte, 129),
	} {
		cases = append(cases, acceptanceJSON(t, bad,
			request.ad, request.nonce, request.proof))
	}
	for _, bad := range []string{
		strings.ToUpper(hex.EncodeToString(request.requester)),
		"0x" + hex.EncodeToString(request.requester),
	} {
		cases = append(cases, strings.Replace(good,
			hex.EncodeToString(request.requester), bad, 1))
	}
	for _, bad := range [][]byte{
		{0xff}, {0x80}, append([]byte{0x98, 2}, request.ad[1:]...),
		append(bytes.Clone(request.ad), 0), make([]byte, 1025),
	} {
		cases = append(cases, acceptanceJSON(t, request.requester,
			bad, request.nonce, request.proof))
	}
	for _, size := range []int{0, 31, 33} {
		cases = append(cases, acceptanceJSON(t, request.requester,
			request.ad, make([]byte, size), request.proof))
	}
	for _, size := range []int{0, 73} {
		cases = append(cases, acceptanceJSON(t, request.requester,
			request.ad, request.nonce, make([]byte, size)))
	}
	for i, body := range cases {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, acceptanceHTTPRequest(body))
		assert.Equal(w.Code, 400, i)
		assertChallengeError(t, w, 400)
	}
}

func TestAcceptanceActualByteLimitAndDisabledCapability(t *testing.T) {
	defer assert.PushTester(t)()
	h, good := acceptanceBoundary(t)
	for _, size := range []int{3072, 3073} {
		for _, length := range []int64{-1, 0, 1, int64(size), 1 << 30} {
			r := acceptanceHTTPRequest(good + strings.Repeat(" ", size-len(good)))
			r.ContentLength = length
			if length == -1 {
				r.TransferEncoding = []string{"chunked"}
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := 413
			if size == 3072 {
				want = 400 // Envelope admitted, deliberately invalid signature.
			}
			assertChallengeError(t, w, want)
		}
	}
	r := acceptanceHTTPRequest(good)
	r.Body = nil
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assertChallengeError(t, w, 400)
	for _, handler := range []http.Handler{
		NewChallengeHandler(nil, h.root, h.local, h.endpoint, h.next),
		NewAcceptanceHandler(nil, h.root, h.local, h.endpoint, nil, h.next),
		NewAcceptanceHandler(nil, h.root, h.local, "", h.accept, h.next),
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, acceptanceHTTPRequest(good))
		assertChallengeError(t, w, 404)
	}
}
