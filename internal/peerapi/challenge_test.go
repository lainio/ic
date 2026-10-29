package peerapi

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
)

const challengePath = "/peer/pw/challenge"

func challengeJSON(t *testing.T, requester key.Public, ad []byte) string {
	t.Helper()
	defer assert.PushTester(t)()
	return string(try.To1(json.Marshal(map[string]any{
		"version": 1, "requester_public_key_hex": hex.EncodeToString(requester),
		"ad": ad,
	})))
}

func challengeRequest(body string) *http.Request {
	r := httptest.NewRequest(
		http.MethodPost,
		challengePath,
		strings.NewReader(body),
	)
	r.Header.Set("Content-Type", "application/json")
	return r
}

func boundaryChallengeHandler(public key.Public) *challengeHandler {
	return NewChallengeHandler(nil, public, public, proofEndpoint,
		NewHandler(nil, public, public)).(*challengeHandler)
}

func assertChallengeError(
	t *testing.T,
	w *httptest.ResponseRecorder,
	status int,
) {
	t.Helper()
	defer assert.PushTester(t)()
	assert.Equal(w.Code, status)
	assert.Equal(w.Body.String(), http.StatusText(status)+"\n")
	assert.Equal(w.Header().Get("Cache-Control"), "no-store")
	for _, name := range []string{
		"WWW-Authenticate", "Authorization", "Set-Cookie", "Access-Control-Allow-Origin",
	} {
		assert.Empty(w.Header().Get(name))
	}
}

func TestChallengeRoutingBeforeVaultOrLedger(t *testing.T) {
	defer assert.PushTester(t)()
	public, ad, _ := proofInput(t)
	requester := key.Public(try.To1(key.New().CBORPublicKey()))
	body := challengeJSON(t, requester, ad)
	h := boundaryChallengeHandler(public)
	h.challenges.random = nil // Any attempt to generate randomness would panic.
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"GET", challengePath, 405}, {"HEAD", challengePath, 405},
		{"PUT", challengePath, 405}, {"DELETE", challengePath, 405},
		{"OPTIONS", challengePath, 405}, {"PATCH", challengePath, 405},
		{"POST", challengePath + "/", 404}, {"POST", "/peer//pw/challenge", 404},
		{"POST", "/peer/pw/../pw/challenge", 404},
		{"POST", "/peer/pw/%63hallenge", 404},
		{"POST", "/peer%2fpw/challenge", 404},
		{"POST", challengePath + ";x=1", 404},
		{"POST", challengePath + "?", 400},
		{"POST", challengePath + "?now=0", 400},
		{"POST", "/peer/pw/consume", 404}, {"POST", "/peer/pw/accept", 404},
		{"POST", "/owner/ads/publish", 404},
		{"POST", "/owner/ads/verify", 404}, {"GET", "/owner/status", 404},
	} {
		r := challengeRequest(body)
		r.Method = tc.method
		r.URL = httptest.NewRequest(tc.method, tc.path, nil).URL
		r.Header.Set("Authorization", "Bearer ignored-owner-credential")
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
		r := challengeRequest(body)
		want := 400
		switch scenario {
		case "fragment":
			r.URL.Fragment = "private"
		case "raw fragment":
			r.URL.RawFragment = "%70rivate"
		case "opaque":
			r.URL.Opaque, want = challengePath, 404
		case "raw path":
			r.URL.RawPath, want = challengePath, 404
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
	assert.MEmpty(h.challenges.entries)
}

func TestChallengeStrictEnvelopeBeforeVaultOrLedger(t *testing.T) {
	defer assert.PushTester(t)()
	public, ad, _ := proofInput(t)
	requester := key.Public(try.To1(key.New().CBORPublicKey()))
	good := challengeJSON(t, requester, ad)
	h := boundaryChallengeHandler(public)
	h.challenges.random = nil
	cases := []string{
		"",
		"null",
		"[]",
		"{}",
		"{",
		good + "{}",
		good + "x",
		"\xff" + good,
	}
	for _, value := range []string{`1.0`, `1e0`, `"1"`, `null`, `true`, `0`, `2`, `-1`, `[]`, `{}`} {
		cases = append(
			cases,
			strings.Replace(good, `"version":1`, `"version":`+value, 1),
		)
	}
	for _, field := range []string{"version", "ad", "requester_public_key_hex"} {
		var fields map[string]json.RawMessage
		try.To(json.Unmarshal([]byte(good), &fields))
		cases = append(
			cases,
			strings.TrimSuffix(
				good,
				"}",
			)+`,"`+field+`":`+string(
				fields[field],
			)+`}`,
		)
		cases = append(
			cases,
			strings.Replace(
				good,
				`"`+field+`":`,
				`"`+strings.ToUpper(field)+`":`,
				1,
			),
		)
		delete(fields, field)
		cases = append(cases, string(try.To1(json.Marshal(fields))))
	}
	for _, field := range []string{"nonce", "challenge", "proof", "root", "peer_url", "signer", "bearer", "clock", "purpose", "callback"} {
		cases = append(
			cases,
			strings.TrimSuffix(good, "}")+`,"`+field+`":"private"}`,
		)
	}
	cases = append(cases, strings.TrimSuffix(good, "}")+`,"\u0076ersion":1}`)
	for _, field := range []string{"ad", "requester_public_key_hex"} {
		for _, value := range []string{`null`, `0`, `[]`, `{}`, `true`, `""`, `"AA"`, `"AA==\n"`, `"AB=="`, `"__=="`, `"private"`, `"\ud800"`} {
			var fields map[string]json.RawMessage
			try.To(json.Unmarshal([]byte(good), &fields))
			fields[field] = json.RawMessage(value)
			cases = append(cases, string(try.To1(json.Marshal(fields))))
		}
	}
	hexKey := hex.EncodeToString(requester)
	for _, bad := range []string{hexKey[1:], strings.ToUpper(hexKey), "0x" + hexKey, hexKey + " ", strings.Repeat("aa", 129)} {
		cases = append(cases, strings.Replace(good, hexKey, bad, 1))
	}
	encodedAd := base64.StdEncoding.EncodeToString(ad)
	for _, bad := range []string{encodedAd + `\n`, encodedAd[:4] + `\r\n` + encodedAd[4:], encodedAd + " "} {
		cases = append(cases, strings.Replace(good, encodedAd, bad, 1))
	}
	for i, body := range cases {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, challengeRequest(body))
		assert.Equal(w.Code, 400, i)
		assertChallengeError(t, w, 400)
	}
	assert.MEmpty(h.challenges.entries)
}

func TestChallengeKeyAndAdAuthenticationBeforeVault(t *testing.T) {
	defer assert.PushTester(t)()
	public, ad, _ := proofInput(t)
	requester := key.Public(try.To1(key.New().CBORPublicKey()))
	h := boundaryChallengeHandler(public)
	h.challenges.random = nil
	cases := []string{challengeJSON(t, public, ad)}
	for _, bad := range [][]byte{{0xff}, {0x80}, append([]byte{0x98, 2}, ad[1:]...), append(bytes.Clone(ad), 0), make([]byte, 1025)} {
		cases = append(cases, challengeJSON(t, requester, bad))
	}
	for _, field := range []string{"Root", "node", "device", "slot", "epoch", "version", "endpoint", "signature", "forged", "token"} {
		var current ads.Current
		try.To(wire.UnmarshalCanonical(&current, ad))
		switch field {
		case "Root":
			current.Payload.Root = requester
		case "node":
			current.Payload.Node = requester
		case "device":
			current.Payload.Device = requester
		case "slot":
			current.Payload.Slot = 2
		case "epoch":
			current.Payload.Epoch = 1
		case "version":
			current.Payload.Version = 2
		case "endpoint":
			current.Payload.PeerIntroductionURL = "http://private.invalid/secret"
		case "signature":
			current.Signature = make([]byte, 73)
		case "forged":
			digest := key.HashTagged(
				ads.SignaturePurpose,
				try.To1(wire.Marshal(current.Payload)),
			)
			current.Signature = try.To1(key.New().Sign(digest[:]))
		case "token":
			current.Payload.Token[0] ^= 1
		}
		cases = append(
			cases,
			challengeJSON(t, requester, try.To1(wire.Marshal(current))),
		)
	}
	for _, bad := range []key.Public{nil, {0xff}, {0x80}, append(bytes.Clone(requester), 0),
		append([]byte{0xb8, 5}, requester[1:]...), bytes.Repeat([]byte{0}, 129)} {
		cases = append(cases, challengeJSON(t, bad, ad))
	}
	for _, field := range []string{"algorithm", "curve", "type", "off curve", "short coordinate", "long coordinate"} {
		var decoded webauthncose.EC2PublicKeyData
		try.To(wire.UnmarshalCanonical(&decoded, requester))
		switch field {
		case "algorithm":
			decoded.Algorithm = -8
		case "curve":
			decoded.Curve = 2
		case "type":
			decoded.KeyType = 1
		case "off curve":
			decoded.XCoord, decoded.YCoord = make([]byte, 32), make([]byte, 32)
		case "short coordinate":
			decoded.XCoord = nil
		case "long coordinate":
			decoded.YCoord = make([]byte, 33)
		}
		cases = append(
			cases,
			challengeJSON(t, try.To1(wire.Marshal(decoded)), ad),
		)
	}
	var trace bytes.Buffer
	previousError, previousReturn := err2.ErrorTracer(), err2.ErrRetTracer()
	err2.SetErrorTracer(&trace)
	err2.SetErrRetTracer(&trace)
	defer func() { err2.SetErrorTracer(previousError); err2.SetErrRetTracer(previousReturn) }()
	for i, body := range cases {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, challengeRequest(body))
		assert.Equal(w.Code, 400, i)
		assertChallengeError(t, w, 400)
	}
	assert.ThatNot(strings.Contains(trace.String(), "private"))
	assert.MEmpty(h.challenges.entries)
}

func TestChallengeActualBodyBoundAndDisabledHandler(t *testing.T) {
	defer assert.PushTester(t)()
	public, ad, _ := proofInput(t)
	requester := key.Public(try.To1(key.New().CBORPublicKey()))
	good := challengeJSON(t, requester, ad)
	h := boundaryChallengeHandler(public)
	h.challenges.random = nil
	for _, size := range []int{2048, 2049} {
		for _, length := range []int64{-1, 0, 1, int64(size), 1 << 30} {
			r := challengeRequest(good + strings.Repeat(" ", size-len(good)))
			r.ContentLength = length
			if length == -1 {
				r.TransferEncoding = []string{"chunked"}
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := 413
			if size == 2048 {
				want = 500 // Valid input reaches the deliberately absent Vault.
			}
			assertChallengeError(t, w, want)
		}
	}
	r := challengeRequest(good)
	r.Body = nil
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assertChallengeError(t, w, 400)
	for _, old := range []http.Handler{
		NewHandler(nil, public, public),
		NewAdHandler(nil, public, public, proofEndpoint),
		NewProofHandler(nil, public, public, proofEndpoint, nil),
		NewChallengeHandler(nil, public, public, "", NewHandler(nil, public, public)),
	} {
		w := httptest.NewRecorder()
		old.ServeHTTP(w, challengeRequest(good))
		assertChallengeError(t, w, 404)
	}
	assert.MEmpty(h.challenges.entries)
}
