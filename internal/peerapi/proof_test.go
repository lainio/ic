package peerapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
)

const proofPath = "/peer/ad/proof"
const proofEndpoint = "http://127.0.0.1:1234/peer/introduction"

func proofInput(t *testing.T) (key.Public, []byte, []byte) {
	t.Helper()
	defer assert.PushTester(t)()
	signer := key.New()
	public := key.Public(try.To1(signer.CBORPublicKey()))
	payload := ads.Payload{Version: 1, Root: public, Node: public, Device: public,
		Slot: 1, Token: make([]byte, 32), ExpiresUnixNano: time.Now().Add(ads.TTL).UnixNano(),
		PeerIntroductionURL: proofEndpoint}
	digest := key.HashTagged(ads.SignaturePurpose, try.To1(wire.Marshal(payload)))
	ad := try.To1(wire.Marshal(ads.Current{Payload: payload, Signature: try.To1(signer.Sign(digest[:]))}))
	return public, ad, make([]byte, 32)
}

func proofJSON(t *testing.T, ad, nonce []byte) string {
	t.Helper()
	defer assert.PushTester(t)()
	return string(try.To1(json.Marshal(map[string]any{"version": 1, "ad": ad, "challenge": nonce})))
}

func proofRequest(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, proofPath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestProofHTTPBoundaryBeforeCapabilityOrVault(t *testing.T) {
	defer assert.PushTester(t)()
	public, ad, nonce := proofInput(t)
	body := proofJSON(t, ad, nonce)
	calls := 0
	h := NewProofHandler(nil, public, public, proofEndpoint, func([]byte, []byte) (key.Signature, error) {
		calls++
		return nil, errors.New("must not enter")
	})
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"GET", proofPath, 405}, {"HEAD", proofPath, 405}, {"PUT", proofPath, 405},
		{"DELETE", proofPath, 405}, {"OPTIONS", proofPath, 405}, {"PATCH", proofPath, 405},
		{"POST", proofPath + "/", 404}, {"POST", "/peer//ad/proof", 404},
		{"POST", "/peer/ad/../ad/proof", 404}, {"POST", "/peer/ad/%70roof", 404},
		{"POST", "/peer%2fad/proof", 404}, {"POST", proofPath + ";x=1", 404},
		{"POST", proofPath + "?", 400}, {"POST", proofPath + "?ad=secret", 400},
		{"POST", "/peer/ad", 405}, {"POST", "/peer/introduction", 405},
		{"POST", "/owner/ads/publish", 404}, {"POST", "/owner/device/bootstrap", 404},
		{"GET", "/owner/status", 404}, {"GET", "/owner/introduction", 404},
		{"POST", "/owner/introduction/check", 404}, {"POST", "/owner/introductions", 404},
		{"POST", "/owner/introductions/verify", 404}, {"POST", "/owner/ads/fetch", 404},
	} {
		for _, auth := range []string{"", "Bearer private-owner-header"} {
			r := proofRequest(body)
			r.Method = tc.method
			r.URL = httptest.NewRequest(tc.method, tc.path, nil).URL
			r.Header.Set("Authorization", auth)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			assert.Equal(w.Code, tc.status, tc.path)
			assert.Equal(w.Body.String(), http.StatusText(tc.status)+"\n")
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
			assert.Equal(string(try.To1(io.ReadAll(r.Body))), body)
			if tc.status == 405 && tc.path == proofPath {
				assert.Equal(w.Header().Get("Allow"), "POST")
			}
		}
	}
	for _, scenario := range []string{"fragment", "raw fragment", "opaque", "raw path", "missing media", "wrong media", "combined media", "duplicate media"} {
		r := proofRequest(body)
		want := 400
		switch scenario {
		case "fragment":
			r.URL.Fragment = "private"
		case "raw fragment":
			r.URL.RawFragment = "%70rivate"
		case "opaque":
			r.URL.Opaque, want = proofPath, 404
		case "raw path":
			r.URL.RawPath, want = proofPath, 404
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
		assert.Equal(w.Code, want, scenario)
		assert.Equal(string(try.To1(io.ReadAll(r.Body))), body)
	}
	assert.Equal(calls, 0)
}

func TestProofStrictEnvelopeAndShapeAdmission(t *testing.T) {
	defer assert.PushTester(t)()
	public, ad, nonce := proofInput(t)
	good := proofJSON(t, ad, nonce)
	calls := 0
	h := NewProofHandler(nil, public, public, proofEndpoint, func([]byte, []byte) (key.Signature, error) {
		calls++
		return nil, errors.New("must not enter")
	})
	cases := []string{"", "null", "[]", "{}", "{", good + "{}", good + "x", "\xff" + good,
		strings.Replace(good, `"version":1`, `"version":1.0`, 1),
		strings.Replace(good, `"version":1`, `"version":1e0`, 1),
		strings.Replace(good, `"version":1`, `"version":"1"`, 1),
		strings.Replace(good, `"version":1`, `"version":null`, 1),
		strings.Replace(good, `"version":1`, `"version":true`, 1),
		strings.Replace(good, `"version":1`, `"version":2`, 1),
		strings.Replace(good, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(good, `"version":1`, `"version":1,"\u0076ersion":1`, 1),
		strings.Replace(good, `"version":1`, `"algorithm":"private"`, 1),
		strings.Replace(good, `"version":1`, `"version":1,"message":"private"`, 1),
	}
	for _, field := range []string{"ad", "challenge", "version"} {
		var fields map[string]json.RawMessage
		try.To(json.Unmarshal([]byte(good), &fields))
		delete(fields, field)
		cases = append(cases, string(try.To1(json.Marshal(fields))))
	}
	for _, field := range []string{"ad", "challenge"} {
		for _, value := range []string{`null`, `0`, `[]`, `{}`, `true`, `""`, `"AA"`, `"AA==\n"`, `"AB=="`, `"__=="`, `"private value"`, `"\ud800"`} {
			var fields map[string]json.RawMessage
			try.To(json.Unmarshal([]byte(good), &fields))
			fields[field] = json.RawMessage(value)
			cases = append(cases, string(try.To1(json.Marshal(fields))))
		}
		cases = append(cases, strings.TrimSuffix(good, "}")+`,"`+field+`":"AA=="}`)
	}
	for _, size := range []int{0, 1, 31, 33, 1024} {
		cases = append(cases, proofJSON(t, ad, make([]byte, size)))
	}
	encodedNonce := base64.StdEncoding.EncodeToString(nonce)
	for _, bad := range []string{encodedNonce[:len(encodedNonce)-1], encodedNonce[:len(encodedNonce)-2] + "B=",
		encodedNonce + `\n`, encodedNonce[:4] + `\r\n` + encodedNonce[4:], encodedNonce + " "} {
		cases = append(cases, strings.Replace(good, encodedNonce, bad, 1))
	}
	for _, bad := range [][]byte{{0xff}, {0x80}, append([]byte{0x98, 2}, ad[1:]...), append(bytes.Clone(ad), 0), make([]byte, 1025)} {
		cases = append(cases, proofJSON(t, bad, nonce))
	}
	other := try.To1(key.New().CBORPublicKey())
	for _, field := range []string{"Root", "node", "device", "slot", "epoch", "version", "endpoint", "signature"} {
		var current ads.Current
		try.To(wire.UnmarshalCanonical(&current, ad))
		switch field {
		case "Root":
			current.Payload.Root = other
		case "node":
			current.Payload.Node = other
		case "device":
			current.Payload.Device = other
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
		}
		cases = append(cases, proofJSON(t, try.To1(wire.Marshal(current)), nonce))
	}
	var trace bytes.Buffer
	previousError, previousReturn := err2.ErrorTracer(), err2.ErrRetTracer()
	err2.SetErrorTracer(&trace)
	err2.SetErrRetTracer(&trace)
	defer func() { err2.SetErrorTracer(previousError); err2.SetErrRetTracer(previousReturn) }()
	for i, body := range cases {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, proofRequest(body))
		assert.Equal(w.Code, 400, i)
		assert.Equal(w.Body.String(), "Bad Request\n")
	}
	assert.ThatNot(strings.Contains(trace.String(), "private"))
	assert.Equal(calls, 0)
}

func TestProofBodyBoundAndDisabledConstructors(t *testing.T) {
	defer assert.PushTester(t)()
	public, ad, nonce := proofInput(t)
	good := proofJSON(t, ad, nonce)
	calls := 0
	prove := func(got, challenge []byte) (key.Signature, error) {
		calls++
		assert.DeepEqual(got, ad)
		assert.DeepEqual(challenge, nonce)
		return key.Signature{1}, nil
	}
	h := NewProofHandler(nil, public, public, proofEndpoint, prove)
	for _, scenario := range []string{"declared", "chunked", "understated", "zero", "overstated"} {
		reader := strings.NewReader(good + strings.Repeat(" ", 4096))
		r := proofRequest("")
		r.Body = io.NopCloser(reader)
		r.ContentLength = int64(reader.Len())
		switch scenario {
		case "chunked":
			r.ContentLength, r.TransferEncoding = -1, []string{"chunked"}
		case "understated":
			r.ContentLength = 1
		case "zero":
			r.ContentLength = 0
		case "overstated":
			r.ContentLength = 1 << 30
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assert.Equal(w.Code, 413)
		assert.Equal(reader.Len(), len(good)+4096-2049)
	}
	assert.Equal(calls, 0)
	for _, old := range []http.Handler{NewHandler(nil, public, public), NewAdHandler(nil, public, public, proofEndpoint),
		NewProofHandler(nil, public, public, proofEndpoint, nil), NewProofHandler(nil, public, public, "", prove)} {
		w := httptest.NewRecorder()
		old.ServeHTTP(w, proofRequest(good))
		assert.Equal(w.Code, 404)
	}
	// Exactly 2 KiB is accepted, even without a declared length.
	r := proofRequest(good + strings.Repeat(" ", 2048-len(good)))
	r.ContentLength, r.TransferEncoding = -1, []string{"chunked"}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(w.Code, 200)
	assert.Equal(w.Body.String(), `{"version":1,"proof":"`+base64.StdEncoding.EncodeToString([]byte{1})+`"}`)
	assert.Equal(calls, 1)
}
