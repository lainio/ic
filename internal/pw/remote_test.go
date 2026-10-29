package pw_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
)

type observedExchange struct {
	path, host, remote string
	header             http.Header
	body, reply        []byte
	status             int
}

func TestRequestRemoteAcceptanceTwoRestoredNodes(t *testing.T) {
	defer assert.PushTester(t)()
	var mu sync.Mutex
	var requests []observedExchange
	f := newExchange(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read", 400)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			reply := httptest.NewRecorder()
			next.ServeHTTP(reply, r)
			mu.Lock()
			requests = append(requests, observedExchange{r.URL.Path, r.Host,
				r.RemoteAddr, r.Header.Clone(), body, bytes.Clone(reply.Body.Bytes()),
				reply.Code})
			mu.Unlock()
			copyReply(w, reply)
		})
	})
	mu.Lock()
	requests = nil // Historical verification happened before this operation.
	mu.Unlock()
	before := f.snapshot(t)
	try.To(f.request(t.Context()))
	assert.DeepEqual(f.snapshot(t), before)
	mu.Lock()
	observed := append([]observedExchange(nil), requests...)
	mu.Unlock()
	assert.Equal(len(observed), 2)
	assert.Equal(observed[0].path, challengePath)
	assert.Equal(observed[1].path, acceptPath)
	assert.NotEqual(observed[0].remote, observed[1].remote)
	var nonce []byte
	for i, request := range observed {
		assert.Equal(request.status, 200)
		assert.Equal(request.host, f.server.Listener.Addr().String())
		assert.Equal(request.header.Get("Content-Type"), "application/json")
		for _, field := range []string{"Authorization", "Cookie",
			"Proxy-Authorization", "Accept-Encoding"} {
			assert.Equal(request.header.Get(field), "")
		}
		var fields map[string]json.RawMessage
		try.To(json.Unmarshal(request.body, &fields))
		assert.Equal(len(fields), 3+2*i)
		assert.That(len(request.body) <= 2048+1024*i)
		var body struct {
			Version       int
			Requester     string `json:"requester_public_key_hex"`
			Ad, Challenge []byte
			Proof         key.Signature `json:"requester_proof"`
		}
		try.To(json.Unmarshal(request.body, &body))
		assert.Equal(body.Version, 1)
		assert.Equal(body.Requester, hex.EncodeToString(f.a.public))
		assert.DeepEqual(body.Ad, f.ad)
		if i == 0 {
			var response struct{ Challenge []byte }
			try.To(json.Unmarshal(request.reply, &response))
			nonce = response.Challenge
			assert.Equal(len(nonce), 32)
			continue
		}
		assert.DeepEqual(body.Challenge, nonce)
		try.To(pw.VerifyLocalAcceptanceProof(f.root, f.a.public, f.b.public,
			nonce, body.Proof))
		var response struct {
			Proof key.Signature `json:"acceptor_proof"`
		}
		try.To(json.Unmarshal(request.reply, &response))
		try.To(pw.VerifyLocalAcceptanceProof(f.root, f.b.public, f.a.public,
			nonce, response.Proof))
		assert.Error(pw.VerifyLocalAcceptanceProof(f.root, f.a.public,
			f.b.public, nonce, response.Proof))
		assert.Error(pw.VerifyLocalAcceptanceProof(f.root, f.b.public,
			f.a.public, nonce, body.Proof))
		assertAcceptanceSignedOnce(t, f, nonce)
	}
}

func assertAcceptanceSignedOnce(
	t *testing.T,
	f *exchangeFixture,
	nonce []byte,
) {
	t.Helper()
	defer assert.PushTester(t)()
	for _, pair := range [][2]*exchangeNode{{f.a, f.b}, {f.b, f.a}} {
		payload := try.To1(wire.Marshal([]any{1, f.root,
			pair[0].public, pair[1].public, nonce}))
		digest := key.HashTagged("pw-local-acceptance/v1", payload)
		count := 0
		for _, message := range pair[0].signer.signed() {
			if bytes.Equal(message, digest[:]) {
				count++
			}
		}
		assert.Equal(count, 1)
	}
}

func copyReply(w http.ResponseWriter, reply *httptest.ResponseRecorder) {
	for name, values := range reply.Header() {
		w.Header()[name] = values
	}
	w.WriteHeader(reply.Code)
	_, _ = w.Write(reply.Body.Bytes())
}

type inputMutatingSigner struct {
	key.Handle
	once   sync.Once
	inputs [][]byte
}

func (s *inputMutatingSigner) Sign(data []byte) ([]byte, error) {
	s.once.Do(func() {
		for _, input := range s.inputs {
			clear(input)
		}
	})
	proof, err := s.Handle.Sign(data)
	clear(data)
	return proof, err
}

func TestRequestRemoteAcceptanceOwnsCallerIdentities(t *testing.T) {
	defer assert.PushTester(t)()
	f := newExchange(t, nil)
	root, local, peer := bytes.Clone(f.root), bytes.Clone(f.a.public),
		bytes.Clone(f.b.public)
	signer := &inputMutatingSigner{Handle: f.a.signer,
		inputs: [][]byte{root, local, peer}}
	before := f.snapshot(t)
	try.To(pw.RequestRemoteAcceptance(t.Context(), f.a.store.Vault(),
		root, local, peer, signer))
	assert.DeepEqual(f.snapshot(t), before)
}

func TestRequestRemoteAcceptanceSanitizesDiagnostics(t *testing.T) {
	defer assert.PushTester(t)()
	const diagnostic = "PRIVATE_REMOTE_RESPONSE_DIAGNOSTIC"
	f := newExchange(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != challengePath {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = io.WriteString(w, `{"`+diagnostic+`":true}`)
		})
	})
	var trace bytes.Buffer
	previousError, previousReturn := err2.ErrorTracer(), err2.ErrRetTracer()
	err2.SetErrorTracer(&trace)
	err2.SetErrRetTracer(&trace)
	defer func() {
		err2.SetErrorTracer(previousError)
		err2.SetErrRetTracer(previousReturn)
	}()
	assert.Equal(f.request(t.Context()), pw.ErrRemoteAcceptance)
	f.a.signer.fail = true
	assert.Equal(f.request(t.Context()), pw.ErrUnusableSigner)
	for _, private := range []string{diagnostic, "private provider diagnostic",
		f.server.URL, f.ownerAuth, base64.StdEncoding.EncodeToString(f.ad),
		hex.EncodeToString(f.a.public)} {
		assert.ThatNot(strings.Contains(trace.String(), private))
	}
}
