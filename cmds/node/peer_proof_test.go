package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
)

const peerProofPath = "/peer/ad/proof"

func peerProofBody(t *testing.T, ad, nonce []byte) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	return try.To1(json.Marshal(map[string]any{"version": 1, "ad": ad, "challenge": nonce}))
}

func peerProofNonce(t *testing.T) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	nonce := make([]byte, 32)
	try.To1(rand.Read(nonce))
	return nonce
}

func postPeerProofHTTP(ctx context.Context, url, auth string, body []byte, chunked bool) peerHTTPResult {
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return peerHTTPResult{err: err}
	}
	r.Header.Set("Content-Type", "application/json")
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	if chunked {
		r.ContentLength = -1
	}
	response, err := client.Do(r)
	if err != nil {
		return peerHTTPResult{err: err}
	}
	data, readErr := io.ReadAll(response.Body)
	if response.StatusCode == 200 && (response.Header.Get("Content-Type") != "application/json" ||
		response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("WWW-Authenticate") != "") {
		readErr = errors.Join(readErr, errors.New("incorrect public proof headers"))
	}
	return peerHTTPResult{response.StatusCode, data, errors.Join(readErr, response.Body.Close())}
}

func assertOnlineProof(t *testing.T, response peerHTTPResult, f serveFixture, ad, nonce []byte) key.Signature {
	t.Helper()
	defer assert.PushTester(t)()
	assert.NoError(response.err)
	assert.Equal(response.status, 200)
	assert.That(len(response.body) <= 1024)
	var fields map[string]json.RawMessage
	try.To(json.Unmarshal(response.body, &fields))
	assert.Equal(len(fields), 2)
	assert.Equal(string(fields["version"]), "1")
	var encoded string
	try.To(json.Unmarshal(fields["proof"], &encoded))
	proof := key.Signature(try.To1(base64.StdEncoding.Strict().DecodeString(encoded)))
	assert.Equal(base64.StdEncoding.EncodeToString(proof), encoded)
	try.To(ads.VerifyCurrentProof(f.root, f.child, ad, nonce, proof, time.Now()))
	return proof
}

func TestServeOnlinePeerProofAndRestart(t *testing.T) {
	defer assert.PushTester(t)()
	f := prepareServeFixture(t)
	choice := saveServeChoice(t, f, "completed")
	s := setupPeerServe(t, f)
	auth := serveAuthorization(t, s)
	assert.Equal(serveDeviceRequest(s.handler, auth, "POST", "/owner/introductions", try.To1(onboarding.EncodeIntroduction(choice))).Code, 200)
	assert.Equal(serveDeviceRequest(s.handler, auth, "POST", "/owner/introductions/verify", []byte("{}")).Code, 200)
	assert.Equal(serveDeviceRequest(s.handler, auth, "POST", ownerBootstrapPath, []byte("{}")).Code, 200)
	owner, peer := try.To2(bindNodeListeners(t.Context(), "127.0.0.1:0", s.peerAddress))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	var result error
	var output bytes.Buffer
	go func() { result = runNodeServe(ctx, owner, peer, s, &output); close(done) }()
	defer func() { cancel(); waitNodeServe(t, done) }()
	ownerURL, peerURL := "http://"+owner.Addr().String(), "http://"+peer.Addr().String()
	published := postDeviceHTTP(t.Context(), ownerURL+ownerPublishPath, auth)
	assert.NoError(published.err)
	assert.Equal(published.status, 200)
	get := waitPeerHTTP(t, peerHTTPRequest(t.Context(), peerURL+"/peer/ad", ""))
	assert.NoError(get.err)
	assert.Equal(get.status, 200)
	var document struct{ Ad []byte }
	try.To(json.Unmarshal(get.body, &document))
	ad := document.Ad
	current, found := try.To2(ads.ReadCurrentLocal(s.store.Vault(), f.root, f.child, time.Now()))
	assert.That(found)
	assert.Equal(current.Payload.PeerIntroductionURL, peerURL+"/peer/introduction")
	assert.DeepEqual(ad, try.To1(wire.Marshal(current)))
	t.Run("proofs preserve all saved state and usage", func(t *testing.T) {
		defer assert.PushTester(t)()
		assertPeerFilesUnchanged(t, f)
		before := try.To1(deviceUnrelatedRecords(s.store.Vault()))
		nonce := peerProofNonce(t)
		proof := assertOnlineProof(t, postPeerProofHTTP(t.Context(), peerURL+peerProofPath, "", peerProofBody(t, ad, nonce), false), f, ad, nonce)
		other := peerProofNonce(t)
		second := assertOnlineProof(t, postPeerProofHTTP(t.Context(), peerURL+peerProofPath, "", peerProofBody(t, ad, other), true), f, ad, other)
		assert.ThatNot(bytes.Equal(proof, second))
		assert.Error(ads.VerifyCurrentProof(f.root, f.child, ad, other, proof, time.Now()))
		assert.DeepEqual(try.To1(deviceUnrelatedRecords(s.store.Vault())), before)
		for _, route := range []string{"/peer/introduction", "/peer/ad"} {
			public := waitPeerHTTP(t, peerHTTPRequest(t.Context(), peerURL+route, ""))
			assert.NoError(public.err)
			assert.Equal(public.status, 200)
		}
		for _, route := range []string{ownerPublishPath, ownerBootstrapPath, "/owner/introductions/verify", "/owner/ads/fetch"} {
			refused := postDeviceHTTP(t.Context(), peerURL+route, auth)
			assert.NoError(refused.err)
			assert.Equal(refused.status, 404)
		}
		refused := postPeerProofHTTP(t.Context(), ownerURL+peerProofPath, auth, peerProofBody(t, ad, nonce), false)
		assert.NoError(refused.err)
		assert.Equal(refused.status, 404)
		oversize := postPeerProofHTTP(t.Context(), peerURL+peerProofPath, "", bytes.Repeat([]byte(" "), 2049), true)
		assert.NoError(oversize.err)
		assert.Equal(oversize.status, 413)
	})
	// Bind the restart port while the original is occupied, guaranteeing a change.
	nextOwner, nextPeer := try.To2(bindNodeListeners(t.Context(), "127.0.0.1:0", s.peerAddress))
	defer func() { try.Out(nextOwner.Close()).Logf(); try.Out(nextPeer.Close()).Logf() }()
	cancel()
	waitNodeServe(t, done)
	assert.NoError(result)
	assert.ThatNot(strings.Contains(output.String(), auth))
	after := postPeerProofHTTP(t.Context(), peerURL+peerProofPath, "", peerProofBody(t, ad, peerProofNonce(t)), false)
	assert.Error(after.err) // Closed listeners cannot resurrect or sign state.
	s = setupPeerServe(t, f)
	s.configurePublication(nextPeer)
	t.Run("new bound port refuses saved ad without renewal", func(t *testing.T) {
		defer assert.PushTester(t)()
		assertPeerFilesUnchanged(t, f)
		w := serveDeviceRequest(s.peerHandler, "", "POST", peerProofPath, peerProofBody(t, ad, peerProofNonce(t)))
		assert.Equal(w.Code, 409)
		assert.Equal(w.Body.String(), "Conflict\n")
		got, exists := try.To2(ads.ReadCurrentLocal(s.store.Vault(), f.root, f.child, time.Now()))
		assert.That(exists)
		assert.DeepEqual(got, current)
	})
}
