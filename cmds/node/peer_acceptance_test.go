package node

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
)

const peerAcceptancePath = "/peer/pw/accept"

func peerAcceptanceBody(t *testing.T, requester key.Public,
	ad, nonce []byte, proof key.Signature,
) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	return try.To1(json.Marshal(map[string]any{
		"version": 1, "requester_public_key_hex": hex.EncodeToString(requester),
		"ad": ad, "challenge": nonce, "requester_proof": proof,
	}))
}

func requestAcceptanceProof(t *testing.T, requester, acceptor *verificationNode,
	nonce []byte,
) key.Signature {
	t.Helper()
	defer assert.PushTester(t)()
	f := requester.fixture
	signer := try.To1(nodeidentity.OpenDirectory(f.dir, f.unlock))
	proof := try.To1(pw.ProveLocalAcceptance(requester.service.store.Vault(),
		f.root, f.child, acceptor.fixture.child, signer, nonce))
	try.To(pw.VerifyLocalAcceptanceProof(f.root, f.child,
		acceptor.fixture.child, nonce, proof))
	return proof
}

func assertOnlineAcceptance(t *testing.T, result peerHTTPResult,
	root, acceptor, requester key.Public, nonce []byte,
) key.Signature {
	t.Helper()
	defer assert.PushTester(t)()
	assert.NoError(result.err)
	assert.Equal(result.status, 200)
	assert.That(len(result.body) <= 1024)
	var fields map[string]json.RawMessage
	try.To(json.Unmarshal(result.body, &fields))
	assert.Equal(len(fields), 2)
	assert.Equal(string(fields["version"]), "1")
	var encoded string
	try.To(json.Unmarshal(fields["acceptor_proof"], &encoded))
	proof := key.Signature(try.To1(base64.StdEncoding.Strict().DecodeString(encoded)))
	assert.Equal(base64.StdEncoding.EncodeToString(proof), encoded)
	try.To(pw.VerifyLocalAcceptanceProof(root, acceptor, requester, nonce, proof))
	return proof
}

func TestServeAcceptanceTwoRestoredNodes(t *testing.T) {
	defer assert.PushTester(t)()
	a, b := newVerificationPair(t, true)
	assertPeerFilesUnchanged(t, a.fixture)
	assertPeerFilesUnchanged(t, b.fixture)
	beforeA := try.To1(verificationUnrelatedState(a.service.store.Vault()))
	beforeB := try.To1(verificationUnrelatedState(b.service.store.Vault()))
	start := time.Now()
	nonce := assertPeerChallenge(t, postPeerProofHTTP(t.Context(),
		a.peer.URL+peerChallengePath, "",
		peerChallengeBody(t, b.fixture.child, a.ad), true), start)
	requesterProof := requestAcceptanceProof(t, b, a, nonce)
	body := peerAcceptanceBody(t, b.fixture.child, a.ad, nonce, requesterProof)
	proof := assertOnlineAcceptance(t, postPeerProofHTTP(t.Context(),
		a.peer.URL+peerAcceptancePath, "", body, true),
		a.fixture.root, a.fixture.child, b.fixture.child, nonce)
	assert.ThatNot(bytes.Equal(proof, requesterProof))
	assert.Error(pw.VerifyLocalAcceptanceProof(a.fixture.root,
		b.fixture.child, a.fixture.child, nonce, proof))
	assert.Error(pw.VerifyLocalAcceptanceProof(b.fixture.child,
		a.fixture.child, b.fixture.child, nonce, proof))
	assert.Error(pw.VerifyLocalAcceptanceProof(a.fixture.root,
		a.fixture.child, b.fixture.child, peerProofNonce(t), proof))
	refused := postPeerProofHTTP(t.Context(), a.peer.URL+peerAcceptancePath,
		"", body, false)
	assert.NoError(refused.err)
	assert.Equal(refused.status, 409)
	for _, n := range []*verificationNode{a, b} {
		_, found := try.To2(ads.ReadVerifiedClaim(n.service.store.Vault(),
			n.fixture.root, a.fixture.child))
		assert.ThatNot(found)
		for _, auth := range []string{"", n.auth} {
			refused := postPeerProofHTTP(t.Context(), n.owner.URL+peerAcceptancePath,
				auth, body, false)
			assert.NoError(refused.err)
			assert.Equal(refused.status, 404)
		}
	}
	assert.DeepEqual(try.To1(verificationUnrelatedState(a.service.store.Vault())), beforeA)
	assert.DeepEqual(try.To1(verificationUnrelatedState(b.service.store.Vault())), beforeB)
}

func TestServeAcceptanceRestartForgetsUsedAndUnusedChallenges(t *testing.T) {
	defer assert.PushTester(t)()
	a, b := newVerificationPair(t, true)
	var bodies [][]byte
	for range 2 {
		started := time.Now()
		nonce := assertPeerChallenge(t, postPeerProofHTTP(t.Context(),
			a.peer.URL+peerChallengePath, "",
			peerChallengeBody(t, b.fixture.child, a.ad), false), started)
		bodies = append(bodies, peerAcceptanceBody(t, b.fixture.child, a.ad,
			nonce, requestAcceptanceProof(t, b, a, nonce)))
	}
	assert.Equal(postPeerProofHTTP(t.Context(), a.peer.URL+peerAcceptancePath,
		"", bodies[0], false).status, 200)
	address := a.peer.Listener.Addr().String()
	a.peer.Close()
	a.owner.Close()
	try.To(a.service.close())
	// Reopen the real Store and signer on the same port. The unchanged current
	// ad is still valid, isolating ledger loss from endpoint replacement.
	s := setupPeerServe(t, a.fixture)
	config := &net.ListenConfig{}
	listener := try.To1(config.Listen(t.Context(), "tcp", address))
	defer func() { try.Out(listener.Close()).Logf() }()
	s.configurePublication(listener)
	server := httptest.NewUnstartedServer(s.peerHandler)
	try.To(server.Listener.Close())
	server.Listener = listener
	server.Start()
	defer server.Close()
	t.Run("restart is read only with no acceptance history", func(t *testing.T) {
		defer assert.PushTester(t)()
		assertPeerFilesUnchanged(t, a.fixture)
		for _, body := range bodies {
			result := postPeerProofHTTP(t.Context(), server.URL+peerAcceptancePath,
				"", body, false)
			assert.NoError(result.err)
			assert.Equal(result.status, 409)
			assert.Equal(string(result.body), "Conflict\n")
		}
		started := time.Now()
		nonce := assertPeerChallenge(t, postPeerProofHTTP(t.Context(),
			server.URL+peerChallengePath, "",
			peerChallengeBody(t, b.fixture.child, a.ad), false), started)
		body := peerAcceptanceBody(t, b.fixture.child, a.ad, nonce,
			requestAcceptanceProof(t, b, a, nonce))
		assertOnlineAcceptance(t, postPeerProofHTTP(t.Context(),
			server.URL+peerAcceptancePath, "", body, false),
			a.fixture.root, a.fixture.child, b.fixture.child, nonce)
	})
}

func TestServeAcceptanceWithConcurrentVerificationAndPublication(t *testing.T) {
	defer assert.PushTester(t)()
	a, b := newVerificationPair(t, true)
	var operations []func() peerHTTPResult
	for _, pair := range [][2]*verificationNode{{a, b}, {b, a}} {
		x, y := pair[0], pair[1]
		started := time.Now()
		nonce := assertPeerChallenge(t, postPeerProofHTTP(t.Context(),
			x.peer.URL+peerChallengePath, "",
			peerChallengeBody(t, y.fixture.child, x.ad), false), started)
		body := peerAcceptanceBody(t, y.fixture.child, x.ad, nonce,
			requestAcceptanceProof(t, y, x, nonce))
		fetch := try.To1(json.Marshal(map[string]string{"peer_url": y.peer.URL + "/peer/ad"}))
		operations = append(operations,
			func() peerHTTPResult {
				return postPeerProofHTTP(t.Context(), x.peer.URL+peerAcceptancePath, "", body, false)
			},
			func() peerHTTPResult { return x.verify(t.Context(), y.fixture.child) },
			func() peerHTTPResult {
				return postPeerProofHTTP(t.Context(), x.owner.URL+"/owner/ads/fetch", x.auth, fetch, false)
			},
			func() peerHTTPResult {
				return postDeviceHTTP(t.Context(), x.owner.URL+ownerPublishPath, x.auth)
			})
	}
	results := make(chan peerHTTPResult, len(operations))
	var workers sync.WaitGroup
	for _, op := range operations {
		workers.Add(1)
		go func() { defer workers.Done(); results <- op() }()
	}
	workers.Wait()
	close(results)
	for result := range results {
		assert.NoError(result.err)
		// Supersession can legitimately reject acceptance or online verification.
		assert.That(result.status == 200 || result.status == 409 || result.status == 502)
	}
}

func TestServeAcceptanceJoinsBeforeVaultClose(t *testing.T) {
	for _, unexpected := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "owner exit"}[unexpected], func(t *testing.T) {
			defer assert.PushTester(t)()
			a, b := newVerificationPair(t, true)
			a.peer.Close()
			a.owner.Close()
			try.To(a.service.close())
			s := setupPeerServe(t, a.fixture)
			owner, peer := try.To2(bindNodeListeners(t.Context(), "127.0.0.1:0", s.peerAddress))
			s.configurePublication(peer)
			assert.Equal(serveDeviceRequest(s.handler, serveAuthorization(t, s),
				"POST", ownerPublishPath, []byte("{}")).Code, 200)
			current, _ := try.To2(ads.ReadCurrentLocal(s.store.Vault(),
				a.fixture.root, a.fixture.child, time.Now()))
			ad := try.To1(wire.Marshal(current))
			issued := serveDeviceRequest(s.peerHandler, "", "POST", peerChallengePath,
				peerChallengeBody(t, b.fixture.child, ad))
			assert.Equal(issued.Code, 200)
			var reply struct{ Challenge []byte }
			try.To(json.Unmarshal(issued.Body.Bytes(), &reply))
			body := peerAcceptanceBody(t, b.fixture.child, ad, reply.Challenge,
				requestAcceptanceProof(t, b, a, reply.Challenge))
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			next := s.peerHandler
			read := make(chan error, 1)
			s.peerHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				<-release
				_, _, err := onboarding.ReadStoredChoice(s.store.Vault(), a.fixture.root, a.fixture.child)
				read <- err
				next.ServeHTTP(w, r)
			})
			observed := &peerObservedListener{Listener: peer, closed: make(chan struct{})}
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			var result error
			var output bytes.Buffer
			go func() { result = runNodeServe(ctx, owner, observed, s, &output); close(done) }()
			defer func() { cancel(); unblock(); waitNodeServe(t, done) }()
			response := make(chan peerHTTPResult, 1)
			go func() {
				response <- postPeerProofHTTP(t.Context(), "http://"+peer.Addr().String()+peerAcceptancePath,
					"", body, false)
			}()
			waitNodeServe(t, entered)
			if unexpected {
				try.To(owner.Close())
			} else {
				cancel()
			}
			waitNodeServe(t, observed.closed)
			select {
			case <-done:
				t.Fatal("service closed the Vault before acceptance joined")
			default:
			}
			unblock()
			waitNodeServe(t, done)
			assert.NoError(<-read)
			assertOnlineAcceptance(t, waitPeerHTTP(t, response), a.fixture.root,
				a.fixture.child, b.fixture.child, reply.Challenge)
			if unexpected {
				assert.ErrorIs(result, net.ErrClosed)
			} else {
				assert.NoError(result)
			}
			assertServeClosed(t, s, a.fixture, a.choice)
		})
	}
}

func TestServeAcceptanceChangedPortAndOptOut(t *testing.T) {
	defer assert.PushTester(t)()
	a, b := newVerificationPair(t, true)
	started := time.Now()
	nonce := assertPeerChallenge(t, postPeerProofHTTP(t.Context(),
		a.peer.URL+peerChallengePath, "",
		peerChallengeBody(t, b.fixture.child, a.ad), false), started)
	body := peerAcceptanceBody(t, b.fixture.child, a.ad, nonce,
		requestAcceptanceProof(t, b, a, nonce))
	// Reserve a distinct real port before shutting down the old publication.
	config := &net.ListenConfig{}
	listener := try.To1(config.Listen(t.Context(), "tcp", "127.0.0.1:0"))
	defer func() { try.Out(listener.Close()).Logf() }()
	assert.NotEqual(listener.Addr().String(), a.peer.Listener.Addr().String())
	a.peer.Close()
	a.owner.Close()
	try.To(a.service.close())
	s := setupPeerServe(t, a.fixture)
	s.configurePublication(listener)
	t.Run("new port cannot use saved publication", func(t *testing.T) {
		defer assert.PushTester(t)()
		assertPeerFilesUnchanged(t, a.fixture)
		w := serveDeviceRequest(s.peerHandler, "", "POST", peerAcceptancePath, body)
		assert.Equal(w.Code, 409)
		assert.Equal(w.Body.String(), "Conflict\n")
		current, found := try.To2(ads.ReadCurrentLocal(s.store.Vault(),
			a.fixture.root, a.fixture.child, time.Now()))
		assert.That(found)
		assert.DeepEqual(try.To1(wire.Marshal(current)), a.ad)
	})
	try.To(s.close())
	disabled, _ := try.To2(setupNodeServe(t.Context(), serveCommand(t, a.fixture)))
	defer func() { try.Out(disabled.close()).Logf() }()
	owner, peer := try.To2(bindNodeListeners(t.Context(), "127.0.0.1:0", disabled.peerAddress))
	defer func() { try.Out(owner.Close()).Logf() }()
	assert.INil(peer)
	disabled.configurePublication(nil)
	assert.INil(disabled.peerHandler)
	for _, auth := range []string{"", serveAuthorization(t, disabled)} {
		w := serveDeviceRequest(disabled.handler, auth, "POST", peerAcceptancePath, body)
		assert.Equal(w.Code, 404)
	}
}
