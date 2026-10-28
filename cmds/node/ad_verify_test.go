package node

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const ownerAdVerifyPath = "/owner/ads/verify"

type verificationExchange struct {
	Ad, Challenge []byte
	Version       int
	auth, path    string
	err           error
}

type verificationNode struct {
	fixture   serveFixture
	service   *nodeServe
	choice    onboarding.StoredChoice
	owner     *httptest.Server
	peer      *httptest.Server
	auth      string
	ad        []byte
	exchanges chan verificationExchange
	calls     atomic.Int32
	mu        sync.Mutex
	respond   func(http.ResponseWriter, *http.Request, http.Handler)
}

func (n *verificationNode) setResponse(respond func(http.ResponseWriter, *http.Request, http.Handler)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.respond = respond
}

func newVerificationPair(t *testing.T, reciprocal bool) (*verificationNode, *verificationNode) {
	t.Helper()
	defer assert.PushTester(t)()
	var root key.Handle
	alice := prepareServeFixtureWithPath(t, func(parent key.Handle, child key.Public) intro.Path {
		root = parent
		return intro.New(key.Info{Public: try.To1(parent.CBORPublicKey())}).Introduce(parent, key.Info{Public: child})
	})
	dir, unlock, _ := initialized(t)
	handle := try.To1(nodeidentity.OpenDirectory(dir, unlock))
	bob := serveFixture{dir: dir, unlock: unlock, storageKey: filepath.Join(filepath.Dir(dir), "storage-key"),
		root: bytes.Clone(alice.root), child: try.To1(handle.CBORPublicKey())}
	bob.proposal = intro.New(key.Info{Public: bob.root}).Introduce(root, key.Info{Public: bob.child})
	store := try.To1(nodevault.CreateForNode(t.Context(), bob.dir, bob.storageKey, bob.root, bob.child))
	try.To(store.Close())
	a, b := startVerificationNode(t, alice, true), startVerificationNode(t, bob, reciprocal)
	receiveVerificationAd(t, b, a)
	if reciprocal {
		receiveVerificationAd(t, a, b)
	}
	return a, b
}

func startVerificationNode(t *testing.T, f serveFixture, publishing bool) *verificationNode {
	t.Helper()
	defer assert.PushTester(t)()
	n := &verificationNode{fixture: f, exchanges: make(chan verificationExchange, 16)}
	if publishing {
		n.choice = saveServeChoice(t, f, "completed")
	}
	cmd := serveCommand(t, f)
	if publishing {
		try.To(cmd.Flags().Set("peer-listen", "127.0.0.1:0"))
	}
	n.service, _ = try.To2(setupNodeServe(t.Context(), cmd))
	t.Cleanup(func() { assert.NoError(n.service.close()) })
	n.auth = serveAuthorization(t, n.service)
	if publishing {
		n.peer = httptest.NewUnstartedServer(nil)
		n.service.configurePublication(n.peer.Listener)
		next := n.service.peerHandler
		n.peer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != peerProofPath {
				next.ServeHTTP(w, r)
				return
			}
			n.calls.Add(1)
			data, err := io.ReadAll(io.LimitReader(r.Body, 2049))
			exchange := verificationExchange{auth: r.Header.Get("Authorization"), path: r.Method + " " + r.URL.RequestURI()}
			exchange.err = errors.Join(err, json.Unmarshal(data, &exchange))
			n.exchanges <- exchange
			r.Body = io.NopCloser(bytes.NewReader(data))
			n.mu.Lock()
			respond := n.respond
			n.mu.Unlock()
			if respond != nil {
				respond(w, r, next)
			} else {
				next.ServeHTTP(w, r)
			}
		})
		n.peer.Start()
		t.Cleanup(n.peer.Close)
		try.To2(onboarding.SaveIntroduction(n.service.store.Vault(), f.root, n.choice.Proposal.Bytes(), n.choice.Acceptance))
		try.To1(onboarding.VerifyReceived(n.service.store.Vault(), f.root))
		assert.Equal(serveDeviceRequest(n.service.handler, n.auth, "POST", ownerBootstrapPath, []byte("{}")).Code, 200)
		n.publish(t)
	} else {
		n.service.configurePublication(nil)
		assert.INil(n.service.peerHandler)
	}
	n.owner = httptest.NewServer(n.service.handler)
	t.Cleanup(n.owner.Close)
	return n
}

func (n *verificationNode) publish(t *testing.T) {
	t.Helper()
	defer assert.PushTester(t)()
	assert.Equal(serveDeviceRequest(n.service.handler, n.auth, "POST", ownerPublishPath, []byte("{}")).Code, 200)
	current, found := try.To2(ads.ReadCurrentLocal(n.service.store.Vault(), n.fixture.root, n.fixture.child, time.Now()))
	assert.That(found)
	n.ad = try.To1(wire.Marshal(current))
}

func receiveVerificationAd(t *testing.T, receiver, publisher *verificationNode) {
	t.Helper()
	defer assert.PushTester(t)()
	v, root := receiver.service.store.Vault(), receiver.fixture.root
	try.To2(onboarding.SaveIntroduction(v, root, publisher.choice.Proposal.Bytes(), publisher.choice.Acceptance))
	try.To1(onboarding.VerifyReceived(v, root))
	try.To1(ads.ReceiveClaim(v, root, publisher.fixture.child, publisher.ad))
}

func ownerAdVerificationBody(subject key.Public) []byte {
	return []byte(`{"subject_public_key_hex":"` + hex.EncodeToString(subject) + `"}`)
}

func (n *verificationNode) verify(ctx context.Context, subject key.Public) peerHTTPResult {
	return postPeerProofHTTP(ctx, n.owner.URL+ownerAdVerifyPath, n.auth, ownerAdVerificationBody(subject), false)
}

func assertAdVerification(t *testing.T, result peerHTTPResult, subject key.Public, changed bool) {
	t.Helper()
	defer assert.PushTester(t)()
	assert.NoError(result.err)
	assert.Equal(result.status, 200, string(result.body))
	assert.That(len(result.body) <= 1024)
	var fields map[string]any
	try.To(json.Unmarshal(result.body, &fields))
	assert.DeepEqual(fields, map[string]any{"subject_public_key_hex": hex.EncodeToString(subject), "verified": true, "changed": changed})
}

func assertHistoricalAd(t *testing.T, receiver, publisher *verificationNode, want []byte) {
	t.Helper()
	defer assert.PushTester(t)()
	got, found := try.To2(ads.ReadVerifiedClaim(receiver.service.store.Vault(), receiver.fixture.root, publisher.fixture.child))
	assert.That(found)
	assert.DeepEqual(got, want)
}

func verificationUnrelatedState(vault *storage.Vault) (_ map[string]map[string][]byte, err error) {
	defer err2.Handle(&err, nil)
	records := try.To1(deviceUnrelatedRecords(vault))
	records["root"] = make(map[string][]byte)
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		for _, name := range []string{"local-device-auth-v1", "unrelated"} {
			if try.To1(tx.HasChild([]byte(name))) {
				ns := try.To1(tx.Child([]byte(name)))
				records[name] = make(map[string][]byte)
				try.To(ns.Each(func(k, v []byte) error { records[name][string(k)] = v; return nil }))
			}
		}
		return tx.Each(func(k, v []byte) error {
			if string(k) != "verified-ad-claims-v1" {
				records["root"][string(k)] = v
			}
			return nil
		})
	}))
	return records, nil
}

func TestServeAdVerificationWithoutPeerListener(t *testing.T) {
	defer assert.PushTester(t)()
	a, b := newVerificationPair(t, false)
	assert.INil(b.service.peerHandler)
	assert.Equal(a.calls.Load(), int32(0)) // Setup, receipt and Known never verify.
	try.To(b.service.store.Vault().Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		ns := try.To1(tx.EnsureChild([]byte("unrelated")))
		return ns.Put([]byte("sentinel"), []byte("unchanged"))
	}))
	before := try.To1(verificationUnrelatedState(b.service.store.Vault()))
	assertPeerFilesUnchanged(t, a.fixture)
	assertAdVerification(t, b.verify(t.Context(), a.fixture.child), a.fixture.child, true)
	assertHistoricalAd(t, b, a, a.ad)
	assert.DeepEqual(try.To1(verificationUnrelatedState(b.service.store.Vault())), before)
	vaultBytes := try.To1(os.ReadFile(filepath.Join(b.fixture.dir, "state", "vault.db")))
	usageBytes := try.To1(os.ReadFile(filepath.Join(b.fixture.dir, "state", "usage.db")))
	assertAdVerification(t, b.verify(t.Context(), a.fixture.child), a.fixture.child, false)
	assert.DeepEqual(try.To1(os.ReadFile(filepath.Join(b.fixture.dir, "state", "vault.db"))), vaultBytes)
	assert.DeepEqual(try.To1(os.ReadFile(filepath.Join(b.fixture.dir, "state", "usage.db"))), usageBytes)
	assert.DeepEqual(try.To1(verificationUnrelatedState(b.service.store.Vault())), before)
	first, second := waitVerificationExchange(t, a.exchanges), waitVerificationExchange(t, a.exchanges)
	for _, exchange := range []verificationExchange{first, second} {
		assert.NoError(exchange.err)
		assert.Empty(exchange.auth)
		assert.Equal(exchange.path, "POST /peer/ad/proof")
		assert.Equal(exchange.Version, 1)
		assert.DeepEqual(exchange.Ad, a.ad)
		assert.SLen(exchange.Challenge, 32)
	}
	assert.ThatNot(bytes.Equal(first.Challenge, second.Challenge))
	assert.Equal(a.calls.Load(), int32(2))
	refused := postPeerProofHTTP(t.Context(), a.peer.URL+ownerAdVerifyPath, a.auth, ownerAdVerificationBody(b.fixture.child), false)
	assert.NoError(refused.err)
	assert.Equal(refused.status, 404)
}

func TestServeAdVerificationReciprocal(t *testing.T) {
	defer assert.PushTester(t)()
	a, b := newVerificationPair(t, true)
	beforeA, beforeB := try.To1(verificationUnrelatedState(a.service.store.Vault())), try.To1(verificationUnrelatedState(b.service.store.Vault()))
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	gate := func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		arrived <- struct{}{}
		select {
		case <-release:
			next.ServeHTTP(w, r) // Real proof capability acquires its publisher lock.
		case <-r.Context().Done():
		}
	}
	a.setResponse(gate)
	b.setResponse(gate)
	start := make(chan struct{})
	results := make(chan peerHTTPResult, 2)
	go func() { <-start; results <- a.verify(t.Context(), b.fixture.child) }()
	go func() { <-start; results <- b.verify(t.Context(), a.fixture.child) }()
	close(start)
	for range 2 {
		select {
		case <-arrived:
		case <-time.After(2 * time.Second):
			t.Fatal("both outbound proofs must arrive before either is allowed")
		}
	}
	unblock()
	for range 2 {
		select {
		case result := <-results:
			assert.NoError(result.err)
			assert.Equal(result.status, 200, string(result.body))
		case <-time.After(2 * time.Second):
			t.Fatal("reciprocal proof waited for a lock cycle or timeout")
		}
	}
	assert.Equal(a.calls.Load(), int32(1))
	assert.Equal(b.calls.Load(), int32(1))
	assertHistoricalAd(t, a, b, b.ad)
	assertHistoricalAd(t, b, a, a.ad)
	assert.DeepEqual(try.To1(verificationUnrelatedState(a.service.store.Vault())), beforeA)
	assert.DeepEqual(try.To1(verificationUnrelatedState(b.service.store.Vault())), beforeB)
}

func TestServeAdVerificationConcurrentSameAd(t *testing.T) {
	defer assert.PushTester(t)()
	a, b := newVerificationPair(t, false)
	arrived, release := make(chan struct{}, 2), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	a.setResponse(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		arrived <- struct{}{}
		select {
		case <-release:
			next.ServeHTTP(w, r)
		case <-r.Context().Done():
		}
	})
	results := make(chan peerHTTPResult, 2)
	for range 2 {
		go func() { results <- b.verify(t.Context(), a.fixture.child) }()
	}
	for range 2 {
		select {
		case <-arrived:
		case <-time.After(2 * time.Second):
			t.Fatal("verification requests were serialized across the network")
		}
	}
	unblock()
	changed := 0
	for range 2 {
		result := waitPeerHTTP(t, results)
		assert.NoError(result.err)
		assert.Equal(result.status, 200)
		var response struct{ Verified, Changed bool }
		try.To(json.Unmarshal(result.body, &response))
		assert.That(response.Verified)
		if response.Changed {
			changed++
		}
	}
	assert.Equal(changed, 1)
	assertHistoricalAd(t, b, a, a.ad)
	first, second := waitVerificationExchange(t, a.exchanges), waitVerificationExchange(t, a.exchanges)
	assert.ThatNot(bytes.Equal(first.Challenge, second.Challenge))
}
