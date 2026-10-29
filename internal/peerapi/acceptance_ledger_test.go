package peerapi

import (
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/ownerapi"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
)

func ledgerSigner(t *testing.T) key.Handle {
	t.Helper()
	defer assert.PushTester(t)()
	secret := make([]byte, 32)
	defer clear(secret)
	try.To1(rand.Read(secret))
	path := filepath.Join(t.TempDir(), "identity.json")
	try.To1(nodeidentity.Create(path, secret))
	return try.To1(nodeidentity.Open(path, secret))
}

func TestAcceptanceUsesIssuingLedgerExpiryCapacityAndInvocation(t *testing.T) {
	defer assert.PushTester(t)()
	localSigner, requesterSigner := ledgerSigner(t), ledgerSigner(t)
	rootSigner := ledgerSigner(t)
	root := key.Public(try.To1(rootSigner.CBORPublicKey()))
	local := key.Public(try.To1(localSigner.CBORPublicKey()))
	requester := key.Public(try.To1(requesterSigner.CBORPublicKey()))
	localDir, remoteDir := t.TempDir(), t.TempDir()
	try.To(os.Chmod(localDir, 0700))
	try.To(os.Chmod(remoteDir, 0700))
	store := try.To1(nodevault.CreateForNode(t.Context(), localDir,
		filepath.Join(t.TempDir(), "key"), root, local))
	defer func() { assert.NoError(store.Close()) }()
	remote := try.To1(nodevault.CreateForNode(t.Context(), remoteDir,
		filepath.Join(t.TempDir(), "key"), root, requester))
	defer func() { assert.NoError(remote.Close()) }()
	path := intro.New(key.Info{Public: root}).Introduce(rootSigner,
		key.Info{Public: requester})
	acceptance := try.To1(path.SignAcceptance(requesterSigner))
	for _, s := range []*nodevault.Store{store, remote} {
		try.To2(onboarding.SaveIntroduction(s.Vault(), root, path.Bytes(), acceptance))
		try.To1(onboarding.VerifyReceived(s.Vault(), root))
	}
	localPath := intro.New(key.Info{Public: root}).Introduce(rootSigner,
		key.Info{Public: local})
	localAcceptance := try.To1(localPath.SignAcceptance(localSigner))
	for _, s := range []*nodevault.Store{store, remote} {
		try.To2(onboarding.SaveIntroduction(s.Vault(), root,
			localPath.Bytes(), localAcceptance))
		try.To1(onboarding.VerifyReceived(s.Vault(), root))
	}
	try.To1(device.BootstrapLocal(store.Vault(), root, local, localSigner))
	try.To1(device.BootstrapLocal(remote.Vault(), root, requester, requesterSigner))
	listener := httptest.NewUnstartedServer(nil)
	defer listener.Close()
	endpoint := "http://" + listener.Listener.Addr().String() + "/peer/introduction"
	ad := try.To1(wire.Marshal(try.To1(ads.PublishLocal(store.Vault(), root,
		local, localSigner, endpoint, time.Now()))))
	_, _, bind := try.To3(ownerapi.NewAcceptanceCredentials(t.Context(),
		store.Vault(), root, local, localSigner, t.TempDir()))
	_, prove := bind(listener.Listener)
	calls := 0
	accept := func(peer key.Public, expectedAd, nonce []byte) (key.Signature, error) {
		calls++
		return prove(peer, expectedAd, nonce)
	}
	h := NewAcceptanceHandler(store.Vault(), root, local, endpoint,
		accept, NewHandler(store.Vault(), root, local)).(*challengeHandler)
	now := time.Now()
	h.challenges.now = func() time.Time { return now }
	issue := func() []byte {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, challengeRequest(challengeJSON(t, requester, ad)))
		assert.Equal(w.Code, 200)
		var reply struct{ Challenge []byte }
		try.To(json.Unmarshal(w.Body.Bytes(), &reply))
		return reply.Challenge
	}
	body := func(nonce []byte) string {
		proof := try.To1(pw.ProveLocalAcceptance(remote.Vault(), root, requester,
			local, requesterSigner, nonce))
		return acceptanceJSON(t, requester, ad, nonce, proof)
	}
	nonce := issue()
	first := body(nonce)
	for range 31 {
		issue()
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, challengeRequest(challengeJSON(t, requester, ad)))
	assertChallengeError(t, w, 429)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, acceptanceHTTPRequest(first))
	assert.Equal(w.Code, 200)
	assert.Equal(calls, 1)
	assert.Equal(len(h.challenges.entries), 31)
	fresh := issue() // Consuming one frees one slot; no pending nonce was evicted.
	now = now.Add(challengeTTL)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, acceptanceHTTPRequest(body(fresh)))
	assertChallengeError(t, w, 409)
	assert.Equal(calls, 1)
	assert.MEmpty(h.challenges.entries)
	pending := body(issue())
	restarted := NewAcceptanceHandler(store.Vault(), root, local, endpoint,
		accept, h.next)
	for _, request := range []string{first, pending} {
		w := httptest.NewRecorder()
		restarted.ServeHTTP(w, acceptanceHTTPRequest(request))
		assertChallengeError(t, w, 409)
	}
	assert.Equal(calls, 1)
}
