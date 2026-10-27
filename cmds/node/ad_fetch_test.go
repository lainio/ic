package node

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const ownerAdFetchPath = "/owner/ads/fetch"

func TestServeAdFetchTwoIndependentNodesAndRestart(t *testing.T) {
	defer assert.PushTester(t)()
	alice := prepareServeFixture(t)
	choice := saveServeChoice(t, alice, "completed")
	sender := setupPeerServe(t, alice)
	// Use the actual opt-in handler and bind before its one-shot configuration.
	peer := httptest.NewUnstartedServer(nil)
	sender.configurePublication(peer.Listener)
	peer.Config.Handler = sender.peerHandler
	peer.Start()
	defer peer.Close()
	senderAuth := serveAuthorization(t, sender)
	for _, request := range []struct {
		path string
		body []byte
	}{
		{"/owner/introductions", try.To1(onboarding.EncodeIntroduction(choice))},
		{"/owner/introductions/verify", []byte("{}")},
		{ownerBootstrapPath, []byte("{}")},
		{ownerPublishPath, []byte("{}")},
	} {
		assert.Equal(serveDeviceRequest(sender.handler, senderAuth, "POST", request.path, request.body).Code, 200)
	}
	dir, unlock, _ := initialized(t)
	handle := try.To1(nodeidentity.OpenDirectory(dir, unlock))
	bob := serveFixture{dir: dir, unlock: unlock, storageKey: filepath.Join(filepath.Dir(dir), "storage-key"),
		root: bytes.Clone(alice.root), child: try.To1(handle.CBORPublicKey())}
	assert.ThatNot(bytes.Equal(bob.child, alice.child))
	store := try.To1(nodevault.CreateForNode(t.Context(), bob.dir, bob.storageKey, bob.root, bob.child))
	try.To(store.Close())
	receiver, _ := try.To2(setupNodeServe(t.Context(), serveCommand(t, bob)))
	defer func() { try.Out(receiver.close()).Logf() }()
	assert.INil(receiver.peerHandler) // Receiving requires no public listener.
	owner := httptest.NewServer(receiver.handler)
	defer owner.Close()
	before := try.To1(adFetchUnrelatedRecords(receiver.store.Vault()))
	current, found := try.To2(ads.ReadCurrentLocal(sender.store.Vault(), alice.root, alice.child, time.Now()))
	assert.That(found)
	ad := try.To1(wire.Marshal(current))
	senderBytes := try.To1(os.ReadFile(filepath.Join(alice.dir, "state", "vault.db")))
	fetch := func(created, changed bool) {
		t.Helper()
		body := try.To1(json.Marshal(map[string]string{"peer_url": peer.URL + "/peer/ad"}))
		r := try.To1(http.NewRequestWithContext(t.Context(), "POST", owner.URL+ownerAdFetchPath, bytes.NewReader(body)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", serveAuthorization(t, receiver))
		transport := &http.Transport{DisableKeepAlives: true, DisableCompression: true}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
		response := try.To1(client.Do(r))
		defer func() { assert.NoError(response.Body.Close()) }()
		assert.Equal(response.StatusCode, 200)
		assert.Equal(response.Header.Get("Cache-Control"), "no-store")
		var result map[string]any
		try.To(json.Unmarshal(try.To1(io.ReadAll(response.Body)), &result))
		assert.DeepEqual(result, map[string]any{"subject_public_key_hex": hex.EncodeToString(alice.child),
			"introduction_created": created, "ad_changed": changed})
	}
	fetch(true, true)
	assertAdFetchStored(t, receiver.store.Vault(), bob.root, alice.child, choice, ad)
	assert.DeepEqual(try.To1(adFetchUnrelatedRecords(receiver.store.Vault())), before)
	for _, file := range []string{"vault.db", "usage.db"} {
		path := filepath.Join(bob.dir, "state", file)
		before := try.To1(os.ReadFile(path))
		fetch(false, false)
		assert.That(bytes.Equal(try.To1(os.ReadFile(path)), before))
	}
	assert.That(bytes.Equal(try.To1(os.ReadFile(filepath.Join(alice.dir, "state", "vault.db"))), senderBytes))
	// Owner paths remain absent on the unauthenticated peer handler.
	for _, path := range []string{ownerAdFetchPath, ownerPublishPath, ownerBootstrapPath, "/owner/introductions"} {
		assert.Equal(serveDeviceRequest(sender.peerHandler, senderAuth, "POST", path, []byte("{}")).Code, 404)
	}
	// A newly published claim replaces only ReceivedAd at the receiver.
	assert.Equal(serveDeviceRequest(sender.handler, senderAuth, "POST", ownerPublishPath, []byte("{}")).Code, 200)
	current, found = try.To2(ads.ReadCurrentLocal(sender.store.Vault(), alice.root, alice.child, time.Now()))
	assert.That(found)
	nextAd := try.To1(wire.Marshal(current))
	assert.ThatNot(bytes.Equal(nextAd, ad))
	fetch(false, true)
	assertAdFetchStored(t, receiver.store.Vault(), bob.root, alice.child, choice, nextAd)
	assert.DeepEqual(try.To1(adFetchUnrelatedRecords(receiver.store.Vault())), before)
	owner.Close()
	try.To(receiver.close())
	receiver, _ = try.To2(setupNodeServe(t.Context(), serveCommand(t, bob)))
	assertAdFetchStored(t, receiver.store.Vault(), bob.root, alice.child, choice, nextAd)
	assert.DeepEqual(try.To1(adFetchUnrelatedRecords(receiver.store.Vault())), before)
	owner = httptest.NewServer(receiver.handler)
	defer owner.Close()
	fetch(false, false)
}

func assertAdFetchStored(t *testing.T, vault *storage.Vault, root, subject key.Public, choice onboarding.StoredChoice, ad []byte) {
	t.Helper()
	defer assert.PushTester(t)()
	assert.DeepEqual(try.To1(onboarding.ListIntroductions(vault, root)), []key.Public{subject})
	assert.SEmpty(try.To1(onboarding.ListKnownIntroductions(vault, root)))
	got, found := try.To2(ads.ReadReceivedClaim(vault, root, subject))
	assert.That(found)
	assert.DeepEqual(got, ad)
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		ns := try.To1(tx.Child([]byte("received-introductions-v1")))
		record, found := try.To2(ns.Get(subject))
		assert.That(found)
		proposal := choice.Proposal.Bytes()
		assert.DeepEqual(record[5:5+len(proposal)], proposal)
		assert.DeepEqual(record[5+len(proposal):], []byte(choice.Acceptance))
		return nil
	}))
}

// Snapshot existing authority namespaces and all direct root records except
// ReceivedAd. This operation has no receiver VerifyAd/PW/trust implementation.
func adFetchUnrelatedRecords(vault *storage.Vault) (_ map[string]map[string][]byte, err error) {
	defer err2.Handle(&err, nil)
	records := try.To1(deviceUnrelatedRecords(vault))
	delete(records, "received-introductions-v1")
	records["root"] = make(map[string][]byte)
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		if try.To1(tx.HasChild([]byte("local-device-auth-v1"))) {
			ns := try.To1(tx.Child([]byte("local-device-auth-v1")))
			records["local-device-auth-v1"] = make(map[string][]byte)
			try.To(ns.Each(func(k, v []byte) error { records["local-device-auth-v1"][string(k)] = v; return nil }))
		}
		return tx.Each(func(k, v []byte) error {
			if string(k) != "received-ad-claims-v1" {
				records["root"][string(k)] = v
			}
			return nil
		})
	}))
	return records, nil
}
