package node

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
)

func establishFirstUsePairV2(t *testing.T) (*verificationNode,
	*verificationNode,
) {
	t.Helper()
	defer assert.PushTester(t)()
	alice, bob := newVerificationPair(t, true)
	assertAdVerification(t, alice.verify(t.Context(), bob.fixture.child),
		bob.fixture.child, true)
	issued := postPeerProofHTTP(t.Context(),
		bob.owner.URL+"/owner/pw/invitations/issue", bob.auth,
		[]byte(`{"recipient_public_key_hex":null}`), false)
	assert.NoError(issued.err)
	assert.Equal(issued.status, 200)
	row, _ := try.To2(pw.ReadInvitation(bob.service.store.Vault(),
		bob.fixture.root, bob.fixture.child))
	body := try.To1(json.Marshal(map[string]any{
		"version": 2, "target_public_key_hex": hex.EncodeToString(bob.fixture.child),
		"invitation_id_hex": hex.EncodeToString(row.ID), "audience": "Any",
	}))
	result := postPeerProofHTTP(t.Context(),
		alice.owner.URL+"/owner/pw/invitations/redeem", alice.auth, body, false)
	assert.NoError(result.err)
	assert.Equal(result.status, 200)
	return alice, bob
}

func TestServeFirstUseV2ExactLocalHistoryAndRestart(t *testing.T) {
	defer assert.PushTester(t)()
	alice, bob := establishFirstUsePairV2(t)
	beforeAlice := try.To1(firstUseState(alice.service.store.Vault()))
	beforeBob := try.To1(firstUseState(bob.service.store.Vault()))
	assert.SNil(beforeAlice["root"]["local-pw-first-use-v1"])
	assert.SNil(beforeBob["root"]["local-pw-use-seen-v1"])
	// The default owner selection cannot reinterpret accepted v2 history.
	legacy := postPeerProofHTTP(t.Context(),
		alice.owner.URL+"/owner/pw/first-use", alice.auth, []byte("{}"), false)
	assert.NoError(legacy.err)
	assert.Equal(legacy.status, 409)
	assert.DeepEqual(try.To1(firstUseState(alice.service.store.Vault())),
		beforeAlice)
	result := postPeerProofHTTP(t.Context(),
		alice.owner.URL+"/owner/pw/first-use", alice.auth,
		[]byte(`{"version":2}`), false)
	assert.NoError(result.err)
	assert.Equal(result.status, 200)
	assert.Equal(string(result.body), `{"local_ready":true}`)
	afterAlice := try.To1(firstUseState(alice.service.store.Vault()))
	afterBob := try.To1(firstUseState(bob.service.store.Vault()))
	var ready struct {
		_                 struct{} `cbor:",toarray"`
		Version           uint8
		State             string
		Request, Response []byte
	}
	var receipt struct {
		_                 struct{} `cbor:",toarray"`
		Version           uint8
		Request, Response []byte
	}
	try.To(wire.UnmarshalCanonical(&ready,
		afterAlice["root"]["local-pw-first-use-v1"]))
	try.To(wire.UnmarshalCanonical(&receipt,
		afterBob["root"]["local-pw-use-seen-v1"]))
	assert.Equal(ready.Version, 2)
	assert.Equal(ready.State, "Ready")
	assert.Equal(receipt.Version, 2)
	assert.DeepEqual(receipt.Request, ready.Request)
	assert.DeepEqual(receipt.Response, ready.Response)
	var request pw.SignedFirstUseV2
	var response pw.SignedFirstUseResponseV2
	try.To(wire.UnmarshalCanonical(&request, ready.Request))
	try.To(wire.UnmarshalCanonical(&response, ready.Response))
	digest := key.HashTagged(pw.FirstUsePurposeV2,
		try.To1(wire.Marshal(request.Payload)))
	assert.That(request.Signature.Verify(alice.fixture.child, digest[:]))
	digest = key.HashTagged(pw.FirstUseResponsePurposeV2,
		try.To1(wire.Marshal(response.Payload)))
	assert.That(response.Signature.Verify(bob.fixture.child, digest[:]))
	assert.DeepEqual(response.Payload.Request, request.Payload)
	assert.Equal(request.Payload.Established.Binding.RequesterContact,
		alice.peer.URL)
	assert.Equal(request.Payload.Established.Binding.TargetContact, bob.peer.URL)
	assert.Equal(try.To1(pw.RequesterContactV2(alice.service.store.Vault(),
		alice.fixture.root, alice.fixture.child)), bob.peer.URL)
	assert.Equal(try.To1(pw.BobContactV2(bob.service.store.Vault(),
		bob.fixture.root, bob.fixture.child)), alice.peer.URL)
	delete(afterAlice["root"], "local-pw-first-use-v1")
	delete(afterBob["root"], "local-pw-use-seen-v1")
	// Only distinct local observations changed. No Trust/PWOpen/message state.
	assert.DeepEqual(afterAlice, beforeAlice)
	assert.DeepEqual(afterBob, beforeBob)
	for _, n := range []*verificationNode{alice, bob} {
		retained := try.To1(firstUseState(n.service.store.Vault()))
		body := []byte(`{"text":"still v1 only","peer_message_url":"` +
			bob.peer.URL + `/peer/pw/message"}`)
		result = postPeerProofHTTP(t.Context(),
			n.owner.URL+"/owner/pw/message/send", n.auth, body, false)
		assert.NoError(result.err)
		assert.Equal(result.status, 409)
		assert.DeepEqual(try.To1(firstUseState(n.service.store.Vault())), retained)
		n.owner.Close()
		n.peer.Close()
		try.To(n.service.close())
		cmd := serveCommand(t, n.fixture)
		restarted, _ := try.To2(setupNodeServe(t.Context(), cmd))
		assert.DeepEqual(try.To1(firstUseState(restarted.store.Vault())), retained)
		try.To(restarted.close())
	}
}

func TestServeFirstUseV2RestartCannotRebindRuntime(t *testing.T) {
	for _, mode := range []string{"no listener", "different port"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			alice, bob := establishFirstUsePairV2(t)
			retained := try.To1(firstUseState(alice.service.store.Vault()))
			bobRetained := try.To1(firstUseState(bob.service.store.Vault()))
			alice.owner.Close()
			alice.peer.Close()
			try.To(alice.service.close())
			var config net.ListenConfig
			oldPort := try.To1(config.Listen(t.Context(), "tcp",
				strings.TrimPrefix(alice.peer.URL, "http://")))
			defer func() { assert.NoError(oldPort.Close()) }()
			cmd := serveCommand(t, alice.fixture)
			if mode == "different port" {
				try.To(cmd.Flags().Set("peer-listen", "127.0.0.1:0"))
			}
			restarted, _ := try.To2(setupNodeServe(t.Context(), cmd))
			defer func() { assert.NoError(restarted.close()) }()
			if mode == "different port" {
				peer := httptest.NewUnstartedServer(nil)
				restarted.configurePublication(peer.Listener)
				peer.Config.Handler = restarted.peerHandler
				peer.Start()
				defer peer.Close()
				assert.NotEqual(peer.URL, alice.peer.URL)
			} else {
				restarted.configurePublication(nil)
				assert.INil(restarted.peerHandler)
			}
			owner := httptest.NewServer(restarted.handler)
			defer owner.Close()
			result := postPeerProofHTTP(t.Context(),
				owner.URL+"/owner/pw/first-use",
				serveAuthorization(t, restarted), []byte(`{"version":2}`), false)
			assert.NoError(result.err)
			assert.Equal(result.status, 409)
			assert.DeepEqual(try.To1(firstUseState(restarted.store.Vault())), retained)
			assert.DeepEqual(try.To1(firstUseState(bob.service.store.Vault())),
				bobRetained)
		})
	}
}
