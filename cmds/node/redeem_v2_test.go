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
	"github.com/lainio/ic/internal/pw"
)

func TestServeRequesterV2BoundOriginsAndRestartConflict(t *testing.T) {
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
		"version":               2,
		"target_public_key_hex": hex.EncodeToString(bob.fixture.child),
		"invitation_id_hex": hex.EncodeToString(
			row.ID,
		), "audience": "Any",
	}))
	const path = "/owner/pw/invitations/redeem"
	beforeAlice := try.To1(
		verificationUnrelatedState(alice.service.store.Vault()),
	)
	beforeBob := try.To1(verificationUnrelatedState(bob.service.store.Vault()))
	result := postPeerProofHTTP(t.Context(), alice.owner.URL+path,
		alice.auth, body, false)
	assert.NoError(result.err)
	assert.Equal(result.status, 200)
	assert.Equal(
		string(result.body),
		`{"acceptance_saved":true,"local_held":true}`,
	)
	assert.Equal(try.To1(pw.RequesterContactV2(alice.service.store.Vault(),
		alice.fixture.root, alice.fixture.child)), bob.peer.URL)
	assert.Equal(try.To1(pw.BobContactV2(bob.service.store.Vault(),
		bob.fixture.root, bob.fixture.child)), alice.peer.URL)
	afterAlice := try.To1(
		verificationUnrelatedState(alice.service.store.Vault()),
	)
	afterBob := try.To1(verificationUnrelatedState(bob.service.store.Vault()))
	for _, name := range []string{"local-pw-accepted-v1", "local-pw-held-v1"} {
		assert.SNotEmpty(afterAlice["root"][name])
		assert.DeepEqual(afterAlice["root"][name], afterBob["root"][name])
		delete(afterAlice["root"], name)
		delete(afterBob["root"], name)
	}
	delete(afterAlice["root"], "local-pw-attempt-v1")
	afterBob["root"]["local-pw-invitation-v1"] =
		beforeBob["root"]["local-pw-invitation-v1"]
	assert.DeepEqual(afterAlice, beforeAlice)
	assert.DeepEqual(
		afterBob,
		beforeBob,
	) // No first use, message, pipe or Trust.

	retained := try.To1(
		verificationUnrelatedState(alice.service.store.Vault()),
	)
	alice.owner.Close()
	alice.peer.Close()
	try.To(alice.service.close())
	// Occupy the old port so this restart necessarily selects a different one.
	var config net.ListenConfig
	oldPort := try.To1(config.Listen(t.Context(), "tcp",
		strings.TrimPrefix(alice.peer.URL, "http://")))
	defer func() { assert.NoError(oldPort.Close()) }()
	cmd := serveCommand(t, alice.fixture)
	try.To(cmd.Flags().Set("peer-listen", "127.0.0.1:0"))
	restarted, _ := try.To2(setupNodeServe(t.Context(), cmd))
	defer func() { assert.NoError(restarted.close()) }()
	peer := httptest.NewUnstartedServer(nil)
	restarted.configurePublication(peer.Listener)
	peer.Config.Handler = restarted.peerHandler
	peer.Start()
	defer peer.Close()
	owner := httptest.NewServer(restarted.handler)
	defer owner.Close()
	assert.NotEqual(peer.URL, alice.peer.URL)
	result = postPeerProofHTTP(t.Context(), owner.URL+path,
		serveAuthorization(t, restarted), body, false)
	assert.NoError(result.err)
	assert.Equal(result.status, 409)
	assert.DeepEqual(try.To1(verificationUnrelatedState(
		restarted.store.Vault())), retained)
}
