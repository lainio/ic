package node

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/pw"
)

func TestServeRequesterIndependentHolding(t *testing.T) {
	defer assert.PushTester(t)()
	alice, bob := newVerificationPair(t, true)
	assertAdVerification(
		t,
		alice.verify(t.Context(), bob.fixture.child),
		bob.fixture.child,
		true,
	)
	issued := postPeerProofHTTP(
		t.Context(),
		bob.owner.URL+"/owner/pw/invitations/issue",
		bob.auth,
		[]byte(`{"recipient_public_key_hex":null}`),
		false,
	)
	assert.NoError(issued.err)
	assert.Equal(issued.status, 200)
	row, _ := try.To2(
		pw.ReadInvitation(
			bob.service.store.Vault(),
			bob.fixture.root,
			bob.fixture.child,
		),
	)
	body := try.To1(json.Marshal(map[string]string{
		"target_public_key_hex": hex.EncodeToString(bob.fixture.child),
		"invitation_id_hex":     hex.EncodeToString(row.ID), "audience": "Any",
	}))
	const path = "/owner/pw/invitations/redeem"
	for _, surface := range []struct {
		url, auth string
		code      int
	}{
		{alice.owner.URL, "", 401}, {alice.owner.URL, bob.auth, 401},
		{alice.peer.URL, alice.auth, 404}, {bob.peer.URL, bob.auth, 404},
	} {
		result := postPeerProofHTTP(
			t.Context(),
			surface.url+path,
			surface.auth,
			body,
			false,
		)
		assert.NoError(result.err)
		assert.Equal(result.status, surface.code)
	}
	beforeAlice := try.To1(
		verificationUnrelatedState(alice.service.store.Vault()),
	)
	result := postPeerProofHTTP(
		t.Context(),
		alice.owner.URL+path,
		alice.auth,
		body,
		false,
	)
	assert.NoError(result.err)
	assert.Equal(result.status, 200)
	assert.Equal(
		string(result.body),
		`{"acceptance_saved":true,"local_held":true}`,
	)
	afterAlice := try.To1(
		verificationUnrelatedState(alice.service.store.Vault()),
	)
	afterBob := try.To1(verificationUnrelatedState(bob.service.store.Vault()))
	assert.SNotEmpty(afterAlice["root"]["local-pw-attempt-v1"])
	for _, name := range []string{"local-pw-accepted-v1", "local-pw-held-v1"} {
		assert.SNotEmpty(afterAlice["root"][name])
		assert.DeepEqual(afterAlice["root"][name], afterBob["root"][name])
		delete(afterAlice["root"], name)
	}
	delete(afterAlice["root"], "local-pw-attempt-v1")
	assert.DeepEqual(
		afterAlice,
		beforeAlice,
	) // No ad, Known, Trust or pipe changes.
	// Restart Alice without a peer listener; retained success needs no peer I/O.
	alice.owner.Close()
	alice.peer.Close()
	try.To(alice.service.close())
	restarted := startVerificationNode(t, alice.fixture, false)
	assert.INil(restarted.service.peerHandler)
	result = postPeerProofHTTP(
		t.Context(),
		restarted.owner.URL+path,
		restarted.auth,
		body,
		false,
	)
	assert.NoError(result.err)
	assert.Equal(result.status, 200)
}
