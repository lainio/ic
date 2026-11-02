package node

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
)

const peerEstablishmentPath = "/peer/pw/establish"

func TestServeEstablishmentPeerOnly(t *testing.T) {
	defer assert.PushTester(t)()
	alice, bob := newVerificationPair(t, true)
	issued := postPeerProofHTTP(t.Context(),
		bob.owner.URL+"/owner/pw/invitations/issue", bob.auth,
		[]byte(`{"recipient_public_key_hex":null}`), false)
	assert.NoError(issued.err)
	assert.Equal(issued.status, 200)
	row, found := try.To2(pw.ReadInvitation(bob.service.store.Vault(),
		bob.fixture.root, bob.fixture.child))
	assert.That(found)
	request := pw.SignedEstablishment{Payload: pw.Establishment{
		Version: 1, Root: bob.fixture.root, Requester: alice.fixture.child,
		Target: bob.fixture.child, InvitationID: row.ID, Audience: row.Audience,
		AttemptID: bytes.Repeat([]byte{63}, 32), Device: alice.fixture.child,
		Ad: bob.ad,
	}}
	signer := try.To1(nodeidentity.OpenDirectory(alice.fixture.dir,
		alice.fixture.unlock))
	digest := key.HashTagged(pw.EstablishPurpose,
		try.To1(wire.Marshal(request.Payload)))
	request.Signature = try.To1(signer.Sign(digest[:]))
	raw := try.To1(wire.Marshal(request))
	body := try.To1(json.Marshal(struct {
		Version int    `json:"version"`
		Request []byte `json:"request"`
	}{1, raw}))
	beforeAlice := try.To1(
		verificationUnrelatedState(alice.service.store.Vault()),
	)
	beforeBob := try.To1(verificationUnrelatedState(bob.service.store.Vault()))
	for _, auth := range []string{"", bob.auth, alice.auth} {
		result := postPeerProofHTTP(
			t.Context(),
			bob.owner.URL+peerEstablishmentPath,
			auth,
			body,
			false,
		)
		assert.NoError(result.err)
		assert.Equal(result.status, 404)
	}
	result := postPeerProofHTTP(t.Context(), bob.peer.URL+peerEstablishmentPath,
		"", body, true)
	assert.NoError(result.err)
	assert.Equal(result.status, 200)
	var reply struct {
		Version    int
		Acceptance []byte
	}
	try.To(json.Unmarshal(result.body, &reply))
	assert.Equal(reply.Version, 1)
	var response pw.SignedAccepted
	try.To(wire.UnmarshalCanonical(&response, reply.Acceptance))
	assert.DeepEqual(response.Payload.Binding, request.Payload)
	digest = key.HashTagged(pw.AcceptedPurpose,
		try.To1(wire.Marshal(response.Payload)))
	assert.That(response.Signature.Verify(bob.fixture.child, digest[:]))
	retry := postPeerProofHTTP(t.Context(), bob.peer.URL+peerEstablishmentPath,
		"", body, false)
	assert.NoError(retry.err)
	assert.Equal(retry.status, 200)
	assert.DeepEqual(retry.body, result.body)
	assert.DeepEqual(
		try.To1(verificationUnrelatedState(alice.service.store.Vault())),
		beforeAlice,
	)
	afterBob := try.To1(verificationUnrelatedState(bob.service.store.Vault()))
	assert.SNotEmpty(afterBob["root"]["local-pw-accepted-v1"])
	assert.SNotEmpty(afterBob["root"]["local-pw-held-v1"])
	delete(afterBob["root"], "local-pw-accepted-v1")
	delete(afterBob["root"], "local-pw-held-v1")
	afterBob["root"]["local-pw-invitation-v1"] =
		beforeBob["root"]["local-pw-invitation-v1"]
	assert.DeepEqual(
		afterBob,
		beforeBob,
	) // No Trust, open state or other writes.

	bob.owner.Close()
	bob.peer.Close()
	try.To(bob.service.close())
	disabled := startVerificationNode(t, bob.fixture, false)
	assert.INil(disabled.service.peerHandler)
	for _, auth := range []string{"", disabled.auth} {
		result := postPeerProofHTTP(t.Context(),
			disabled.owner.URL+peerEstablishmentPath, auth, body, false)
		assert.NoError(result.err)
		assert.Equal(result.status, 404)
	}
}
