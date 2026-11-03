package node

import (
	"encoding/hex"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/policy"
)

func TestServeDenyOwnerOnlyAndWithoutPeerListener(t *testing.T) {
	defer assert.PushTester(t)()
	alice, bob := newVerificationPair(t, true)
	const path = "/owner/policy/deny"
	body := []byte(`{"peer_public_key_hex":"` +
		hex.EncodeToString(bob.fixture.child) + `"}`)
	aBefore := try.To1(firstUseState(alice.service.store.Vault()))
	bBefore := try.To1(firstUseState(bob.service.store.Vault()))
	for _, surface := range []struct {
		url, auth string
		status    int
	}{
		{alice.owner.URL, "", 401}, {alice.owner.URL, bob.auth, 401},
		{alice.peer.URL, alice.auth, 404}, {bob.peer.URL, bob.auth, 404},
	} {
		r := postPeerProofHTTP(t.Context(), surface.url+path, surface.auth,
			body, false)
		assert.NoError(r.err)
		assert.Equal(r.status, surface.status)
	}
	assert.DeepEqual(
		try.To1(firstUseState(alice.service.store.Vault())),
		aBefore,
	)
	// The operational route also works without opting into any peer listener.
	alice.owner.Close()
	alice.peer.Close()
	try.To(alice.service.close())
	a := startVerificationNode(t, alice.fixture, false)
	assert.INil(a.service.peerHandler)
	assert.DeepEqual(try.To1(firstUseState(a.service.store.Vault())), aBefore)
	r := postPeerProofHTTP(t.Context(), a.owner.URL+path, a.auth, body, false)
	assert.NoError(r.err)
	assert.Equal(r.status, 200)
	assert.Equal(string(r.body), `{"changed":true}`)
	after := try.To1(firstUseState(a.service.store.Vault()))
	assert.SNotEmpty(after["root"]["local-denied-peers-v1"])
	delete(after["root"], "local-denied-peers-v1")
	assert.DeepEqual(after, aBefore)
	assert.DeepEqual(try.To1(firstUseState(bob.service.store.Vault())), bBefore)
	a.owner.Close()
	try.To(a.service.close())
	a = startVerificationNode(t, alice.fixture, false)
	assert.That(try.To1(policy.IsDenied(a.service.store.Vault(),
		alice.fixture.root, alice.fixture.child, bob.fixture.child)))
	r = postPeerProofHTTP(t.Context(), a.owner.URL+path, a.auth, body, false)
	assert.NoError(r.err)
	assert.Equal(r.status, 200)
	assert.Equal(string(r.body), `{"changed":false}`)
	assert.DeepEqual(try.To1(firstUseState(bob.service.store.Vault())), bBefore)
}
