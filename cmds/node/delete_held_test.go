package node

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/pw"
)

func TestServeDeleteHeldOwnerOnlyAndWithoutPeerListener(t *testing.T) {
	defer assert.PushTester(t)()
	alice, bob := newVerificationPair(t, true)
	assertAdVerification(t, alice.verify(t.Context(), bob.fixture.child),
		bob.fixture.child, true)
	row := try.To1(
		pw.IssueInvitation(bob.service.store.Vault(), bob.fixture.root,
			bob.fixture.child, alice.fixture.child),
	)
	body := try.To1(json.Marshal(map[string]string{
		"target_public_key_hex": hex.EncodeToString(bob.fixture.child),
		"invitation_id_hex": hex.EncodeToString(
			row.ID,
		), "audience": row.Audience,
	}))
	redeemed := postPeerProofHTTP(t.Context(),
		alice.owner.URL+"/owner/pw/invitations/redeem", alice.auth, body, false)
	assert.NoError(redeemed.err)
	assert.Equal(redeemed.status, 200)
	const path = "/owner/pw/holding/delete"
	aBefore := try.To1(firstUseState(alice.service.store.Vault()))
	bBefore := try.To1(firstUseState(bob.service.store.Vault()))
	for _, surface := range []struct {
		url, auth string
		status    int
	}{
		{alice.owner.URL, "", 401}, {alice.owner.URL, bob.auth, 401},
		{alice.peer.URL, alice.auth, 404}, {bob.peer.URL, bob.auth, 404},
	} {
		r := postPeerProofHTTP(
			t.Context(),
			surface.url+path,
			surface.auth,
			[]byte("{}"),
			false,
		)
		assert.NoError(r.err)
		assert.Equal(r.status, surface.status)
	}
	assert.DeepEqual(
		try.To1(firstUseState(alice.service.store.Vault())),
		aBefore,
	)
	assert.DeepEqual(try.To1(firstUseState(bob.service.store.Vault())), bBefore)
	// Restart the actual node serve composition without --peer-listen. Setup
	// restores the holding; only the authenticated explicit POST removes it.
	for _, n := range []*verificationNode{alice, bob} {
		n.owner.Close()
		n.peer.Close()
		try.To(n.service.close())
	}
	a := startVerificationNode(t, alice.fixture, false)
	b := startVerificationNode(t, bob.fixture, false)
	assert.INil(a.service.peerHandler)
	assert.INil(b.service.peerHandler)
	assert.Empty(a.service.peerAddress)
	assert.Empty(b.service.peerAddress)
	assert.DeepEqual(try.To1(firstUseState(a.service.store.Vault())), aBefore)
	assert.DeepEqual(try.To1(firstUseState(b.service.store.Vault())), bBefore)
	for _, n := range []*verificationNode{a, b} {
		before := try.To1(firstUseState(n.service.store.Vault()))
		r := postPeerProofHTTP(
			t.Context(),
			n.owner.URL+path,
			n.auth,
			[]byte("{}"),
			false,
		)
		assert.NoError(r.err)
		assert.Equal(r.status, 200)
		assert.Equal(string(r.body), `{"deleted":true}`)
		delete(before["root"], "local-pw-held-v1")
		assert.DeepEqual(
			try.To1(firstUseState(n.service.store.Vault())),
			before,
		)
		if n == a {
			assert.DeepEqual(
				try.To1(firstUseState(b.service.store.Vault())),
				bBefore,
			)
		}
		r = postPeerProofHTTP(
			t.Context(),
			n.owner.URL+path,
			n.auth,
			[]byte("{}"),
			false,
		)
		assert.NoError(r.err)
		assert.Equal(r.status, 200)
		assert.Equal(string(r.body), `{"deleted":false}`)
	}
}
