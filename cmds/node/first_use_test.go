package node

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/storage"
)

func TestServeFirstUseOnlyExplicitOwnerAndOptInPeer(t *testing.T) {
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
	redeemed := postPeerProofHTTP(
		t.Context(),
		alice.owner.URL+"/owner/pw/invitations/redeem",
		alice.auth,
		body,
		false,
	)
	assert.NoError(redeemed.err)
	assert.Equal(redeemed.status, 200)
	beforeAlice := try.To1(
		firstUseState(alice.service.store.Vault()),
	)
	beforeBob := try.To1(firstUseState(bob.service.store.Vault()))
	assert.SNil(beforeAlice["root"]["local-pw-first-use-v1"])
	assert.SNil(beforeBob["root"]["local-pw-use-seen-v1"])
	const ownerPath, peerPath = "/owner/pw/first-use", "/peer/pw/first-use"
	for _, surface := range []struct {
		url, path, auth string
		status          int
	}{
		{alice.owner.URL, ownerPath, "", 401},
		{alice.owner.URL, ownerPath, bob.auth, 401},
		{alice.peer.URL, ownerPath, alice.auth, 404},
		{bob.peer.URL, ownerPath, bob.auth, 404},
		{bob.owner.URL, peerPath, "", 404},
		{bob.owner.URL, peerPath, bob.auth, 404},
	} {
		result := postPeerProofHTTP(
			t.Context(),
			surface.url+surface.path,
			surface.auth,
			[]byte("{}"),
			false,
		)
		assert.NoError(result.err)
		assert.Equal(result.status, surface.status)
	}
	result := postPeerProofHTTP(
		t.Context(),
		alice.owner.URL+ownerPath,
		alice.auth,
		[]byte("{}"),
		false,
	)
	assert.NoError(result.err)
	assert.Equal(result.status, 200)
	assert.Equal(string(result.body), `{"local_ready":true}`)
	afterAlice := try.To1(
		firstUseState(alice.service.store.Vault()),
	)
	afterBob := try.To1(firstUseState(bob.service.store.Vault()))
	var record struct {
		_                 struct{} `cbor:",toarray"`
		Version           uint8
		State             string
		Request, Response []byte
	}
	try.To(
		wire.UnmarshalCanonical(
			&record,
			afterAlice["root"]["local-pw-first-use-v1"],
		),
	)
	assert.Equal(record.State, "Ready")
	var receipt struct {
		_                 struct{} `cbor:",toarray"`
		Version           uint8
		Request, Response []byte
	}
	try.To(
		wire.UnmarshalCanonical(
			&receipt,
			afterBob["root"]["local-pw-use-seen-v1"],
		),
	)
	assert.DeepEqual(receipt.Request, record.Request)
	assert.DeepEqual(receipt.Response, record.Response)
	delete(afterAlice["root"], "local-pw-first-use-v1")
	delete(afterBob["root"], "local-pw-use-seen-v1")
	// Whole logical state: no Trust/PWOpen, ad, Known, acceptance, holding,
	// device or invitation changes beyond the two named local observations.
	assert.DeepEqual(afterAlice, beforeAlice)
	assert.DeepEqual(afterBob, beforeBob)
	bob.owner.Close()
	bob.peer.Close()
	try.To(bob.service.close())
	disabled := startVerificationNode(t, bob.fixture, false)
	assert.INil(disabled.service.peerHandler)
	for _, auth := range []string{"", disabled.auth} {
		result := postPeerProofHTTP(
			t.Context(),
			disabled.owner.URL+peerPath,
			auth,
			[]byte("{}"),
			false,
		)
		assert.NoError(result.err)
		assert.Equal(result.status, 404)
	}
}

// Include the historical VerifiedAd too; the older verification fixture
// intentionally excludes it because those tests change it.
func firstUseState(v *storage.Vault) (_ map[string]map[string][]byte, err error) {
	defer err2.Handle(&err, nil)
	records := try.To1(verificationUnrelatedState(v))
	try.To(v.View(func(tx storage.ReadTx) error {
		return tx.Each(func(k, value []byte) error {
			records["root"][string(k)] = value
			return nil
		})
	}))
	return records, nil
}
