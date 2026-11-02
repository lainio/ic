package node

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/pw"
)

// Exercise the actual node serve setup and both HTTP listeners with a restored
// identity and nodevault, then restart with fresh credentials and the same row.
func TestServeInvitationOwnerOnlyAndRestart(t *testing.T) {
	defer assert.PushTester(t)()
	f := prepareServeFixture(t)
	n := startVerificationNode(t, f, true)
	const issue = "/owner/pw/invitations/issue"
	const revoke = "/owner/pw/invitations/revoke"
	body := []byte(`{"recipient_public_key_hex":null}`)
	_, found := try.To2(
		pw.ReadInvitation(n.service.store.Vault(), f.root, f.child),
	)
	assert.ThatNot(found) // Startup, bootstrap and a real ad did not issue.
	for _, path := range []string{issue, revoke} {
		for _, auth := range []string{"", n.auth} {
			result := postPeerProofHTTP(
				t.Context(),
				n.peer.URL+path,
				auth,
				body,
				false,
			)
			assert.NoError(result.err)
			assert.Equal(result.status, 404)
		}
		result := postPeerProofHTTP(
			t.Context(),
			n.owner.URL+path,
			"",
			body,
			false,
		)
		assert.NoError(result.err)
		assert.Equal(result.status, 401)
	}
	result := postPeerProofHTTP(
		t.Context(),
		n.owner.URL+issue,
		n.auth,
		body,
		true,
	)
	assert.NoError(result.err)
	assert.Equal(result.status, 200)
	var reply struct {
		ID string `json:"invitation_id_hex"`
	}
	try.To(json.Unmarshal(result.body, &reply))
	id := try.To1(hex.DecodeString(reply.ID))
	row, found := try.To2(
		pw.ReadInvitation(n.service.store.Vault(), f.root, f.child),
	)
	assert.That(found)
	assert.DeepEqual(row.ID, id)
	oldAuth := n.auth
	n.owner.Close()
	n.peer.Close()
	try.To(n.service.close())

	n = startVerificationNode(t, f, false) // No peer listener is needed.
	got, found := try.To2(
		pw.ReadInvitation(n.service.store.Vault(), f.root, f.child),
	)
	assert.That(found)
	assert.DeepEqual(got, row)
	result = postPeerProofHTTP(
		t.Context(),
		n.owner.URL+issue,
		oldAuth,
		body,
		false,
	)
	assert.NoError(result.err)
	assert.Equal(result.status, 401)
	result = postPeerProofHTTP(
		t.Context(),
		n.owner.URL+issue,
		n.auth,
		body,
		false,
	)
	assert.NoError(result.err)
	assert.Equal(result.status, 409)
	result = postPeerProofHTTP(t.Context(), n.owner.URL+revoke, n.auth,
		[]byte(`{"invitation_id_hex":"`+reply.ID+`"}`), true)
	assert.NoError(result.err)
	assert.Equal(result.status, 200)
	assert.Equal(string(result.body), `{"revoked":true}`)
	row.State = pw.InvitationRevoked
	n.owner.Close()
	try.To(n.service.close())
	n = startVerificationNode(t, f, false)
	got, found = try.To2(
		pw.ReadInvitation(n.service.store.Vault(), f.root, f.child),
	)
	assert.That(found)
	assert.DeepEqual(got, row)
}
