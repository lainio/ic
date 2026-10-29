package ownerapi

import (
	"bytes"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
)

// LocalAcceptanceProver grants only a momentary, purpose-bound response for an
// authenticated requester and consumed listener challenge. The peer boundary
// must verify requester key possession and consume its exact ad-bound nonce
// first. This capability owns the installed signer and service mutation lock;
// it grants no raw signing, policy mutation, bootstrap or durable PW authority.
type LocalAcceptanceProver func(requester key.Public,
	expectedAd, nonce []byte,
) (key.Signature, error)

func (h *publicationHandler) proveLocalAcceptance(requester key.Public,
	expectedAd, nonce []byte,
) (_ key.Signature, err error) {
	defer err2.Handle(&err, nil)

	requester = bytes.Clone(requester)
	expectedAd, nonce = bytes.Clone(expectedAd), bytes.Clone(nonce)
	h.mutations.Lock()
	defer h.mutations.Unlock()

	// The ledger lock is already released. Publication, bootstrap, Known
	// writes and peer proofs share this mutex; no HTTP I/O or Vault transaction
	// spans these signing calls. External policy/signer changes must also be
	// serialized by the service, as required by ProveLocalAcceptance.
	try.To(h.requireAcceptanceAd(expectedAd))
	proof := try.To1(pw.ProveLocalAcceptance(h.vault, h.root, h.child,
		requester, h.signer, nonce))
	// Use a fresh clock read so expiration during signing fails closed too.
	try.To(h.requireAcceptanceAd(expectedAd))
	return proof, nil
}

func (h *publicationHandler) requireAcceptanceAd(expectedAd []byte) (err error) {
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()

	assert.That(h.endpoint != "", ads.ErrNotCurrent)
	current, found := try.To2(ads.ReadCurrentLocal(
		h.vault, h.root, h.child, time.Now()))
	assert.That(found && current.Payload.PeerIntroductionURL == h.endpoint,
		ads.ErrNotCurrent)
	assert.That(bytes.Equal(try.To1(wire.Marshal(current)), expectedAd),
		ads.ErrNotCurrent)
	return nil
}
