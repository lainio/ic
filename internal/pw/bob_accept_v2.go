package pw

import (
	"bytes"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// BobAcceptV2 commits only Bob's contact-bound held half. The caller supplies
// an independently Root/local-bound Vault and the bound listener endpoint, and
// MUST hold the same owner mutation/signer lock as BobAccept. It remains unwired
// to HTTP. Signing occurs outside Update; all durable guards are reread in TX-B,
// serialized with revocation and policy/deletion. Delivery requires BobReplyV2.
//
// Alice's contact is only her authenticated assertion. Its historical value
// lives in the immutable signed request/result, never a mutable contact row.
// The shared accepted/held keys use version-2 envelopes; the invitation stays
// version 1. No migration, peer Vault access, first use or Trust is involved.
func BobAcceptV2(vault *storage.Vault, root, local key.Public, signer key.Handle,
	endpoint string, raw []byte,
) error {
	return bobAcceptV2(vault, root, local, signer, endpoint, raw, time.Now)
}

func bobAcceptV2(vault *storage.Vault, root, local key.Public, signer key.Handle,
	endpoint string, raw []byte, now func() time.Time,
) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return ErrEstablishment })

	assert.NotNil(vault, ErrEstablishment)
	root, local, raw = bytes.Clone(root), bytes.Clone(local), bytes.Clone(raw)
	request := try.To1(decodeEstablishmentV2(raw, root, local))
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		try.To(noFirstUseV2(tx))
		try.To1(newRedemption(tx, request.Payload.guardBinding(), endpoint, now))
		return nil
	}))
	state := try.To1(device.InspectLocal(vault, root, local, localSigner{signer}))
	assert.That(state.Authorized && state.Usable, ErrEstablishment)
	payload := acceptedPayloadV2(request.Payload, raw)
	digest := key.HashTagged(AcceptedPurposeV2, try.To1(wire.Marshal(payload)))
	signature := try.To1((localSigner{signer}).Sign(bytes.Clone(digest[:])))
	response := try.To1(wire.Marshal(SignedAcceptedV2{
		Payload: payload, Signature: bytes.Clone(signature),
	}))
	try.To(verifyAcceptedV2(response, payload))
	return vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return commitAcceptanceV2(tx, root, local, endpoint, raw, response, now)
	})
}

func commitAcceptanceV2(tx storage.WriteTx, root, local key.Public,
	endpoint string, raw, response []byte, now func() time.Time,
) (err error) {
	defer err2.Handle(&err, nil)

	request := try.To1(decodeEstablishmentV2(raw, root, local))
	payload := acceptedPayloadV2(request.Payload, raw)
	try.To(verifyAcceptedV2(response, payload))
	try.To(noFirstUseV2(tx))
	// Authentication binds TargetContact to the signed ad's canonical origin;
	// newRedemption requires that exact ad to be Bob's own current publication
	// at the bound listener. The projection is used only for shared guards.
	row := try.To1(newRedemption(tx, request.Payload.guardBinding(), endpoint, now))
	row.State = InvitationConsumed
	try.To(tx.Put([]byte(invitationKey), try.To1(wire.Marshal(row))))
	try.To(tx.Put([]byte(acceptedKey), try.To1(wire.Marshal(acceptedRecord{
		Version: 2, Request: raw, Response: response,
	}))))
	return tx.Put([]byte(heldKey), try.To1(wire.Marshal(heldRecord{
		Version: 2, RequestDigest: payload.RequestDigest,
	})))
}
