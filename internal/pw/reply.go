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

// BobReply implements IntroTreePWInvitationV1.BobReply/ExactRetry. The caller
// holds the same owner mutation/signer lifecycle lock required by BobAccept.
// Authenticate the exact request, make a fresh discarded usability probe OUTSIDE
// any transaction, then validate history, holding and all durable current guards
// together in one View. No acceptance is signed or reconstructed; no Update,
// encryption consumption, bookkeeping or repair is performed.
//
// Expiry of the consumed invitation alone is irrelevant. Current ad validity
// still matters. Return bytes only after View closes; the caller must release
// its service lock before network I/O. A later Deny cannot recall these bytes.
func BobReply(vault *storage.Vault, root, local key.Public, signer key.Handle,
	endpoint string, raw []byte,
) ([]byte, error) {
	return bobReply(vault, root, local, signer, endpoint, raw, time.Now)
}

func bobReply(vault *storage.Vault, root, local key.Public, signer key.Handle,
	endpoint string, raw []byte, now func() time.Time,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return ErrEstablishment })

	assert.NotNil(vault, ErrEstablishment)
	root, local, raw = bytes.Clone(root), bytes.Clone(local), bytes.Clone(raw)
	request := try.To1(decodeEstablishment(raw, root, local))
	state := try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	assert.That(state.Authorized && state.Usable, ErrEstablishment)

	var response []byte
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)

		row, found := try.To2(readInvitation(tx, root, local))
		assert.That(found && row.State == InvitationConsumed &&
			matchesInvitation(row, request.Payload), ErrEstablishment)
		history, found := try.To2(tx.Get([]byte(acceptedKey)))
		assert.That(found && len(history) <= 2*MaxEstablishmentBytes+16,
			ErrEstablishment)
		var accepted acceptedRecord
		assert.That(wire.DecMode.Unmarshal(history, &accepted) == nil,
			ErrEstablishment)
		assert.That(accepted.Version == 1 &&
			bytes.Equal(history, try.To1(wire.Marshal(accepted))) &&
			bytes.Equal(accepted.Request, raw), ErrEstablishment)
		payload := acceptedPayload(request.Payload, raw)
		try.To(verifyAccepted(accepted.Response, payload))

		holding, found := try.To2(tx.Get([]byte(heldKey)))
		assert.That(found && len(holding) <= 128, ErrEstablishment)
		var held heldRecord
		assert.That(wire.DecMode.Unmarshal(holding, &held) == nil,
			ErrEstablishment)
		assert.That(held.Version == 1 &&
			bytes.Equal(holding, try.To1(wire.Marshal(held))) &&
			bytes.Equal(held.RequestDigest, payload.RequestDigest),
			ErrEstablishment)
		try.To1(currentEstablishmentGuards(tx, request.Payload, endpoint, now))
		response = bytes.Clone(accepted.Response)
		return nil
	}))
	return response, nil
}
