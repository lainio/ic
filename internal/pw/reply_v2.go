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

// BobReplyV2 retrieves the original committed v2 success under current local
// guards and matching holding. Hold the same owner mutation/signer lock as
// BobAcceptV2. A fresh discarded signer-usability probe occurs outside View;
// acceptance is never re-signed, rebound or written. This is also the initial
// delivery path. Release the lock before I/O; a later Deny cannot recall bytes.
// Consumed invitation expiry alone is irrelevant; current ad guards still apply.
func BobReplyV2(vault *storage.Vault, root, local key.Public, signer key.Handle,
	endpoint string, raw []byte,
) ([]byte, error) {
	return bobReplyV2(vault, root, local, signer, endpoint, raw, time.Now)
}

func bobReplyV2(vault *storage.Vault, root, local key.Public, signer key.Handle,
	endpoint string, raw []byte, now func() time.Time,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return ErrEstablishment })

	assert.NotNil(vault, ErrEstablishment)
	root, local, raw = bytes.Clone(root), bytes.Clone(local), bytes.Clone(raw)
	request := try.To1(decodeEstablishmentV2(raw, root, local))
	state := try.To1(device.InspectLocal(vault, root, local, localSigner{signer}))
	assert.That(state.Authorized && state.Usable, ErrEstablishment)

	var response []byte
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)

		row, found := try.To2(readInvitation(tx, root, local))
		assert.That(found && row.State == InvitationConsumed &&
			matchesInvitation(row, request.Payload.guardBinding()), ErrEstablishment)
		history, found := try.To2(tx.Get([]byte(acceptedKey)))
		assert.That(found && len(history) <= 2*MaxEstablishmentBytes+16,
			ErrEstablishment)
		var accepted acceptedRecord
		assert.That(wire.DecMode.Unmarshal(history, &accepted) == nil,
			ErrEstablishment)
		assert.That(accepted.Version == 2 &&
			bytes.Equal(history, try.To1(wire.Marshal(accepted))) &&
			bytes.Equal(accepted.Request, raw), ErrEstablishment)
		payload := acceptedPayloadV2(request.Payload, raw)
		try.To(verifyAcceptedV2(accepted.Response, payload))

		holding, found := try.To2(tx.Get([]byte(heldKey)))
		assert.That(found && len(holding) <= 128, ErrEstablishment)
		var held heldRecord
		assert.That(wire.DecMode.Unmarshal(holding, &held) == nil,
			ErrEstablishment)
		assert.That(held.Version == 2 &&
			bytes.Equal(holding, try.To1(wire.Marshal(held))) &&
			bytes.Equal(held.RequestDigest, payload.RequestDigest), ErrEstablishment)
		try.To1(currentEstablishmentGuards(tx, request.Payload.guardBinding(),
			endpoint, now))
		response = bytes.Clone(accepted.Response)
		return nil
	}))
	return response, nil
}
