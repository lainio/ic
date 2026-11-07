package pw

import (
	"bytes"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
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

		history := try.To1(readLocalHistoryV2(tx, root, local, false))
		assert.That(history.version == 2 && history.accepted && history.held &&
			bytes.Equal(history.request, raw), ErrEstablishment)
		try.To1(currentEstablishmentGuards(tx, request.Payload.guardBinding(),
			endpoint, now))
		response = bytes.Clone(history.response)
		return nil
	}))
	return response, nil
}
