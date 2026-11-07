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

// ReceiveAcceptanceV2 commits Alice's half using only her exact saved signed
// request and the received canonical v2 acceptance. Root/local and Vault are
// independently pinned by the owner/service caller. Hold the same mutation,
// configuration and signer lock as SaveAttemptV2 across this call. Probe outside
// transactions, then revalidate exact evidence and durable guards in TX-A.
//
// An exact duplicate is read-only, subject to Alice's current guards, and
// returns her current holding; it cannot undo Delete. No peer Vault, callback,
// transport, first use, PWOpen or Trust is involved. Errors are sanitized.
func ReceiveAcceptanceV2(vault *storage.Vault, root, local key.Public,
	signer key.Handle, response []byte,
) (bool, error) {
	return receiveAcceptanceV2(vault, root, local, signer, response, time.Now)
}

func receiveAcceptanceV2(vault *storage.Vault, root, local key.Public,
	signer key.Handle, response []byte, now func() time.Time,
) (_ bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return ErrEstablishment })

	assert.NotNil(vault, ErrEstablishment)
	root, local = bytes.Clone(root), bytes.Clone(local)
	response = bytes.Clone(response)
	var saved localHistoryV2
	read := func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		saved = try.To1(checkRequesterAcceptanceV2(tx, root, local, response, now))
		return nil
	}
	try.To(vault.View(read))
	state := try.To1(device.InspectLocal(vault, root, local, localSigner{signer}))
	assert.That(state.Authorized && state.Usable, ErrEstablishment)
	if saved.accepted {
		try.To(vault.View(read))
		return saved.held, nil
	}
	updateErr := vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		saved = try.To1(commitRequesterAcceptanceV2(tx, root, local, response, now))
		if saved.accepted {
			return errRequesterUnchanged
		}
		return nil
	})
	if updateErr == errRequesterUnchanged {
		return saved.held, nil
	}
	try.To(updateErr)
	return true, nil
}

func checkRequesterAcceptanceV2(tx storage.ReadTx, root, local key.Public,
	response []byte, now func() time.Time,
) (_ localHistoryV2, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)
	saved := try.To1(readLocalHistoryV2(tx, root, local, true))
	assert.That(saved.version == 2 && saved.request != nil, ErrEstablishment)
	try.To(verifyAcceptedV2(response,
		acceptedPayloadV2(saved.binding, saved.request)))
	assert.That(!saved.accepted || bytes.Equal(saved.response, response),
		ErrEstablishment)
	try.To1(requesterGuards(tx, saved.binding.guardBinding(), now))
	return saved, nil
}

func commitRequesterAcceptanceV2(tx storage.WriteTx, root, local key.Public,
	response []byte, now func() time.Time,
) (_ localHistoryV2, err error) {
	defer err2.Handle(&err, nil)
	saved := try.To1(checkRequesterAcceptanceV2(tx, root, local, response, now))
	if saved.accepted {
		return saved, nil
	}
	digest := key.HashTagged(requestPurposeV2, saved.request)
	try.To(tx.Put([]byte(acceptedKey), try.To1(wire.Marshal(acceptedRecord{
		Version: 2, Request: saved.request, Response: response,
	}))))
	try.To(tx.Put([]byte(heldKey), try.To1(wire.Marshal(heldRecord{
		Version: 2, RequestDigest: digest[:],
	}))))
	return saved, nil
}
