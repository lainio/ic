package pw

import (
	"bytes"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const messageSentEnvelopePurposeV2 = "pw-message-sent-envelope/v2"

// Only saveMessageTransmitV2 constructs this owned, immutable snapshot. It
// carries no Vault, signer or continuing permission. The destination is the
// authenticated historical peer origin plus the fixed application path.
type savedMessageTransmitV2 struct {
	envelope, destination string
}

// The caller holds the owner mutation/signer/configuration lock, including
// runtime, throughout. Transmit/RetryExact rechecks current local guards and
// exact saved bytes after the external signer probe and at the write boundary.
// sent records authorization only, never dispatch, admission or delivery.
// An exact permitted retry is read-only. Later failure preserves earlier
// commits; later Deny/Delete blocks new snapshots, not already authorized bytes.
func saveMessageTransmitV2(vault *storage.Vault, root, local key.Public,
	signer key.Handle, runtime ContactRuntimeV2,
) (_ savedMessageTransmitV2, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errMessageTransmit })

	assert.That(vault != nil && validPublic(root) && validPublic(local),
		errMessageTransmit)
	root, local = bytes.Clone(root), bytes.Clone(local)
	var snapshot savedMessageTransmitV2
	var saved bool
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		snapshot, saved = try.To2(
			checkMessageTransmitV2(tx, root, local, runtime),
		)
		return nil
	}))

	state := try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	assert.That(state.Authorized && state.Usable, errMessageTransmit)
	if saved {
		try.To(vault.View(func(tx storage.ReadTx) (err error) {
			defer err2.Handle(&err, nil)
			current, found := try.To2(
				checkMessageTransmitV2(tx, root, local, runtime),
			)
			assert.That(found && current == snapshot, errMessageTransmit)
			return nil
		}))
	} else {
		updateErr := vault.Update(func(tx storage.WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			return commitMessageTransmitV2(tx, root, local, runtime, snapshot)
		})
		if updateErr != errSentUnchanged {
			try.To(updateErr)
		}
	}
	return snapshot, nil
}

func commitMessageTransmitV2(tx storage.WriteTx, root, local key.Public,
	runtime ContactRuntimeV2, expected savedMessageTransmitV2,
) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	current, saved := try.To2(checkMessageTransmitV2(tx, root, local, runtime))
	assert.That(current == expected, errMessageTransmit)
	if saved {
		return errSentUnchanged // Abort backend bookkeeping too; no seal.
	}
	digest := key.HashTagged(messageSentEnvelopePurposeV2,
		[]byte(current.envelope))
	raw := try.To1(wire.Marshal(messageSent{
		Version: 2, EnvelopeDigest: digest[:],
	}))
	assert.That(len(raw) <= maxMessageSentBytes, errMessageTransmit)
	return tx.Put([]byte(messageSentKey), raw)
}

func checkMessageTransmitV2(tx storage.ReadTx, root, local key.Public,
	runtime ContactRuntimeV2,
) (_ savedMessageTransmitV2, _ bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	binding, history := try.To2(outgoingHistoryV2(tx, root, local))
	try.To(firstUseGuardsV2(tx, history, runtime, binding.Requester))
	message := try.To1(readEnvelopeMessageV2(tx, binding))
	envelope := try.To1(readMessageEnvelopeV2(tx, binding, message))
	assert.That(envelope != nil, errMessageTransmit)
	destination := history.peerContact(binding.Requester) + messagePath
	assert.That(validMessageURL(destination), errMessageTransmit)
	snapshot := savedMessageTransmitV2{string(envelope), destination}

	raw, found := try.To2(tx.Get([]byte(messageSentKey)))
	if !found {
		return snapshot, false, nil
	}
	assert.That(len(raw) > 0 && len(raw) <= maxMessageSentBytes,
		errMessageTransmit)
	var record messageSent
	assert.That(wire.DecMode.Unmarshal(raw, &record) == nil,
		errMessageTransmit)
	digest := key.HashTagged(messageSentEnvelopePurposeV2, envelope)
	assert.That(record.Version == 2 &&
		bytes.Equal(raw, try.To1(wire.Marshal(record))) &&
		bytes.Equal(record.EnvelopeDigest, digest[:]), errMessageTransmit)
	return snapshot, true, nil
}
