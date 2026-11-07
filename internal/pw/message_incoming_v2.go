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

// AdmitIncomingEnvelopeV2 implements receiver-local AcceptIncoming. The caller
// MUST hold its owner mutation/signer/configuration lock throughout, including
// reentrant signer lifecycle and runtime changes (ContactRuntimeV2 discipline).
// Supply independently pinned Root/local identities, their already-bound Vault
// and installed signer. Untrusted exact envelope bytes are bounded and copied
// before callbacks; callers must not mutate inputs concurrently with this call.
//
// True means one inbox commit completed. False with nil error is a currently
// permitted exact retry with no write or seal. The shared v1 inboxKey retains a
// canonical inboxMessage with Version 2; v1 data is never migrated or replaced.
// No plaintext, notification, ACK, peer observation or remote permission is
// returned. Errors return false and make no durability claim: inspect on a later
// explicit call, never automatically retry. Receipt signing is separate.
func AdmitIncomingEnvelopeV2(vault *storage.Vault, root, local key.Public,
	signer key.Handle, runtime ContactRuntimeV2, raw []byte,
) (_ bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errIncoming })

	assert.That(vault != nil && validPublic(root) && validPublic(local) &&
		len(raw) > 0 && len(raw) <= maxMessageEnvelopeBytes, errIncoming)
	root, local, raw = bytes.Clone(root), bytes.Clone(local), bytes.Clone(raw)
	var saved bool
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		saved = try.To1(checkIncomingV2(tx, root, local, runtime, raw))
		return nil
	}))

	state := try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	assert.That(state.Authorized && state.Usable, errIncoming)
	if saved {
		try.To(vault.View(func(tx storage.ReadTx) (err error) {
			defer err2.Handle(&err, nil)
			assert.That(
				try.To1(checkIncomingV2(tx, root, local, runtime, raw)),
				errIncoming,
			)
			return nil
		}))
		return false, nil
	}

	updateErr := vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return commitIncomingV2(tx, root, local, runtime, raw)
	})
	if updateErr == errInboxUnchanged {
		return false, nil
	}
	try.To(updateErr)
	return true, nil
}

func commitIncomingV2(tx storage.WriteTx, root, local key.Public,
	runtime ContactRuntimeV2, raw []byte,
) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	// Reauthenticate receiver history, current guards, the exact envelope and
	// any singleton row together. No signer callback runs in this transaction.
	if try.To1(checkIncomingV2(tx, root, local, runtime, raw)) {
		return errInboxUnchanged // Abort even backend bookkeeping; no seal.
	}
	record := try.To1(wire.Marshal(inboxMessage{Version: 2, Envelope: raw}))
	assert.That(len(record) <= maxInboxBytes, errIncoming)
	return tx.Put([]byte(inboxKey), record)
}

func incomingPrerequisitesV2(tx storage.ReadTx, root, local key.Public,
	runtime ContactRuntimeV2,
) (_ outgoingBindingV2, err error) {
	defer err2.Handle(&err, nil)

	// This receiver's own authenticated acceptance and historical Ready/useSeen
	// choose the relationship. The input never selects a key, peer or role.
	// Check current LOCAL guards and own signed contact before reversing the
	// orientation. No outgoing row, fresh ad or current peer policy is needed.
	binding := try.To1(outgoingPrerequisitesV2(tx, root, local, runtime))
	binding.Sender, binding.Receiver = binding.Receiver, binding.Sender
	binding.Requester = !binding.Requester
	return binding, nil
}

func checkIncomingV2(tx storage.ReadTx, root, local key.Public,
	runtime ContactRuntimeV2, raw []byte,
) (_ bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	binding := try.To1(incomingPrerequisitesV2(tx, root, local, runtime))
	try.To1(decodeMessageEnvelopeV2(raw, binding))
	saved, found := try.To2(tx.Get([]byte(inboxKey)))
	if !found {
		return false, nil
	}
	assert.That(len(saved) > 0 && len(saved) <= maxInboxBytes, errIncoming)
	var record inboxMessage
	assert.That(wire.DecMode.Unmarshal(saved, &record) == nil, errIncoming)
	assert.That(record.Version == 2 &&
		bytes.Equal(saved, try.To1(wire.Marshal(record))), errIncoming)
	try.To1(decodeMessageEnvelopeV2(record.Envelope, binding))
	assert.That(bytes.Equal(record.Envelope, raw), errIncoming)
	return true, nil
}
