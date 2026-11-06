package pw

import (
	"bytes"
	"errors"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const (
	inboxKey      = "local-pw-message-inbox-v1"
	maxInboxBytes = maxMessageEnvelopeBytes + 16
)

var (
	errIncoming       = errors.New("local incoming message refused")
	errInboxUnchanged = errors.New("local inbox unchanged")
)

// One immutable receiver-local row retains the exact authenticated wire bytes,
// including the signature. Re-signing the same message is not an exact retry.
type inboxMessage struct {
	_        struct{} `cbor:",toarray"`
	Version  uint8
	Envelope []byte
}

// admitIncomingEnvelope projects only candidate PW-Msg-02 AcceptIncoming. The
// caller MUST hold this node's existing owner mutation/signer lock throughout,
// supplying independently pinned Root/local identities, their already-bound
// Vault and installed signer. Input bytes are untrusted and copied before any
// callback; callers must not mutate them concurrently with this call.
//
// True means one receiver-local inbox commit completed. False with nil error
// means an exact, currently permitted read-only retry. Neither outcome returns
// plaintext, an ACK, remote permission, transmission or a live pipe. An error
// cannot establish whether an attempted commit persisted: inspect the Vault on
// a later explicit call; never automatically retry. Signer usability is probed
// outside transactions; its external lifecycle still requires the caller lock.
func admitIncomingEnvelope(vault *storage.Vault, root, local key.Public,
	signer key.Handle, raw []byte,
) (_ bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errIncoming })

	assert.That(vault != nil && validPublic(root) && validPublic(local) &&
		len(raw) > 0 && len(raw) <= maxMessageEnvelopeBytes, errIncoming)
	root, local, raw = bytes.Clone(root), bytes.Clone(local), bytes.Clone(raw)
	var saved bool
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		saved = try.To1(checkIncoming(tx, root, local, raw))
		return nil
	}))

	state := try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	assert.That(state.Authorized && state.Usable, errIncoming)
	if saved {
		try.To(vault.View(func(tx storage.ReadTx) (err error) {
			defer err2.Handle(&err, nil)
			assert.That(try.To1(checkIncoming(tx, root, local, raw)),
				errIncoming)
			return nil
		}))
		return false, nil
	}

	updateErr := vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return commitIncoming(tx, root, local, raw)
	})
	if updateErr == errInboxUnchanged {
		return false, nil
	}
	try.To(updateErr)
	return true, nil
}

func commitIncoming(tx storage.WriteTx, root, local key.Public,
	raw []byte,
) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	// Reauthenticate history, current durable guards, input and any stored row
	// in the final transaction. No signer call or nested transaction occurs.
	if try.To1(checkIncoming(tx, root, local, raw)) {
		return errInboxUnchanged // Abort even backend bookkeeping; no seal.
	}
	record := try.To1(wire.Marshal(inboxMessage{Version: 1, Envelope: raw}))
	assert.That(len(record) <= maxInboxBytes, errIncoming)
	return tx.Put([]byte(inboxKey), record)
}

func incomingPrerequisites(tx storage.ReadTx, root, local key.Public,
) (_ outgoingBinding, err error) {
	defer err2.Handle(&err, nil)

	// This validator needs no outgoing row: it authenticates this receiver's
	// exact accepted history and historical first-use success, then checks its
	// current Known/holding/Deny/device guards. Orient that local relationship
	// for the peer sender, including the sender's ORIGINAL establishment role.
	binding := try.To1(outgoingPrerequisites(tx, root, local))
	binding.Sender, binding.Receiver = binding.Receiver, binding.Sender
	binding.Requester = !binding.Requester
	return binding, nil
}

func checkIncoming(tx storage.ReadTx, root, local key.Public,
	raw []byte,
) (_ bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	binding := try.To1(incomingPrerequisites(tx, root, local))
	try.To1(decodeMessageEnvelope(raw, binding))
	saved, found := try.To2(tx.Get([]byte(inboxKey)))
	if !found {
		return false, nil
	}
	assert.That(len(saved) > 0 && len(saved) <= maxInboxBytes, errIncoming)
	var record inboxMessage
	assert.That(wire.DecMode.Unmarshal(saved, &record) == nil, errIncoming)
	assert.That(record.Version == 1 &&
		bytes.Equal(saved, try.To1(wire.Marshal(record))), errIncoming)
	try.To1(decodeMessageEnvelope(record.Envelope, binding))
	assert.That(bytes.Equal(record.Envelope, raw), errIncoming)
	return true, nil
}
