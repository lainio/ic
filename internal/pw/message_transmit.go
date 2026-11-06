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
	messageSentKey             = "local-pw-message-sent-v1"
	messageSentEnvelopePurpose = "pw-message-sent-envelope/v1"
	maxMessageSentBytes        = 64
)

var (
	errMessageTransmit = errors.New("local message transmission refused")
	errSentUnchanged   = errors.New("local message transmission unchanged")
)

// This separate canonical row records authorization of an attempted send, not
// evidence of dispatch or admission. Its digest includes the exact signature.
type messageSent struct {
	_              struct{} `cbor:",toarray"`
	Version        uint8
	EnvelopeDigest []byte
}

// Only saveMessageTransmit supplies this immutable, caller-owned snapshot.
// It carries no routing hint, live permission, Vault or signer. Every explicit
// retry must obtain a fresh snapshot under current guards; do not cache it as
// continuing authority. A string prevents byte-slice aliasing or mutation.
type savedMessageTransmit struct {
	envelope string
}

// saveMessageTransmit projects candidate Transmit/RetryExact's local boundary.
// The caller MUST hold the existing owner mutation/signer lock throughout,
// supplying independently pinned Root/local identities and their bound Vault.
// Only authenticated stored history selects the peer, role and exact message.
// Probe outside transactions; recheck all durable guards at the final boundary.
// The caller lock also serializes external signer lifecycle changes.
//
// At most one Update saves sent. A permitted exact repeat is read-only, with no
// seal, new ID or envelope signature. No network, ACK or lifecycle change occurs.
// A failed commit has an uncertain local outcome; inspect on a later explicit
// call. A crash after commit but before HTTP likewise leaves dispatch unknown.
// Release the lock before sendMessageOnce: later Deny/Delete cannot recall this
// already-authorized attempt, but blocks obtaining a new snapshot for retry.
func saveMessageTransmit(vault *storage.Vault, root, local key.Public,
	signer key.Handle,
) (_ savedMessageTransmit, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errMessageTransmit })

	assert.That(vault != nil && validPublic(root) && validPublic(local),
		errMessageTransmit)
	root, local = bytes.Clone(root), bytes.Clone(local)
	var envelope []byte
	var saved bool
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		envelope, saved = try.To2(checkMessageTransmit(tx, root, local))
		return nil
	}))

	state := try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	assert.That(state.Authorized && state.Usable, errMessageTransmit)
	if saved {
		try.To(vault.View(func(tx storage.ReadTx) (err error) {
			defer err2.Handle(&err, nil)
			current, found := try.To2(checkMessageTransmit(tx, root, local))
			assert.That(found && bytes.Equal(current, envelope),
				errMessageTransmit)
			return nil
		}))
	} else {
		updateErr := vault.Update(func(tx storage.WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			return commitMessageTransmit(tx, root, local, envelope)
		})
		if updateErr != errSentUnchanged {
			try.To(updateErr)
		}
	}
	return savedMessageTransmit{envelope: string(envelope)}, nil
}

func commitMessageTransmit(tx storage.WriteTx, root, local key.Public,
	expected []byte,
) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	envelope, saved := try.To2(checkMessageTransmit(tx, root, local))
	assert.That(bytes.Equal(envelope, expected), errMessageTransmit)
	if saved {
		return errSentUnchanged // Abort backend bookkeeping too; no seal.
	}
	digest := key.HashTagged(messageSentEnvelopePurpose, envelope)
	raw := try.To1(wire.Marshal(messageSent{
		Version: 1, EnvelopeDigest: digest[:],
	}))
	assert.That(len(raw) <= maxMessageSentBytes, errMessageTransmit)
	return tx.Put([]byte(messageSentKey), raw)
}

func checkMessageTransmit(tx storage.ReadTx, root, local key.Public,
) (_ []byte, _ bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	binding := try.To1(outgoingPrerequisites(tx, root, local))
	message := try.To1(readEnvelopeMessage(tx, binding))
	envelope := try.To1(readMessageEnvelope(tx, binding, message))
	assert.That(envelope != nil, errMessageTransmit)
	raw, found := try.To2(tx.Get([]byte(messageSentKey)))
	if !found {
		return envelope, false, nil
	}
	assert.That(len(raw) > 0 && len(raw) <= maxMessageSentBytes,
		errMessageTransmit)
	var record messageSent
	assert.That(wire.DecMode.Unmarshal(raw, &record) == nil,
		errMessageTransmit)
	digest := key.HashTagged(messageSentEnvelopePurpose, envelope)
	assert.That(record.Version == 1 &&
		bytes.Equal(raw, try.To1(wire.Marshal(record))) &&
		bytes.Equal(record.EnvelopeDigest, digest[:]), errMessageTransmit)
	return envelope, true, nil
}
