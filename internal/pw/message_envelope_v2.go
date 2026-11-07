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

const messageAuthPurposeV2 = "pw-message-auth/v2"

// A version-2 canonical array in messageEnvelopeKey. The installed sender signs
// HashTagged(messageAuthPurposeV2, Message), with the repository ES256/P-256
// convention. Message is the exact saved outgoing bytes. This authenticates
// plaintext, not encryption, an AKE, dispatch authorization or peer delivery.
type messageEnvelopeV2 struct {
	_         struct{} `cbor:",toarray"`
	Version   uint8
	Message   []byte
	Signature key.Signature
}

// PrepareOutgoingEnvelopeV2 prepares only the already committed v2 outgoing
// record. It requires the same pinned identities, bound Vault and owner
// mutation/signer/configuration lock as CreateOutgoingV2. Sign/probe outside
// transactions; recheck authenticated history, own runtime and durable guards
// at commit. The caller serializes external signer/runtime lifecycle changes.
//
// An exact repeat returns owned original signed bytes without re-signing the
// message or writing, after a discarded usability probe. A failed preparation
// preserves the outgoing commit for a later explicit call; no rollback across
// the two operations is claimed. Errors return no bytes and make no durability
// claim; inspect on a later explicit call. No sent, inbox, receipt, ACK, routing
// or network operation occurs.
func PrepareOutgoingEnvelopeV2(vault *storage.Vault, root, local key.Public,
	signer key.Handle, runtime ContactRuntimeV2,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errMessageEnvelope })

	assert.That(vault != nil && validPublic(root) && validPublic(local),
		errMessageEnvelope)
	root, local = bytes.Clone(root), bytes.Clone(local)
	var binding outgoingBindingV2
	var message, saved []byte
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		binding = try.To1(outgoingPrerequisitesV2(tx, root, local, runtime))
		message = try.To1(readEnvelopeMessageV2(tx, binding))
		saved = try.To1(readMessageEnvelopeV2(tx, binding, message))
		return nil
	}))
	state := try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	assert.That(state.Authorized && state.Usable, errMessageEnvelope)
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		current := try.To1(outgoingPrerequisitesV2(tx, root, local, runtime))
		assert.That(bytes.Equal(message,
			try.To1(readEnvelopeMessageV2(tx, current))), errMessageEnvelope)
		now := try.To1(readMessageEnvelopeV2(tx, current, message))
		assert.That(
			saved == nil || bytes.Equal(saved, now),
			errMessageEnvelope,
		)
		saved = now
		return nil
	}))
	if saved != nil {
		return bytes.Clone(saved), nil
	}

	digest := key.HashTagged(messageAuthPurposeV2, message)
	signature := try.To1((localSigner{signer}).Sign(bytes.Clone(digest[:])))
	assert.That(len(signature) > 0 && len(signature) <= 72, errMessageEnvelope)
	prepared := try.To1(wire.Marshal(messageEnvelopeV2{
		Version: 2, Message: message, Signature: bytes.Clone(signature),
	}))
	try.To1(decodeMessageEnvelopeV2(prepared, binding))
	// A signing callback may have invalidated usability. The last external
	// callback precedes the final durable recheck, never a Vault transaction.
	state = try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	assert.That(state.Authorized && state.Usable, errMessageEnvelope)

	updateErr := vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		saved, err = commitMessageEnvelopeV2(tx, root, local, runtime,
			message, prepared)
		return err
	})
	if updateErr != errEnvelopeUnchanged {
		try.To(updateErr)
	}
	return bytes.Clone(saved), nil
}

func commitMessageEnvelopeV2(tx storage.WriteTx, root, local key.Public,
	runtime ContactRuntimeV2, message, prepared []byte,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	binding := try.To1(outgoingPrerequisitesV2(tx, root, local, runtime))
	assert.That(bytes.Equal(message,
		try.To1(readEnvelopeMessageV2(tx, binding))), errMessageEnvelope)
	envelope := try.To1(decodeMessageEnvelopeV2(prepared, binding))
	assert.That(bytes.Equal(envelope.Message, message), errMessageEnvelope)
	if saved := try.To1(readMessageEnvelopeV2(tx, binding, message)); saved != nil {
		return saved, errEnvelopeUnchanged // Abort even backend bookkeeping.
	}
	try.To(tx.Put([]byte(messageEnvelopeKey), prepared))
	return prepared, nil
}

func readEnvelopeMessageV2(tx storage.ReadTx, binding outgoingBindingV2,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	raw, found := try.To2(tx.Get([]byte(outgoingKey)))
	assert.That(found, errMessageEnvelope)
	try.To1(decodeOutgoingV2(raw, binding))
	return raw, nil
}

func readMessageEnvelopeV2(tx storage.ReadTx, binding outgoingBindingV2,
	message []byte,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	raw, found := try.To2(tx.Get([]byte(messageEnvelopeKey)))
	if !found {
		return nil, nil
	}
	envelope := try.To1(decodeMessageEnvelopeV2(raw, binding))
	assert.That(bytes.Equal(envelope.Message, message), errMessageEnvelope)
	return raw, nil
}

// Pure bounded verification into owned storage. expected MUST come from
// independently authenticated local v2 history oriented for the sender, never
// from the envelope or an ad. No receiver admission or current policy follows.
// The separate symbolic message model supplies no composed protocol proof.
func decodeMessageEnvelopeV2(raw []byte, expected outgoingBindingV2,
) (_ messageEnvelopeV2, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errMessageEnvelope })

	assert.That(validPublic(expected.Root) && validPublic(expected.Sender) &&
		validPublic(expected.Receiver) &&
		!bytes.Equal(expected.Sender, expected.Receiver) &&
		len(expected.RequestDigest) == key.HashSize &&
		len(expected.AcceptedDigest) == key.HashSize, errMessageEnvelope)
	assert.That(len(raw) > 0 && len(raw) <= maxMessageEnvelopeBytes,
		errMessageEnvelope)
	var envelope messageEnvelopeV2
	assert.That(wire.DecMode.Unmarshal(raw, &envelope) == nil,
		errMessageEnvelope)
	assert.That(envelope.Version == 2 &&
		bytes.Equal(raw, try.To1(wire.Marshal(envelope))), errMessageEnvelope)
	try.To1(decodeOutgoingV2(envelope.Message, expected))
	digest := key.HashTagged(messageAuthPurposeV2, envelope.Message)
	assert.That(len(envelope.Signature) > 0 && len(envelope.Signature) <= 72 &&
		envelope.Signature.Verify(
			expected.Sender,
			digest[:],
		), errMessageEnvelope)
	return envelope, nil
}
