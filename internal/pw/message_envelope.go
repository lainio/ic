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
	messageEnvelopeKey      = "local-pw-message-envelope-v1"
	messageAuthPurpose      = "pw-message-auth/v1"
	maxMessageEnvelopeBytes = maxOutgoingBytes + 128
)

var (
	errMessageEnvelope   = errors.New("local message envelope refused")
	errEnvelopeUnchanged = errors.New("local message envelope unchanged")
)

// messageEnvelope is both the canonical wire array and the separate local v1
// row. Message contains the exact committed outgoing v1 bytes, without another
// encoding of its ID/text/binding. The installed ES256/P-256 sender signs
// HashTagged(messageAuthPurpose, Message), using the repository Sign/Verify
// convention. This authenticates plaintext; it supplies no session key.
type messageEnvelope struct {
	_         struct{} `cbor:",toarray"`
	Version   uint8
	Message   []byte
	Signature key.Signature
}

// prepareOutgoingEnvelope requires the caller's existing owner mutation/signer
// lock throughout, independently pinned identities and their already-bound
// Vault. It prepares only this protocol instance's saved outgoing message; it
// does not Transmit, set sent, admit an inbox, acknowledge, or change lifecycle
// state. The model's symbolic Packet is not a distributed refinement proof.
//
// Signing/probing occurs outside transactions. Current durable guards are
// checked again at commit; external signer lifecycle changes still require the
// caller's lock. Only a successful commit or authenticated saved row supplies
// caller-owned bytes. An error leaves the outcome uncertain: inspect storage
// on a later explicit call, never automatically retry or regenerate a row.
func prepareOutgoingEnvelope(vault *storage.Vault, root, local key.Public,
	signer key.Handle,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errMessageEnvelope })

	assert.That(vault != nil && validPublic(root) && validPublic(local),
		errMessageEnvelope)
	root, local = bytes.Clone(root), bytes.Clone(local)
	var binding outgoingBinding
	var message, saved []byte
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		binding = try.To1(outgoingPrerequisites(tx, root, local))
		message = try.To1(readEnvelopeMessage(tx, binding))
		saved = try.To1(readMessageEnvelope(tx, binding, message))
		return nil
	}))

	state := try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	assert.That(state.Authorized && state.Usable, errMessageEnvelope)
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		current := try.To1(outgoingPrerequisites(tx, root, local))
		assert.That(bytes.Equal(message,
			try.To1(readEnvelopeMessage(tx, current))), errMessageEnvelope)
		now := try.To1(readMessageEnvelope(tx, current, message))
		assert.That(saved == nil || bytes.Equal(saved, now), errMessageEnvelope)
		saved = now
		return nil
	}))
	if saved != nil {
		return bytes.Clone(saved), nil
	}

	digest := key.HashTagged(messageAuthPurpose, message)
	signature := try.To1((localSigner{signer}).Sign(bytes.Clone(digest[:])))
	assert.That(len(signature) > 0 && len(signature) <= 72, errMessageEnvelope)
	prepared := try.To1(wire.Marshal(messageEnvelope{
		Version: 1, Message: message, Signature: signature,
	}))
	try.To1(decodeMessageEnvelope(prepared, binding))

	updateErr := vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		saved, err = commitMessageEnvelope(tx, root, local, message, prepared)
		return err
	})
	if updateErr != errEnvelopeUnchanged {
		try.To(updateErr)
	}
	return bytes.Clone(saved), nil
}

func commitMessageEnvelope(tx storage.WriteTx, root, local key.Public,
	message, prepared []byte,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	binding := try.To1(outgoingPrerequisites(tx, root, local))
	assert.That(bytes.Equal(message,
		try.To1(readEnvelopeMessage(tx, binding))), errMessageEnvelope)
	envelope := try.To1(decodeMessageEnvelope(prepared, binding))
	assert.That(bytes.Equal(envelope.Message, message), errMessageEnvelope)
	if saved := try.To1(readMessageEnvelope(tx, binding, message)); saved != nil {
		// Another exact prepare may have signed differently. Its authenticated
		// committed bytes win; abort this read-only transaction without sealing.
		return saved, errEnvelopeUnchanged
	}
	try.To(tx.Put([]byte(messageEnvelopeKey), prepared))
	return prepared, nil
}

func readEnvelopeMessage(tx storage.ReadTx, binding outgoingBinding,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	raw, found := try.To2(tx.Get([]byte(outgoingKey)))
	assert.That(found, errMessageEnvelope)
	try.To1(decodeOutgoing(raw, binding))
	return raw, nil
}

func readMessageEnvelope(tx storage.ReadTx, binding outgoingBinding,
	message []byte,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	raw, found := try.To2(tx.Get([]byte(messageEnvelopeKey)))
	if !found {
		return nil, nil
	}
	envelope := try.To1(decodeMessageEnvelope(raw, binding))
	assert.That(bytes.Equal(envelope.Message, message), errMessageEnvelope)
	return raw, nil
}

// decodeMessageEnvelope is pure, bounded authentication into owned storage.
// expected MUST come from independently authenticated relationship evidence,
// oriented for the expected sender, never from the received envelope. Both
// participants retain the same canonical acceptedRecord, so its digest and the
// signed request digest identify the same relationship on either side. The
// expected sender key is the verification authority. This helper makes no
// current receiver-local permission, inbox, or delivery claim.
func decodeMessageEnvelope(raw []byte, expected outgoingBinding,
) (_ messageEnvelope, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errMessageEnvelope })

	assert.That(validPublic(expected.Root) && validPublic(expected.Sender) &&
		validPublic(expected.Receiver) &&
		!bytes.Equal(expected.Sender, expected.Receiver) &&
		len(expected.RequestDigest) == key.HashSize &&
		len(expected.AcceptedDigest) == key.HashSize, errMessageEnvelope)
	assert.That(len(raw) > 0 && len(raw) <= maxMessageEnvelopeBytes,
		errMessageEnvelope)
	var envelope messageEnvelope
	assert.That(wire.DecMode.Unmarshal(raw, &envelope) == nil,
		errMessageEnvelope)
	assert.That(envelope.Version == 1 &&
		bytes.Equal(raw, try.To1(wire.Marshal(envelope))), errMessageEnvelope)
	try.To1(decodeOutgoing(envelope.Message, expected))
	digest := key.HashTagged(messageAuthPurpose, envelope.Message)
	assert.That(len(envelope.Signature) > 0 && len(envelope.Signature) <= 72 &&
		envelope.Signature.Verify(
			expected.Sender,
			digest[:],
		), errMessageEnvelope)
	return envelope, nil
}
