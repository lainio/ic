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

const (
	messageReceiptPurposeV2         = "pw-message-receipt-auth/v2"
	messageReceiptEnvelopePurposeV2 = "pw-message-receipt-envelope/v2"
	maxMessageReceiptBytesV2        = 640
)

// Canonical version-2 wire arrays, never Vault rows. The installed receiver
// signs HashTagged(messageReceiptPurposeV2, canonical Payload) using the
// repository ES256/P-256 convention. V1 wire types and purposes stay separate.
type messageReceiptV2 struct {
	_         struct{} `cbor:",toarray"`
	Version   uint8
	Payload   messageReceiptPayloadV2
	Signature key.Signature
}

// Preserve the ORIGINAL sender orientation, UUID and exact relationship
// digests. EnvelopeDigest covers the whole canonical signed envelope, including
// the sender signature, with the v2 receipt-specific digest purpose.
type messageReceiptPayloadV2 struct {
	_              struct{} `cbor:",toarray"`
	EnvelopeDigest []byte
	ID             []byte
	Binding        outgoingBindingV2
}

// IssueMessageReceiptV2 implements ReturnReceipt only for an authenticated,
// already committed exact v2 inbox. The caller MUST hold the same owner
// mutation/signer/configuration lock as AdmitIncomingEnvelopeV2 and supply
// independently pinned identities, their bound Vault and installed signer.
// Inputs are bounded and copied before callbacks; do not mutate concurrently.
//
// Probe and sign outside transactions, rechecking local guards and the exact
// inbox around signing. No Vault.Update, receipt row, seal, inbox rewrite or ACK
// occurs. Repetition may change signature bytes, never the logical payload.
// Failure or loss cannot roll back admission or establish sender observation;
// a later explicit issuance can succeed if still permitted. The signature is
// an assertion of past acceptance, not proof of honest remote storage, current
// remote permission, a live pipe or delivery.
func IssueMessageReceiptV2(vault *storage.Vault, root, local key.Public,
	signer key.Handle, runtime ContactRuntimeV2, raw []byte,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errMessageReceipt })

	assert.That(vault != nil && validPublic(root) && validPublic(local) &&
		len(raw) > 0 && len(raw) <= maxMessageEnvelopeBytes, errMessageReceipt)
	root, local, raw = bytes.Clone(root), bytes.Clone(local), bytes.Clone(raw)
	var binding outgoingBindingV2
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		assert.That(try.To1(checkIncomingV2(tx, root, local, runtime, raw)),
			errMessageReceipt)
		binding = try.To1(incomingPrerequisitesV2(tx, root, local, runtime))
		return nil
	}))
	payload := try.To1(receiptPayloadForEnvelopeV2(raw, binding))

	state := try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	assert.That(state.Authorized && state.Usable, errMessageReceipt)
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		assert.That(try.To1(checkIncomingV2(tx, root, local, runtime, raw)),
			errMessageReceipt)
		return nil
	}))

	digest := key.HashTagged(messageReceiptPurposeV2,
		try.To1(wire.Marshal(payload)))
	signature := try.To1((localSigner{signer}).Sign(bytes.Clone(digest[:])))
	assert.That(len(signature) > 0 && len(signature) <= 72, errMessageReceipt)
	prepared := try.To1(wire.Marshal(messageReceiptV2{
		Version: 2, Payload: payload, Signature: bytes.Clone(signature),
	}))
	try.To1(decodeMessageReceiptV2(prepared, raw, binding))

	// A signing callback may invalidate usability or durable local permission.
	// The last external callback precedes the final authenticated snapshot.
	state = try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	assert.That(state.Authorized && state.Usable, errMessageReceipt)
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		assert.That(try.To1(checkIncomingV2(tx, root, local, runtime, raw)),
			errMessageReceipt)
		return nil
	}))
	return prepared, nil
}

// Pure bounded verification returning owned data. exactEnvelope MUST be the
// trusted exact outgoing envelope and expected its independently authenticated
// original sender binding. Only expected.Receiver is the receipt authority.
// No current permission or Vault check belongs here; historical verification
// grants no permission and implements no sender ACK. The symbolic message
// model is separate from the invitation model, with no composition proof.
func decodeMessageReceiptV2(raw, exactEnvelope []byte,
	expected outgoingBindingV2,
) (_ messageReceiptV2, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errMessageReceipt })

	assert.That(len(raw) > 0 && len(raw) <= maxMessageReceiptBytesV2,
		errMessageReceipt)
	payload := try.To1(receiptPayloadForEnvelopeV2(exactEnvelope, expected))
	var receipt messageReceiptV2
	assert.That(wire.DecMode.Unmarshal(raw, &receipt) == nil, errMessageReceipt)
	assert.That(receipt.Version == 2 &&
		bytes.Equal(raw, try.To1(wire.Marshal(receipt))) &&
		bytes.Equal(try.To1(wire.Marshal(receipt.Payload)),
			try.To1(wire.Marshal(payload))), errMessageReceipt)
	digest := key.HashTagged(messageReceiptPurposeV2,
		try.To1(wire.Marshal(receipt.Payload)))
	assert.That(len(receipt.Signature) > 0 && len(receipt.Signature) <= 72 &&
		receipt.Signature.Verify(
			expected.Receiver,
			digest[:],
		), errMessageReceipt)
	return receipt, nil
}

func receiptPayloadForEnvelopeV2(raw []byte, expected outgoingBindingV2,
) (_ messageReceiptPayloadV2, err error) {
	defer err2.Handle(&err, nil)

	envelope := try.To1(decodeMessageEnvelopeV2(raw, expected))
	message := try.To1(decodeOutgoingV2(envelope.Message, expected))
	digest := key.HashTagged(messageReceiptEnvelopePurposeV2, raw)
	return messageReceiptPayloadV2{EnvelopeDigest: digest[:], ID: message.ID,
		Binding: message.Binding}, nil
}
