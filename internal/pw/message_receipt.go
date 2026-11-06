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
	messageReceiptPurpose         = "pw-message-receipt-auth/v1"
	messageReceiptEnvelopePurpose = "pw-message-receipt-envelope/v1"
	maxMessageReceiptBytes        = 640
)

var errMessageReceipt = errors.New("local message receipt refused")

// This canonical wire array is never a Vault row. The receiver signs the
// canonical payload with the receipt-specific v1 purpose (ES256/P-256, using
// the repository HashTagged/Sign/Verify convention).
type messageReceipt struct {
	_         struct{} `cbor:",toarray"`
	Version   uint8
	Payload   messageReceiptPayload
	Signature key.Signature
}

// Binding keeps the ORIGINAL message orientation: Sender is the receipt's
// target; Receiver is its issuer. Root, role and the exact signed request and
// accepted-history digests pin the relationship. EnvelopeDigest covers every
// signed envelope byte, including its signature. No message text is included.
type messageReceiptPayload struct {
	_              struct{} `cbor:",toarray"`
	EnvelopeDigest []byte
	ID             []byte
	Binding        outgoingBinding
}

// issueMessageReceipt projects only ReturnReceipt. The caller MUST hold the
// node's existing owner mutation/signer lock throughout, supplying its already
// bound Vault, independently pinned Root/local identities and installed signer.
// raw is untrusted; inputs are copied before callbacks and must not be mutated
// concurrently with this call. No peer, role or message ID selector is accepted.
//
// The exact authenticated inbox must already be committed. Each explicit call
// rechecks receiver-local permission and historical first-use success, including
// after all signing/probing callbacks. Callbacks run outside transactions. The
// external signer lifecycle still requires the caller's lock. No Vault.Update,
// seal, ACK or sent transition occurs. Signature bytes may differ on repetition;
// the logical payload cannot. Losing this response leaves sender observation
// unknown and cannot roll back the inbox. This assertion is neither proof of
// honest remote storage nor a delivery, live pipe or current remote consent.
func issueMessageReceipt(vault *storage.Vault, root, local key.Public,
	signer key.Handle, raw []byte,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errMessageReceipt })

	assert.That(vault != nil && validPublic(root) && validPublic(local) &&
		len(raw) > 0 && len(raw) <= maxMessageEnvelopeBytes, errMessageReceipt)
	root, local, raw = bytes.Clone(root), bytes.Clone(local), bytes.Clone(raw)
	var binding outgoingBinding
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		assert.That(try.To1(checkIncoming(tx, root, local, raw)),
			errMessageReceipt)
		binding = try.To1(incomingPrerequisites(tx, root, local))
		return nil
	}))
	payload := try.To1(receiptPayloadForEnvelope(raw, binding))

	state := try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	assert.That(state.Authorized && state.Usable, errMessageReceipt)
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		assert.That(try.To1(checkIncoming(tx, root, local, raw)),
			errMessageReceipt)
		return nil
	}))

	digest := key.HashTagged(
		messageReceiptPurpose,
		try.To1(wire.Marshal(payload)),
	)
	signature := try.To1((localSigner{signer}).Sign(bytes.Clone(digest[:])))
	assert.That(len(signature) > 0 && len(signature) <= 72, errMessageReceipt)
	prepared := try.To1(wire.Marshal(messageReceipt{
		Version: 1, Payload: payload, Signature: signature,
	}))
	try.To1(decodeMessageReceipt(prepared, raw, binding))

	// A successful signature alone cannot authorize return after a callback
	// changed policy or signer usability. The last callback precedes the final
	// durable read, so even a change during this probe is observed.
	state = try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	assert.That(state.Authorized && state.Usable, errMessageReceipt)
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		assert.That(try.To1(checkIncoming(tx, root, local, raw)),
			errMessageReceipt)
		return nil
	}))
	return prepared, nil
}

// decodeMessageReceipt is a pure bounded verifier returning owned data.
// exactEnvelope MUST be the trusted exact saved prepared outgoing envelope;
// expected MUST be its independently authenticated relationship, oriented for
// the original sender. In particular expected.Receiver, never a key asserted
// by the receipt, is the verification authority. There is no Vault, permission
// or clock check: historical verification after either node's Deny/Delete is
// valid and grants no permission. A later ObserveReceipt owns any ACK write.
func decodeMessageReceipt(raw, exactEnvelope []byte, expected outgoingBinding,
) (_ messageReceipt, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errMessageReceipt })

	assert.That(len(raw) > 0 && len(raw) <= maxMessageReceiptBytes,
		errMessageReceipt)
	payload := try.To1(receiptPayloadForEnvelope(exactEnvelope, expected))
	var receipt messageReceipt
	assert.That(wire.DecMode.Unmarshal(raw, &receipt) == nil, errMessageReceipt)
	assert.That(receipt.Version == 1 &&
		bytes.Equal(raw, try.To1(wire.Marshal(receipt))) &&
		bytes.Equal(try.To1(wire.Marshal(receipt.Payload)),
			try.To1(wire.Marshal(payload))), errMessageReceipt)
	digest := key.HashTagged(messageReceiptPurpose,
		try.To1(wire.Marshal(receipt.Payload)))
	assert.That(len(receipt.Signature) > 0 && len(receipt.Signature) <= 72 &&
		receipt.Signature.Verify(
			expected.Receiver,
			digest[:],
		), errMessageReceipt)
	return receipt, nil
}

func receiptPayloadForEnvelope(raw []byte, expected outgoingBinding,
) (_ messageReceiptPayload, err error) {
	defer err2.Handle(&err, nil)

	envelope := try.To1(decodeMessageEnvelope(raw, expected))
	message := try.To1(decodeOutgoing(envelope.Message, expected))
	digest := key.HashTagged(messageReceiptEnvelopePurpose, raw)
	return messageReceiptPayload{EnvelopeDigest: digest[:], ID: message.ID,
		Binding: message.Binding}, nil
}
