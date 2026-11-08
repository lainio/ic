package pw

import (
	"bytes"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// AcceptMessageAndReceiptV2 composes admission then read-only receipt issuance
// for the same owned exact envelope. Hold the owner mutation/signer/configuration
// lock and supply pinned identities, their bound Vault and installed signer as
// for AdmitIncomingEnvelopeV2. Inputs must not be mutated concurrently.
// A receipt-signing failure leaves any committed inbox intact. This is not an
// atomic cross-operation transaction and establishes no sender observation.
func AcceptMessageAndReceiptV2(vault *storage.Vault, root, local key.Public,
	signer key.Handle, runtime ContactRuntimeV2, raw []byte,
) (_ []byte, err error) {
	defer err2.Handle(&err, nil)

	if len(raw) == 0 || len(raw) > maxMessageEnvelopeBytes {
		return nil, errIncoming
	}
	root, local, raw = bytes.Clone(root), bytes.Clone(local), bytes.Clone(raw)
	try.To1(AdmitIncomingEnvelopeV2(vault, root, local, signer, runtime, raw))
	return IssueMessageReceiptV2(vault, root, local, signer, runtime, raw)
}

// ValidateLocalMessageReceiptV2 checks only a SUCCESSFUL trusted local
// capability's output before serialization, including signed wire versions.
// Like ValidateLocalMessageReceipt, it grants no admission or ACK authority.
// The binding comes from local output, never untrusted peer input.
func ValidateLocalMessageReceiptV2(envelope, localReceipt []byte) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errMessageReceipt })

	assert.That(len(localReceipt) > 0 &&
		len(localReceipt) <= maxMessageReceiptBytesV2, errMessageReceipt)
	var receipt messageReceiptV2
	assert.That(wire.DecMode.Unmarshal(localReceipt, &receipt) == nil,
		errMessageReceipt)
	try.To1(decodeMessageReceiptV2(localReceipt, envelope, receipt.Payload.Binding))
	return nil
}
