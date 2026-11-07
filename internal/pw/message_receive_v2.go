package pw

import (
	"bytes"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
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
