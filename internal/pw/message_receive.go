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

// Transport bounds are the existing domain wire bounds, not new formats.
const (
	MaxMessageEnvelopeBytes = maxMessageEnvelopeBytes
	MaxMessageReceiptBytes  = maxMessageReceiptBytes
)

// AcceptMessageAndReceipt composes AcceptIncoming then ReturnReceipt for the
// same owned envelope bytes. The caller MUST hold the existing owner mutation/
// signer lock throughout and supply independently pinned identities, their
// bound Vault and installed signer. Input must not be mutated concurrently.
// A receipt requires a committed inbox; a later signing failure never rolls
// that commit back. An authorized exact retry reads without another write.
// Neither success nor failure establishes sender observation or writes sent/ACK.
func AcceptMessageAndReceipt(vault *storage.Vault, root, local key.Public,
	signer key.Handle, raw []byte,
) (_ []byte, err error) {
	defer err2.Handle(&err, nil)

	if len(raw) == 0 || len(raw) > MaxMessageEnvelopeBytes {
		return nil, errIncoming
	}
	root, local, raw = bytes.Clone(root), bytes.Clone(local), bytes.Clone(raw)
	try.To1(admitIncomingEnvelope(vault, root, local, signer, raw))
	return issueMessageReceipt(vault, root, local, signer, raw)
}

// ValidateLocalMessageReceipt checks only output from a SUCCESSFUL trusted
// local receiver capability before HTTP serialization. Its binding comes from
// that local output, never the peer's envelope. This is not an admission or
// sender ACK verifier: it cannot establish permission or an inbox commit.
// Those remain exclusively the capability's responsibility. Sender observation
// must instead verify against independently authenticated saved history.
func ValidateLocalMessageReceipt(envelope, localReceipt []byte) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errMessageReceipt })

	assert.That(len(localReceipt) > 0 &&
		len(localReceipt) <= MaxMessageReceiptBytes, errMessageReceipt)
	var receipt messageReceipt
	assert.That(wire.DecMode.Unmarshal(localReceipt, &receipt) == nil,
		errMessageReceipt)
	try.To1(
		decodeMessageReceipt(localReceipt, envelope, receipt.Payload.Binding),
	)
	return nil
}
