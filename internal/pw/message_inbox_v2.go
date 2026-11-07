package pw

import (
	"bytes"
	"strings"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// ReadMessageInboxV2 projects the single authenticated v2 inbox from the
// receiver's independently bound Vault and pinned Root/local identities.
// One View authenticates exact accepted contacts and historical successful
// first use before checking the saved canonical inbox and signed envelope.
// Missing or invalid prerequisite history is an error, even without an inbox.
// V1 records cannot supply v2 history or plaintext.
//
// Current holding, Deny, Known, device/signer, bootstrap expiry and runtime do
// not govern this historical read. It probes, signs and writes nothing, grants
// no permission to send/receive, and restores no holding, PWOpen or Trust.
func ReadMessageInboxV2(vault *storage.Vault, root, local key.Public,
) (_ MessageInbox, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errMessageInbox })

	assert.That(vault != nil && validPublic(root) && validPublic(local),
		errMessageInbox)
	root, local = bytes.Clone(root), bytes.Clone(local)
	var result MessageInbox
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)

		binding, _ := try.To2(outgoingHistoryV2(tx, root, local))
		// Only authenticated LOCAL history determines the PEER sender's role.
		binding.Sender, binding.Receiver = binding.Receiver, binding.Sender
		binding.Requester = !binding.Requester

		raw, found := try.To2(tx.Get([]byte(inboxKey)))
		if !found {
			return nil
		}
		assert.That(len(raw) > 0 && len(raw) <= maxInboxBytes, errMessageInbox)
		var record inboxMessage
		assert.That(wire.DecMode.Unmarshal(raw, &record) == nil,
			errMessageInbox)
		assert.That(record.Version == 2 &&
			bytes.Equal(raw, try.To1(wire.Marshal(record))), errMessageInbox)
		envelope := try.To1(decodeMessageEnvelopeV2(record.Envelope, binding))
		message := try.To1(decodeOutgoingV2(envelope.Message, binding))
		result = MessageInbox{Present: true, ID: [16]byte(message.ID),
			Text: strings.Clone(message.Text)}
		return nil
	}))
	return result, nil
}
