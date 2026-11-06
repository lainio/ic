package pw

import (
	"bytes"
	"errors"
	"strings"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

var errMessageInbox = errors.New("local message inbox read refused")

// MessageInbox is an owned projection of the single authenticated incoming
// message. An absent inbox has zero ID and empty Text; a present one has the
// saved UUIDv4 and at most 1024 UTF-8 text bytes. No signed bytes are exposed.
type MessageInbox struct {
	Present bool
	ID      [16]byte
	Text    string
}

// ReadMessageInbox reads only the caller's bound Vault using independently
// pinned Root/local identities. One View authenticates exact accepted history,
// historical successful first use and, if present, the retained signed inbox.
// Missing or invalid history is a refusal even when the inbox is absent.
//
// Current holding, Known, Deny and device/signer state do not govern historical
// reading. This grants no admission, delivery, ACK, current consent, Trust,
// PWOpen or permission to communicate. It signs, probes and writes nothing.
func ReadMessageInbox(vault *storage.Vault, root, local key.Public,
) (_ MessageInbox, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errMessageInbox })

	assert.That(vault != nil && validPublic(root) && validPublic(local),
		errMessageInbox)
	root, local = bytes.Clone(root), bytes.Clone(local)
	var result MessageInbox
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)

		binding, _ := try.To2(outgoingHistory(tx, root, local))
		// Orient authenticated LOCAL history for the PEER's original role.
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
		assert.That(record.Version == 1 &&
			bytes.Equal(raw, try.To1(wire.Marshal(record))), errMessageInbox)
		envelope := try.To1(decodeMessageEnvelope(record.Envelope, binding))
		message := try.To1(decodeOutgoing(envelope.Message, binding))
		result = MessageInbox{Present: true, ID: [16]byte(message.ID),
			Text: strings.Clone(message.Text)}
		return nil
	}))
	return result, nil
}
