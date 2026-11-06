package pw

import (
	"bytes"
	"errors"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const (
	messageACKKey      = "local-pw-message-ack-v1"
	maxMessageACKBytes = maxMessageReceiptBytes + 16
)

var (
	errMessageACK   = errors.New("local message acknowledgement refused")
	errACKUnchanged = errors.New("local message acknowledgement unchanged")
)

// One sender-local historical observation, retaining the first exact signed
// receipt bytes. This canonical row is separate from all existing wire formats.
type messageACK struct {
	_       struct{} `cbor:",toarray"`
	Version uint8
	Receipt []byte
}

// observeMessageReceipt projects only PW-Msg-02 ObserveReceipt. The caller MUST
// hold this node's existing owner mutation lock throughout and supply its
// independently bound Vault and pinned Root/local identities. Untrusted input
// is bounded and copied; callers must not mutate it concurrently with the call.
// No signer or current-permission check belongs here: valid historical evidence
// remains recordable after Deny, Delete, lost Known or device/signer loss.
//
// True means the single local ACK commit succeeded. A logical authenticated
// repeat returns false without a write or seal, even with a different receipt
// signature, preserving the first receipt bytes. Errors are sanitized and leave
// the outcome uncertain until a later explicit inspection/observation; never
// automatically retry. A receiver signature authenticates its assertion, not
// honest remote storage or present permission. No remote Vault read, network
// I/O, sent marker, holding restoration or relationship transition occurs.
func observeMessageReceipt(vault *storage.Vault, root, local key.Public,
	rawReceipt []byte,
) (_ bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errMessageACK })

	assert.That(vault != nil && validPublic(root) && validPublic(local) &&
		len(rawReceipt) > 0 && len(rawReceipt) <= maxMessageReceiptBytes,
		errMessageACK)
	root, local = bytes.Clone(root), bytes.Clone(local)
	rawReceipt = bytes.Clone(rawReceipt)
	var saved bool
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		saved = try.To1(checkMessageACK(tx, root, local, rawReceipt))
		return nil
	}))
	if saved {
		return false, nil
	}

	updateErr := vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return commitMessageACK(tx, root, local, rawReceipt)
	})
	if updateErr == errACKUnchanged {
		return false, nil
	}
	try.To(updateErr)
	return true, nil
}

func commitMessageACK(tx storage.WriteTx, root, local key.Public,
	rawReceipt []byte,
) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	// Reauthenticate history, outgoing, exact signed envelope, input and any
	// competing ACK inside this transaction. No callbacks or nested transaction.
	if try.To1(checkMessageACK(tx, root, local, rawReceipt)) {
		return errACKUnchanged // Abort backend bookkeeping too; no seal.
	}
	raw := try.To1(wire.Marshal(messageACK{Version: 1, Receipt: rawReceipt}))
	assert.That(len(raw) <= maxMessageACKBytes, errMessageACK)
	return tx.Put([]byte(messageACKKey), raw)
}

func checkMessageACK(tx storage.ReadTx, root, local key.Public,
	rawReceipt []byte,
) (_ bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	binding, _ := try.To2(outgoingHistory(tx, root, local))
	message := try.To1(readEnvelopeMessage(tx, binding))
	envelope := try.To1(readMessageEnvelope(tx, binding, message))
	assert.That(envelope != nil, errMessageACK)
	try.To1(decodeMessageReceipt(rawReceipt, envelope, binding))

	raw, found := try.To2(tx.Get([]byte(messageACKKey)))
	if !found {
		return false, nil
	}
	assert.That(len(raw) > 0 && len(raw) <= maxMessageACKBytes, errMessageACK)
	var record messageACK
	assert.That(wire.DecMode.Unmarshal(raw, &record) == nil, errMessageACK)
	assert.That(record.Version == 1 &&
		bytes.Equal(raw, try.To1(wire.Marshal(record))), errMessageACK)
	// Both signatures must authenticate the one exact expected payload. Their
	// signature bytes need not match; the first committed receipt always wins.
	try.To1(decodeMessageReceipt(record.Receipt, envelope, binding))
	return true, nil
}
