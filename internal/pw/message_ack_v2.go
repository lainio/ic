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

const maxMessageACKBytesV2 = maxMessageReceiptBytesV2 + 16

// ObserveMessageReceiptV2 records only a sender-local historical observation.
// The caller MUST hold its owner mutation lock and supply its independently
// bound Vault and pinned Root/local identities. Untrusted receipt bytes are
// bounded and copied; callers must not mutate inputs concurrently with the call.
// No signer, runtime, current permission, sent marker or remote access is needed.
// Deny/Delete and lost current eligibility do not revoke historical evidence.
//
// True means one ACK commit succeeded. An authenticated logical repeat returns
// false without a write or seal, retaining the first exact signed receipt even
// if the repeat has a different signature. The existing messageACKKey holds a
// canonical Version 2 messageACK; v1 state is never migrated or replaced.
// Errors return false and make no durability claim; inspect on a later explicit
// call, never automatically retry. A receipt authenticates the receiver's
// assertion, not honest remote storage, dispatch, delivery, present permission,
// PWOpen or Trust. It restores no holding or permission to communicate.
func ObserveMessageReceiptV2(vault *storage.Vault, root, local key.Public,
	rawReceipt []byte,
) (_ bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errMessageACK })

	assert.That(vault != nil && validPublic(root) && validPublic(local) &&
		len(rawReceipt) > 0 && len(rawReceipt) <= maxMessageReceiptBytesV2,
		errMessageACK)
	root, local = bytes.Clone(root), bytes.Clone(local)
	rawReceipt = bytes.Clone(rawReceipt)
	var saved bool
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		saved = try.To1(checkMessageACKV2(tx, root, local, rawReceipt))
		return nil
	}))
	if saved {
		return false, nil
	}

	updateErr := vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return commitMessageACKV2(tx, root, local, rawReceipt)
	})
	if updateErr == errACKUnchanged {
		return false, nil
	}
	try.To(updateErr)
	return true, nil
}

func commitMessageACKV2(tx storage.WriteTx, root, local key.Public,
	rawReceipt []byte,
) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	// Reauthenticate full local history, outgoing, exact signed envelope,
	// receipt and any competing ACK in this single transaction.
	if try.To1(checkMessageACKV2(tx, root, local, rawReceipt)) {
		return errACKUnchanged // Abort backend bookkeeping too; no seal.
	}
	raw := try.To1(wire.Marshal(messageACK{Version: 2, Receipt: rawReceipt}))
	assert.That(len(raw) <= maxMessageACKBytesV2, errMessageACK)
	return tx.Put([]byte(messageACKKey), raw)
}

func checkMessageACKV2(tx storage.ReadTx, root, local key.Public,
	rawReceipt []byte,
) (_ bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	binding, _ := try.To2(outgoingHistoryV2(tx, root, local))
	message := try.To1(readEnvelopeMessageV2(tx, binding))
	envelope := try.To1(readMessageEnvelopeV2(tx, binding, message))
	assert.That(envelope != nil, errMessageACK)
	try.To1(decodeMessageReceiptV2(rawReceipt, envelope, binding))

	raw, found := try.To2(tx.Get([]byte(messageACKKey)))
	if !found {
		return false, nil
	}
	assert.That(len(raw) > 0 && len(raw) <= maxMessageACKBytesV2, errMessageACK)
	var record messageACK
	assert.That(wire.DecMode.Unmarshal(raw, &record) == nil, errMessageACK)
	assert.That(record.Version == 2 &&
		bytes.Equal(raw, try.To1(wire.Marshal(record))), errMessageACK)
	// Each receipt must independently authenticate the same expected payload
	// with the original sender binding's receiver key. First exact bytes win.
	try.To1(decodeMessageReceiptV2(record.Receipt, envelope, binding))
	return true, nil
}
