package pw

import (
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/storage"
)

func TestIncomingAndReceiptVersionIsolationV2(t *testing.T) {
	defer assert.PushTester(t)()
	for _, receiver := range []int{0, 1} {
		one, n1, raw1, expected1 := receiptTest(t, receiver)
		two, n2, raw2, expected2 := receiptTestV2(t, receiver)
		receipt1 := try.To1(issueMessageReceipt(n1.own.vault, one.root.public,
			n1.local, n1.signer, raw1))
		receipt2 := try.To1(IssueMessageReceiptV2(n2.own.vault, two.root.public,
			n2.local, n2.signer, two.messageRuntime(n2), raw2))
		_, err := decodeMessageReceiptV2(receipt1, raw2, expected2)
		assert.Equal(err, errMessageReceipt)
		_, err = decodeMessageReceipt(receipt2, raw1, expected1)
		assert.Equal(err, errMessageReceipt)
		refuseIncomingV2(t, two, n2, n2.signer, raw1)
		refuseMessageReceiptV2(t, two, n2, n2.signer, raw1)
		refuseIncoming(t, one, n1, n1.signer, raw2)
		refuseMessageReceipt(t, one, n1, n1.signer, raw2)

		// Same keys, same digest fields: neither a version relabel nor the other
		// version's signature purpose can turn an envelope into valid v2 input.
		var envelope messageEnvelopeV2
		try.To(wire.UnmarshalCanonical(&envelope, raw2))
		var message outgoingMessageV2
		try.To(wire.UnmarshalCanonical(&message, envelope.Message))
		message.Version = 1
		legacy := signMessageEnvelope(t, try.To1(wire.Marshal(message)),
			outgoingTestNodes(two.requesterFixture)[1-receiver].signer)
		refuseIncomingV2(t, two, n2, n2.signer, legacy)
		var changed messageEnvelope
		try.To(wire.UnmarshalCanonical(&changed, legacy))
		changed.Version = 2
		refuseIncomingV2(t, two, n2, n2.signer,
			try.To1(wire.Marshal(changed)))

		// Keep each reader's own valid establishment/first-use history. Only
		// the shared inbox slot is substituted, so version refusal is explicit.
		row1 := outgoingTestState(t, n1.own.vault)["root"][inboxKey]
		row2 := outgoingTestState(t, n2.own.vault)["root"][inboxKey]
		try.To(n1.own.vault.Update(func(tx storage.WriteTx) error {
			return tx.Put([]byte(inboxKey), row2)
		}))
		try.To(n2.own.vault.Update(func(tx storage.WriteTx) error {
			return tx.Put([]byte(inboxKey), row1)
		}))
		refuseIncoming(t, one, n1, n1.signer, raw1)
		refuseIncomingV2(t, two, n2, n2.signer, raw2)
		refuseMessageReceipt(t, one, n1, n1.signer, raw1)
		refuseMessageReceiptV2(t, two, n2, n2.signer, raw2)
		n1.own.unchanged(t, func() {
			projection, err := ReadMessageInbox(n1.own.vault,
				one.root.public, n1.local)
			assert.Equal(err, errMessageInbox)
			assert.DeepEqual(projection, MessageInbox{})
		})
	}
}

func TestIncomingCompositionOwnsInputsV2(t *testing.T) {
	defer assert.PushTester(t)()
	f, n, raw := incomingTestV2(t, 0, "owned across admission and receipt")
	expected := messageBindingV2(t, n.other.vault, f.root.public, n.peer)
	root, local, original := append([]byte(nil), f.root.public...),
		append([]byte(nil), n.local...), append([]byte(nil), raw...)
	signer := &probeSigner{Handle: n.signer}
	signer.sign = func(d []byte) ([]byte, error) {
		clear(root)
		clear(local)
		clear(raw)
		return n.signer.Sign(d)
	}
	n.other.unchanged(t, func() {
		receipt := try.To1(AcceptMessageAndReceiptV2(n.own.vault, root,
			local, signer, f.messageRuntime(n), raw))
		try.To1(decodeMessageReceiptV2(receipt, original, expected))
	})
	for _, bad := range [][]byte{nil, make([]byte, maxMessageEnvelopeBytes+1)} {
		n.own.unchanged(t, func() {
			receipt, err := AcceptMessageAndReceiptV2(n.own.vault,
				f.root.public, n.local, n.signer, f.messageRuntime(n), bad)
			assert.Equal(err, errIncoming)
			assert.SNil(receipt)
		})
	}
}
