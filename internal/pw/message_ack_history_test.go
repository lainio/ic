package pw

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func invalidACKReceipts(t *testing.T, f *requesterFixture,
	n outgoingTestNode, envelope, valid []byte, receiver key.Handle,
) map[string][]byte {
	t.Helper()
	defer assert.PushTester(t)()
	var receipt messageReceipt
	try.To(wire.UnmarshalCanonical(&receipt, valid))
	invalid := map[string][]byte{
		"empty": {}, "malformed": {0xff},
		"oversize":     make([]byte, maxMessageReceiptBytes+1),
		"noncanonical": append([]byte{0x98, 3}, valid[1:]...),
		"tag":          append([]byte{0xc0}, valid...),
		"trailing":     append(bytes.Clone(valid), 0),
		"wrong signer": signTestReceipt(t, receipt, n.signer,
			messageReceiptPurpose),
		"wrong purpose": signTestReceipt(t, receipt, receiver,
			messageAuthPurpose),
	}
	for name, change := range map[string]func(*messageReceipt){
		"version": func(r *messageReceipt) { r.Version++ },
		"forged":  func(r *messageReceipt) { r.Signature[0] ^= 1 },
		"ID":      func(r *messageReceipt) { r.Payload.ID[0] ^= 1 },
		"root":    func(r *messageReceipt) { r.Payload.Binding.Root = n.local },
		"target":  func(r *messageReceipt) { r.Payload.Binding.Sender = n.peer },
		"issuer":  func(r *messageReceipt) { r.Payload.Binding.Receiver = f.root.public },
		"role": func(r *messageReceipt) {
			r.Payload.Binding.Requester = !r.Payload.Binding.Requester
		},
		"request": func(r *messageReceipt) { r.Payload.Binding.RequestDigest[0] ^= 1 },
		"history": func(r *messageReceipt) { r.Payload.Binding.AcceptedDigest[0] ^= 1 },
	} {
		var changed messageReceipt
		try.To(wire.UnmarshalCanonical(&changed, valid))
		change(&changed)
		invalid[name] = try.To1(wire.Marshal(changed))
		if name != "forged" {
			invalid["signed/"+name] = signTestReceipt(t, changed, receiver,
				messageReceiptPurpose)
		}
	}
	// An honest receiver signature asserting another envelope is inapplicable,
	// even when that envelope has exactly the same message/ID and new signature.
	var packet messageEnvelope
	try.To(wire.UnmarshalCanonical(&packet, envelope))
	for _, changedText := range []bool{false, true} {
		message := packet.Message
		if changedText {
			var changed outgoingMessage
			try.To(wire.UnmarshalCanonical(&changed, message))
			changed.Text = "different signed text"
			message = try.To1(wire.Marshal(changed))
		}
		other := signMessageEnvelope(t, message, n.signer)
		receipt.Payload = try.To1(receiptPayloadForEnvelope(other,
			receipt.Payload.Binding))
		invalid[fmt.Sprint("other envelope/", changedText)] = signTestReceipt(
			t, receipt, receiver, messageReceiptPurpose)
	}
	_, foreignNode, _, foreign := ackTest(t, 0)
	assert.ThatNot(bytes.Equal(foreignNode.local, n.local))
	invalid["foreign"] = foreign
	return invalid
}

func TestMessageACKReceiptAuthenticationIncludingRepeat(t *testing.T) {
	defer assert.PushTester(t)()
	for sender := range 2 {
		f, n, envelope, receipt := ackTest(t, sender)
		receiver := outgoingTestNodes(f)[1-sender]
		invalid := invalidACKReceipts(t, f, n, envelope, receipt,
			receiver.signer)
		for _, repeat := range []bool{false, true} {
			if repeat {
				assert.That(try.To1(observeMessageReceipt(n.own.vault,
					f.root.public, n.local, receipt)))
			}
			for name, bad := range invalid {
				t.Run(fmt.Sprint(sender, "/", repeat, "/", name),
					func(t *testing.T) {
						refuseMessageACK(t, f, n, bad)
					})
			}
		}
	}
}

func TestMessageACKInvalidSavedRow(t *testing.T) {
	defer assert.PushTester(t)()
	for sender := range 2 {
		f, n, envelope, receipt := ackTest(t, sender)
		receiver := outgoingTestNodes(f)[1-sender]
		original := try.To1(wire.Marshal(messageACK{Version: 1,
			Receipt: receipt}))
		invalid := map[string][]byte{
			"empty": {}, "malformed": {0xff},
			"oversize":     make([]byte, maxMessageACKBytes+1),
			"noncanonical": append([]byte{0x98, 2}, original[1:]...),
			"trailing":     append(bytes.Clone(original), 0),
			"version": try.To1(wire.Marshal(messageACK{Version: 2,
				Receipt: receipt})),
		}
		for name, bad := range invalidACKReceipts(t, f, n, envelope,
			receipt, receiver.signer) {
			invalid["receipt/"+name] = try.To1(wire.Marshal(messageACK{
				Version: 1, Receipt: bad,
			}))
		}
		for name, bad := range invalid {
			t.Run(n.name+"/"+name, func(t *testing.T) {
				defer assert.PushTester(t)()
				try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
					return tx.Put([]byte(messageACKKey), bad)
				}))
				refuseMessageACK(t, f, n, receipt)
			})
		}
		try.To(n.own.vault.Update(func(tx storage.WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			try.To(tx.Delete([]byte(messageACKKey)))
			try.To1(tx.EnsureChild([]byte(messageACKKey)))
			return nil
		}))
		refuseMessageACK(t, f, n, receipt)
	}
}

func TestMessageACKExactHistoricalEvidence(t *testing.T) {
	for sender := range 2 {
		for _, repeat := range []bool{false, true} {
			for _, mode := range []string{"missing outgoing", "corrupt outgoing",
				"changed outgoing", "missing envelope", "corrupt envelope",
				"resigned envelope", "missing acceptance", "corrupt acceptance",
				"foreign acceptance", "resigned acceptance", "acceptance version",
				"acceptance noncanonical", "role", "missing first use",
				"first use version", "first use request", "first use response",
				"first use noncanonical", "no historical response", "Await",
				"contradictory role", "invitation"} {
				t.Run(fmt.Sprint(sender, "/", repeat, "/", mode),
					func(t *testing.T) {
						defer assert.PushTester(t)()
						f, n, envelope, receipt := ackTest(t, sender)
						if repeat {
							assert.That(
								try.To1(observeMessageReceipt(n.own.vault,
									f.root.public, n.local, receipt)),
							)
						}
						rows := outgoingTestState(t, n.own.vault)["root"]
						name, bad := changedACKHistory(t, f, n, rows, mode)
						try.To(
							n.own.vault.Update(func(tx storage.WriteTx) error {
								if bad == nil {
									return tx.Delete([]byte(name))
								}
								return tx.Put([]byte(name), bad)
							}),
						)
						refuseMessageACK(t, f, n, receipt)
						// The receipt is mathematically valid. Its trust anchor
						// cannot be supplied by itself or bypass corrupt history.
						var original outgoingMessage
						try.To(
							wire.UnmarshalCanonical(
								&original,
								rows[outgoingKey],
							),
						)
						try.To1(
							decodeMessageReceipt(
								receipt,
								envelope,
								original.Binding,
							),
						)
					},
				)
			}
		}
	}
}

func changedACKHistory(t *testing.T, f *requesterFixture, n outgoingTestNode,
	rows map[string][]byte, mode string,
) (string, []byte) {
	t.Helper()
	defer assert.PushTester(t)()
	var history acceptedRecord
	try.To(wire.UnmarshalCanonical(&history, rows[acceptedKey]))
	firstUse := firstUseKey
	if n.name == "Bob" {
		firstUse = useSeenKey
	}
	switch mode {
	case "missing outgoing":
		return outgoingKey, nil
	case "corrupt outgoing":
		return outgoingKey, []byte{0xff}
	case "changed outgoing":
		var message outgoingMessage
		try.To(wire.UnmarshalCanonical(&message, rows[outgoingKey]))
		message.Text = "changed local message under the same ID"
		return outgoingKey, try.To1(wire.Marshal(message))
	case "missing envelope":
		return messageEnvelopeKey, nil
	case "corrupt envelope":
		return messageEnvelopeKey, []byte{0xff}
	case "resigned envelope":
		return messageEnvelopeKey, signMessageEnvelope(t, rows[outgoingKey],
			n.signer)
	case "missing acceptance":
		return acceptedKey, nil
	case "corrupt acceptance":
		return acceptedKey, []byte{0xff}
	case "foreign acceptance":
		foreign := newOutgoing(t)
		return acceptedKey, requesterRecords(t, foreign.alice.vault)[1]
	case "resigned acceptance":
		var accepted SignedAccepted
		try.To(wire.UnmarshalCanonical(&accepted, history.Response))
		digest := key.HashTagged(AcceptedPurpose,
			try.To1(wire.Marshal(accepted.Payload)))
		accepted.Signature = try.To1(f.local.handle.Sign(digest[:]))
		history.Response = try.To1(wire.Marshal(accepted))
		return acceptedKey, try.To1(wire.Marshal(history))
	case "acceptance version":
		history.Version++
		return acceptedKey, try.To1(wire.Marshal(history))
	case "acceptance noncanonical":
		return acceptedKey, append([]byte{0x98, 3}, rows[acceptedKey][1:]...)
	case "role":
		if n.name == "Alice" {
			return attemptKey, nil
		}
		return attemptKey, history.Request
	case "missing first use":
		return firstUse, nil
	case "first use noncanonical":
		raw := rows[firstUse]
		return firstUse, append([]byte{0x98, raw[0] & 0x1f}, raw[1:]...)
	case "contradictory role":
		if n.name == "Alice" {
			return useSeenKey, []byte{0xff}
		}
		return firstUseKey, []byte{0xff}
	case "invitation":
		return invitationKey, []byte{0xff}
	default:
		return changedIncomingFirstUse(t, n, rows, mode)
	}
}
