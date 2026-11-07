package pw

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func ackTestV2(t *testing.T, sender int,
) (*firstUseFixtureV2, outgoingTestNode, []byte, []byte) {
	t.Helper()
	defer assert.PushTester(t)()
	f, receiver, envelope, _ := receiptTestV2(t, 1-sender)
	receipt := try.To1(IssueMessageReceiptV2(receiver.own.vault, f.root.public,
		receiver.local, receiver.signer, f.messageRuntime(receiver), envelope))
	return f, outgoingTestNodes(f.requesterFixture)[sender], envelope, receipt
}

func refuseMessageACKV2(t *testing.T, f *firstUseFixtureV2,
	n outgoingTestNode, raw []byte,
) {
	t.Helper()
	defer assert.PushTester(t)()
	before := outgoingTestState(t, n.own.vault)
	n.other.unchanged(t, func() {
		n.own.unchanged(t, func() {
			saved, err := ObserveMessageReceiptV2(n.own.vault, f.root.public,
				n.local, raw)
			assert.Equal(err, errMessageACK)
			assert.ThatNot(saved)
		})
	})
	assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
}

func TestMessageACKAndInboxEitherSenderV2(t *testing.T) {
	for sender := range 2 {
		for _, text := range []string{"a", strings.Repeat("é", 512)} {
			t.Run(fmt.Sprint(sender, "/", len(text)), func(t *testing.T) {
				defer assert.PushTester(t)()
				f, receiver, envelope := incomingTestV2(t, 1-sender, text)
				n := outgoingTestNodes(f.requesterFixture)[sender]
				assert.DeepEqual(try.To1(ReadMessageInboxV2(n.other.vault,
					f.root.public, n.peer)), MessageInbox{})
				before, other := outgoingTestState(t, n.own.vault),
					outgoingTestState(t, n.other.vault)
				var first []byte
				n.own.unchanged(t, func() {
					first = try.To1(AcceptMessageAndReceiptV2(n.other.vault,
						f.root.public, n.peer, receiver.signer,
						f.messageRuntime(receiver), envelope))
				})
				other["root"][inboxKey] = try.To1(wire.Marshal(inboxMessage{
					Version: 2, Envelope: envelope,
				}))
				assert.DeepEqual(outgoingTestState(t, n.other.vault), other)
				second := try.To1(IssueMessageReceiptV2(n.other.vault,
					f.root.public, n.peer, receiver.signer,
					f.messageRuntime(receiver), envelope))
				assert.ThatNot(bytes.Equal(first, second))
				expected := messageBindingV2(t, n.own.vault, f.root.public,
					n.local)
				a := try.To1(decodeMessageReceiptV2(first, envelope, expected))
				b := try.To1(decodeMessageReceiptV2(second, envelope, expected))
				assert.DeepEqual(a.Payload, b.Payload)
				want := MessageInbox{Present: true, ID: [16]byte(a.Payload.ID),
					Text: text}
				assert.That(want.ID[6]>>4 == 4 && want.ID[8]>>6 == 2)
				n.other.reopen(t)
				n.other.lease.remaining.Store(0)
				n.other.unchanged(t, func() {
					got := try.To1(ReadMessageInboxV2(n.other.vault,
						f.root.public, n.peer))
					assert.DeepEqual(got, want)
					got.ID[0] ^= 1
					got.Text = "owned replacement"
					assert.DeepEqual(try.To1(ReadMessageInboxV2(n.other.vault,
						f.root.public, n.peer)), want)
				})

				// No receiver Vault, signer, listener or dispatch marker needed.
				try.To(n.other.db.Close())
				remaining := n.own.lease.remaining.Load()
				n.other.unchanged(t, func() {
					assert.That(try.To1(ObserveMessageReceiptV2(n.own.vault,
						f.root.public, n.local, first)))
				})
				assert.Equal(n.own.lease.remaining.Load(), remaining-1)
				before["root"][messageACKKey] = try.To1(wire.Marshal(messageACK{
					Version: 2, Receipt: first,
				}))
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				assert.SNil(before["root"][inboxKey])
				assert.SNil(other["root"][outgoingKey])
				assert.SNil(other["root"][messageACKKey])
				assert.SNil(before["root"][messageSentKey])
				assert.SNil(other["root"][messageSentKey])
				n.own.reopen(t)
				n.own.lease.remaining.Store(0)
				for _, raw := range [][]byte{first, second, first} {
					n.own.unchanged(t, func() {
						assert.ThatNot(try.To1(ObserveMessageReceiptV2(
							n.own.vault, f.root.public, n.local, raw)))
					})
				}
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				n.other.reopen(t)
				assert.DeepEqual(outgoingTestState(t, n.other.vault), other)
			})
		}
	}
}

func TestMessageACKRejectsReceiptsV2(t *testing.T) {
	defer assert.PushTester(t)()
	for sender := range 2 {
		f, n, envelope, valid := ackTestV2(t, sender)
		receiver := outgoingTestNodes(f.requesterFixture)[1-sender]
		_, _, _, legacy := ackTest(t, sender)
		_, _, _, foreign := ackTestV2(t, sender)
		invalid := map[string][]byte{
			"empty": {}, "malformed": {0xff}, "v1": legacy,
			"foreign":          foreign,
			"oversize":         make([]byte, maxMessageReceiptBytesV2+1),
			"array":            append([]byte{0x98, 3}, valid[1:]...),
			"version encoding": append([]byte{0x83, 0x18, 2}, valid[2:]...),
			"payload encoding": append([]byte{0x83, 2, 0x98, 3}, valid[3:]...),
			"tag":              append([]byte{0xc0}, valid...),
			"trailing":         append(bytes.Clone(valid), 0),
		}
		var receipt messageReceiptV2
		try.To(wire.UnmarshalCanonical(&receipt, valid))
		for name, change := range map[string]func(*messageReceiptV2){
			"version":           func(r *messageReceiptV2) { r.Version = 1 },
			"digest":            func(r *messageReceiptV2) { r.Payload.EnvelopeDigest[0] ^= 1 },
			"ID":                func(r *messageReceiptV2) { r.Payload.ID[0] ^= 1 },
			"ID length":         func(r *messageReceiptV2) { r.Payload.ID = nil },
			"root":              func(r *messageReceiptV2) { r.Payload.Binding.Root = n.local },
			"sender":            func(r *messageReceiptV2) { r.Payload.Binding.Sender = n.peer },
			"receiver":          func(r *messageReceiptV2) { r.Payload.Binding.Receiver = n.local },
			"role":              func(r *messageReceiptV2) { r.Payload.Binding.Requester = !r.Payload.Binding.Requester },
			"request":           func(r *messageReceiptV2) { r.Payload.Binding.RequestDigest[0] ^= 1 },
			"accepted contacts": func(r *messageReceiptV2) { r.Payload.Binding.AcceptedDigest[0] ^= 1 },
		} {
			var changed messageReceiptV2
			try.To(wire.UnmarshalCanonical(&changed, valid))
			change(&changed)
			invalid["tampered/"+name] = try.To1(wire.Marshal(changed))
			invalid["signed/"+name] = signTestReceiptV2(t, changed,
				receiver.signer, messageReceiptPurposeV2)
		}
		for _, purpose := range []string{messageReceiptPurpose,
			messageAuthPurposeV2, messageReceiptEnvelopePurposeV2} {
			invalid[purpose] = signTestReceiptV2(t, receipt, receiver.signer,
				purpose)
		}
		invalid["sender signed"] = signTestReceiptV2(t, receipt, n.signer,
			messageReceiptPurposeV2)
		invalid["root signed"] = signTestReceiptV2(t, receipt, f.root.handle,
			messageReceiptPurposeV2)
		for name, sig := range map[string][]byte{
			"empty signature": nil, "bad DER": {1, 2, 3},
			"long DER":     make([]byte, 73),
			"trailing DER": append(bytes.Clone(receipt.Signature), 0),
		} {
			changed := receipt
			changed.Signature = sig
			invalid[name] = try.To1(wire.Marshal(changed))
		}
		var packet messageEnvelopeV2
		try.To(wire.UnmarshalCanonical(&packet, envelope))
		resigned := signMessageEnvelopeV2(t, packet.Message, n.signer)
		receipt.Payload = try.To1(receiptPayloadForEnvelopeV2(resigned,
			messageBindingV2(t, n.own.vault, f.root.public, n.local)))
		invalid["receipt for resigned envelope"] = signTestReceiptV2(t,
			receipt, receiver.signer, messageReceiptPurposeV2)
		for _, committed := range []bool{false, true} {
			if committed {
				assert.That(try.To1(ObserveMessageReceiptV2(n.own.vault,
					f.root.public, n.local, valid)))
			}
			for name, bad := range invalid {
				t.Run(fmt.Sprint(n.name, "/", committed, "/", name),
					func(t *testing.T) { refuseMessageACKV2(t, f, n, bad) })
			}
		}
	}
}

func TestMessageACKOwnerSerializationV2(t *testing.T) {
	defer assert.PushTester(t)()
	for sender := range 2 {
		f, n, envelope, receipt := ackTestV2(t, sender)
		receiver := outgoingTestNodes(f.requesterFixture)[1-sender]
		second := try.To1(IssueMessageReceiptV2(n.other.vault, f.root.public,
			n.peer, receiver.signer, f.messageRuntime(receiver), envelope))
		var owner sync.Mutex
		type result struct {
			saved bool
			err   error
			raw   []byte
		}
		results := make(chan result, 2)
		remaining := n.own.lease.remaining.Load()
		n.other.unchanged(t, func() {
			for _, raw := range [][]byte{receipt, second} {
				go func() {
					owner.Lock()
					defer owner.Unlock()
					saved, err := ObserveMessageReceiptV2(n.own.vault,
						f.root.public, n.local, raw)
					results <- result{saved, err, raw}
				}()
			}
			a, b := <-results, <-results
			try.To(a.err)
			try.To(b.err)
			assert.That(a.saved != b.saved)
			if !a.saved {
				a = b
			}
			var ack messageACK
			try.To(wire.UnmarshalCanonical(&ack,
				outgoingTestState(t, n.own.vault)["root"][messageACKKey]))
			assert.DeepEqual(ack.Receipt, a.raw)
		})
		assert.Equal(n.own.lease.remaining.Load(), remaining-1)
	}
}

func TestMessageACKAndInboxPinnedInputsV2(t *testing.T) {
	defer assert.PushTester(t)()
	for sender := range 2 {
		f, n, _, receipt := ackTestV2(t, sender)
		for _, tc := range []struct {
			vault       *storage.Vault
			root, local key.Public
		}{
			{nil, f.root.public, n.local},
			{n.own.vault, nil, n.local},
			{n.own.vault, f.root.public, nil},
			{n.own.vault, n.peer, n.local},
			{n.own.vault, f.root.public, n.peer},
			{n.other.vault, f.root.public, n.local},
		} {
			n.other.unchanged(t, func() {
				n.own.unchanged(t, func() {
					saved, err := ObserveMessageReceiptV2(tc.vault, tc.root,
						tc.local, receipt)
					assert.Equal(err, errMessageACK)
					assert.ThatNot(saved)
					got, err := ReadMessageInboxV2(tc.vault, tc.root, tc.local)
					assert.Equal(err, errMessageInbox)
					assert.DeepEqual(got, MessageInbox{})
				})
			})
		}
	}
}
