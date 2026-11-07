package pw

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// Only the sender prepares outgoing bytes. Admission receives its peer's exact
// bytes and independently authenticates its own accepted/first-use history.
func incomingTestV2(t *testing.T, receiver int, text string,
) (*firstUseFixtureV2, outgoingTestNode, []byte) {
	t.Helper()
	defer assert.PushTester(t)()
	f := newOutgoingV2(t)
	nodes := outgoingTestNodes(f.requesterFixture)
	n, sender := nodes[receiver], nodes[1-receiver]
	try.To1(CreateOutgoingV2(sender.own.vault, f.root.public, sender.local,
		sender.signer, f.messageRuntime(sender), text))
	raw := try.To1(PrepareOutgoingEnvelopeV2(sender.own.vault, f.root.public,
		sender.local, sender.signer, f.messageRuntime(sender)))
	return f, n, raw
}

func refuseIncomingV2(t *testing.T, f *firstUseFixtureV2,
	n outgoingTestNode, signer key.Handle, raw []byte,
) {
	t.Helper()
	defer assert.PushTester(t)()
	before := outgoingTestState(t, n.own.vault)
	n.other.unchanged(t, func() {
		n.own.unchanged(t, func() {
			saved, err := AdmitIncomingEnvelopeV2(n.own.vault, f.root.public,
				n.local, signer, f.messageRuntime(n), raw)
			assert.Equal(err, errIncoming)
			assert.ThatNot(saved)
		})
	})
	assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
}

func receiptTestV2(t *testing.T, receiver int,
) (*firstUseFixtureV2, outgoingTestNode, []byte, outgoingBindingV2) {
	t.Helper()
	defer assert.PushTester(t)()
	f, n, raw := incomingTestV2(t, receiver, "private v2 receipt plaintext")
	// Expected receipt authority comes from SENDER history, never the receipt.
	expected := messageBindingV2(t, n.other.vault, f.root.public, n.peer)
	assert.That(try.To1(AdmitIncomingEnvelopeV2(n.own.vault, f.root.public,
		n.local, n.signer, f.messageRuntime(n), raw)))
	return f, n, raw, expected
}

func refuseMessageReceiptV2(t *testing.T, f *firstUseFixtureV2,
	n outgoingTestNode, signer key.Handle, raw []byte,
) {
	t.Helper()
	defer assert.PushTester(t)()
	before := outgoingTestState(t, n.own.vault)
	n.other.unchanged(t, func() {
		n.own.unchanged(t, func() {
			got, err := IssueMessageReceiptV2(n.own.vault, f.root.public,
				n.local, signer, f.messageRuntime(n), raw)
			assert.Equal(err, errMessageReceipt)
			assert.SNil(got)
		})
	})
	assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
}

func TestIncomingBothDirectionsAndReceiptV2(t *testing.T) {
	for _, first := range []int{0, 1} {
		t.Run(fmt.Sprint(first), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOutgoingV2(t)
			nodes := outgoingTestNodes(f.requesterFixture)
			var envelopes [2][]byte
			// Both outgoing slots can be prepared while both inboxes are empty.
			for i, n := range nodes {
				text := "a"
				if i == 1 {
					text = strings.Repeat("é", 512)
				}
				try.To1(CreateOutgoingV2(n.own.vault, f.root.public, n.local,
					n.signer, f.messageRuntime(n), text))
				envelopes[i] = try.To1(PrepareOutgoingEnvelopeV2(n.own.vault,
					f.root.public, n.local, n.signer, f.messageRuntime(n)))
				assert.SNil(outgoingTestState(t, n.own.vault)["root"][inboxKey])
			}
			for _, i := range []int{first, 1 - first} {
				n, sender, raw := nodes[i], nodes[1-i], envelopes[1-i]
				runtime := f.messageRuntime(n)
				expected := messageBindingV2(t, sender.own.vault,
					f.root.public, sender.local)
				var localExpected outgoingBindingV2
				try.To(n.own.vault.View(func(tx storage.ReadTx) (err error) {
					defer err2.Handle(&err, nil)
					localExpected = try.To1(incomingPrerequisitesV2(tx,
						f.root.public, n.local, runtime))
					return nil
				}))
				assert.DeepEqual(localExpected, expected)
				assert.Equal(expected.Requester, sender.name == "Alice")
				before := outgoingTestState(t, n.own.vault)
				remaining := n.own.lease.remaining.Load()
				var firstReceipt []byte
				n.other.unchanged(t, func() {
					firstReceipt = try.To1(AcceptMessageAndReceiptV2(
						n.own.vault, f.root.public, n.local, n.signer,
						runtime, raw))
				})
				assert.Equal(n.own.lease.remaining.Load(), remaining-1)
				before["root"][inboxKey] = try.To1(wire.Marshal(inboxMessage{
					Version: 2, Envelope: raw,
				}))
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				assert.SNil(before["root"][messageSentKey])
				assert.SNil(before["root"][messageACKKey])
				assert.SNotEmpty(before["root"][outgoingKey])
				verified := try.To1(decodeMessageReceiptV2(
					firstReceipt, raw, expected))
				assert.Equal(verified.Version, 2)
				assert.DeepEqual(verified.Payload.Binding, expected)
				envelope := try.To1(decodeMessageEnvelopeV2(raw, expected))
				message := try.To1(decodeOutgoingV2(envelope.Message, expected))
				assert.DeepEqual(verified.Payload.ID, message.ID)
				digest := key.HashTagged(messageReceiptEnvelopePurposeV2, raw)
				assert.DeepEqual(verified.Payload.EnvelopeDigest, digest[:])
				digest = key.HashTagged(messageReceiptPurposeV2,
					try.To1(wire.Marshal(verified.Payload)))
				assert.That(verified.Signature.Verify(n.local, digest[:]))
				assert.ThatNot(verified.Signature.Verify(n.peer, digest[:]))
				assert.That(len(firstReceipt) <= maxMessageReceiptBytesV2)

				n.own.reopen(t)
				n.own.lease.remaining.Store(0)
				n.other.unchanged(t, func() {
					n.own.unchanged(t, func() {
						assert.ThatNot(try.To1(AdmitIncomingEnvelopeV2(
							n.own.vault, f.root.public, n.local, n.signer,
							runtime, raw)))
						again := try.To1(IssueMessageReceiptV2(n.own.vault,
							f.root.public, n.local, n.signer, runtime, raw))
						receipt := try.To1(
							decodeMessageReceiptV2(again, raw, expected),
						)
						assert.DeepEqual(receipt.Payload, verified.Payload)
						assert.ThatNot(bytes.Equal(again, firstReceipt))
						clear(receipt.Payload.Binding.Receiver)
						clear(receipt.Payload.ID)
						clear(again)
					})
				})
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
			}
		})
	}
}

func TestIncomingNoBootstrapOrRemotePolicyGuardV2(t *testing.T) {
	defer assert.PushTester(t)()
	for _, receiver := range []int{0, 1} {
		f, n, raw := incomingTestV2(t, receiver, "historical first use")
		expected := messageBindingV2(t, n.other.vault, f.root.public, n.peer)
		f.now = f.now.Add(24 * time.Hour)
		assert.That(try.To1(f.expireUseV2(false))) // Retained previous Ready.
		try.To(n.own.vault.Update(func(tx storage.WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			if try.To1(tx.HasChild([]byte("local-current-ad-v1"))) {
				try.To(
					try.To1(tx.ChildForUpdate([]byte("local-current-ad-v1"))).
						Delete([]byte("slot-1")),
				)
			}
			return tx.Delete([]byte("verified-ad-claims-v1"))
		}))
		sender := outgoingTestNodes(f.requesterFixture)[1-receiver]
		for _, guard := range []string{"deny", "delete", "authorization"} {
			try.To(mutateEnvelopeGuard(sender, f.root.public, guard))
		}
		n.other.unchanged(t, func() {
			receipt := try.To1(AcceptMessageAndReceiptV2(n.own.vault,
				f.root.public, n.local, n.signer, f.messageRuntime(n), raw))
			try.To1(decodeMessageReceiptV2(receipt, raw, expected))
		})
	}
}

func TestIncomingLocalFirstUseRequiredV2(t *testing.T) {
	for _, receiver := range []int{0, 1} {
		for _, state := range []string{"unestablished", "no first use",
			"Await", "Expired without Ready", "forged response"} {
			t.Run(fmt.Sprint(receiver, state), func(t *testing.T) {
				defer assert.PushTester(t)()
				f, n, raw := incomingTestV2(t, receiver, "first use required")
				try.To(n.own.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					if state == "unestablished" {
						for _, name := range []string{attemptKey, acceptedKey,
							heldKey, firstUseKey, useSeenKey, invitationKey} {
							try.To(tx.Delete([]byte(name)))
						}
						return nil
					}
					name := useSeenKey
					if n.name == "Alice" {
						name = firstUseKey
					}
					if state == "no first use" ||
						(n.name == "Bob" && state != "forged response") {
						return tx.Delete([]byte(name))
					}
					record, _ := try.To2(tx.Get([]byte(name)))
					if state == "forged response" {
						record[len(record)-1] ^= 1
					} else {
						var use firstUseRecord
						try.To(wire.UnmarshalCanonical(&use, record))
						use.State, use.Response = useAwait, nil
						if state == "Expired without Ready" {
							use.State = useExpired
						}
						record = try.To1(wire.Marshal(use))
					}
					return tx.Put([]byte(name), record)
				}))
				refuseIncomingV2(t, f, n, n.signer, raw)
				refuseMessageReceiptV2(t, f, n, n.signer, raw)
				assert.SNil(outgoingTestState(t, n.own.vault)["root"][inboxKey])
			})
		}
	}
}
