package pw

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/storage"
)

func refuseMessageInboxV2(t *testing.T, f *firstUseFixtureV2,
	n outgoingTestNode,
) {
	t.Helper()
	defer assert.PushTester(t)()
	n.other.unchanged(t, func() {
		n.own.unchanged(t, func() {
			got, err := ReadMessageInboxV2(n.own.vault, f.root.public, n.local)
			assert.Equal(err, errMessageInbox)
			assert.DeepEqual(got, MessageInbox{})
		})
	})
}

func TestMessageInboxCorruptSavedRecordsV2(t *testing.T) {
	defer assert.PushTester(t)()
	for receiver := range 2 {
		f, n, raw, _ := receiptTestV2(t, receiver)
		sender := outgoingTestNodes(f.requesterFixture)[1-receiver]
		original := outgoingTestState(t, n.own.vault)["root"][inboxKey]
		_, _, legacy := incomingTest(t, receiver, "foreign v1 plaintext")
		_, _, foreign := incomingTestV2(t, receiver, "foreign v2 plaintext")
		invalid := map[string][]byte{
			"empty": {}, "malformed": {0xff},
			"oversize":     make([]byte, maxInboxBytes+1),
			"noncanonical": append([]byte{0x98, 2}, original[1:]...),
			"tag":          append([]byte{0xc0}, original...),
			"trailing":     append(bytes.Clone(original), 0),
			"version": try.To1(wire.Marshal(inboxMessage{
				Version: 1, Envelope: raw,
			})),
			"v1 envelope": try.To1(wire.Marshal(inboxMessage{
				Version: 2, Envelope: legacy,
			})),
			"foreign": try.To1(wire.Marshal(inboxMessage{
				Version: 2, Envelope: foreign,
			})),
		}
		for name, bad := range incomingWireCasesV2(t, raw, sender.signer,
			f.root.handle) {
			// As in v1, the authenticated Vault is the saved-envelope anchor.
			// A fully signed new body/ID is valid before admission; the reader
			// has no separate copy against which to detect a direct Vault edit.
			if name == "signed/changed ID" || name == "signed/changed body" {
				continue
			}
			invalid[name] = try.To1(wire.Marshal(inboxMessage{
				Version: 2, Envelope: bad,
			}))
		}
		n.own.lease.remaining.Store(int64(len(invalid) + 1))
		for name, bad := range invalid {
			t.Run(n.name+"/"+name, func(t *testing.T) {
				defer assert.PushTester(t)()
				try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
					return tx.Put([]byte(inboxKey), bad)
				}))
				refuseMessageInboxV2(t, f, n)
			})
		}
		try.To(n.own.vault.Update(func(tx storage.WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			try.To(tx.Delete([]byte(inboxKey)))
			try.To1(tx.EnsureChild([]byte(inboxKey)))
			return nil
		}))
		refuseMessageInboxV2(t, f, n)
	}
}

func TestMessageInboxConflictingAdmissionPreservesReadV2(t *testing.T) {
	defer assert.PushTester(t)()
	for receiver := range 2 {
		f, n, raw, _ := receiptTestV2(t, receiver)
		sender := outgoingTestNodes(f.requesterFixture)[1-receiver]
		want := try.To1(ReadMessageInboxV2(n.own.vault, f.root.public, n.local))
		var envelope messageEnvelopeV2
		try.To(wire.UnmarshalCanonical(&envelope, raw))
		changed := changedEnvelopeMessages(t, envelope.Message)
		for _, message := range [][]byte{envelope.Message,
			changed["changed body"], changed["changed ID"]} {
			conflict := signMessageEnvelopeV2(t, message, sender.signer)
			assert.ThatNot(bytes.Equal(conflict, raw))
			refuseIncomingV2(t, f, n, n.signer, conflict)
			n.own.unchanged(t, func() {
				assert.DeepEqual(try.To1(ReadMessageInboxV2(n.own.vault,
					f.root.public, n.local)), want)
			})
		}
	}
}

func TestMessageHistoricalACKAndInboxAfterEligibilityLossV2(t *testing.T) {
	for local := range 2 {
		for _, guard := range []string{"deny", "delete", "own Known",
			"peer Known", "authorization", "signer", "stopped", "origin"} {
			t.Run(fmt.Sprint(local, "/", guard), func(t *testing.T) {
				defer assert.PushTester(t)()
				f, n, envelope, receipt := ackTestV2(t, local)
				peer := outgoingTestNodes(f.requesterFixture)[1-local]
				try.To1(CreateOutgoingV2(peer.own.vault, f.root.public,
					peer.local, peer.signer, f.messageRuntime(peer), "reply"))
				reverse := try.To1(PrepareOutgoingEnvelopeV2(
					peer.own.vault,
					f.root.public,
					peer.local,
					peer.signer,
					f.messageRuntime(peer),
				))
				try.To1(AcceptMessageAndReceiptV2(n.own.vault, f.root.public,
					n.local, n.signer, f.messageRuntime(n), reverse))
				want := try.To1(ReadMessageInboxV2(n.own.vault, f.root.public,
					n.local))
				f.now = f.now.Add(24 * time.Hour)
				assert.That(try.To1(f.expireUseV2(false)))
				// Current ads are not historical authority. Remove/replace them.
				try.To(n.own.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					if try.To1(tx.HasChild([]byte("local-current-ad-v1"))) {
						try.To(try.To1(tx.ChildForUpdate(
							[]byte("local-current-ad-v1"))).Put(
							[]byte("slot-1"), []byte("unrelated current ad")))
					}
					return tx.Delete([]byte("verified-ad-claims-v1"))
				}))
				runtime := f.messageRuntime(n)
				signer := &probeSigner{Handle: n.signer}
				switch guard {
				case "signer":
					signer.signErr = errors.New("private unavailable signer")
				case "stopped":
					runtime.Running = false
				case "origin":
					runtime.BoundOrigin = "http://127.0.0.1:8888"
				default:
					try.To(mutateEnvelopeGuard(n, f.root.public, guard))
				}
				before, other := outgoingTestState(t, n.own.vault),
					outgoingTestState(t, n.other.vault)
				n.other.unchanged(t, func() {
					assert.That(try.To1(ObserveMessageReceiptV2(n.own.vault,
						f.root.public, n.local, receipt)))
				})
				before["root"][messageACKKey] = try.To1(wire.Marshal(messageACK{
					Version: 2, Receipt: receipt,
				}))
				assert.Equal(signer.signCalls.Load(), 0)
				assert.Equal(signer.publicCalls.Load(), 0)
				n.own.reopen(t)
				n.own.lease.remaining.Store(0)
				n.own.unchanged(t, func() {
					assert.DeepEqual(try.To1(ReadMessageInboxV2(n.own.vault,
						f.root.public, n.local)), want)
					assert.ThatNot(try.To1(ObserveMessageReceiptV2(n.own.vault,
						f.root.public, n.local, receipt)))
					assert.Equal(signer.signCalls.Load(), 0)
					var packet messageEnvelopeV2
					var outgoing outgoingMessageV2
					try.To(wire.UnmarshalCanonical(&packet, envelope))
					try.To(wire.UnmarshalCanonical(&outgoing, packet.Message))
					_, err := CreateOutgoingV2(n.own.vault, f.root.public,
						n.local, signer, runtime, outgoing.Text)
					assert.Equal(err, errOutgoing)
					_, err = PrepareOutgoingEnvelopeV2(n.own.vault,
						f.root.public, n.local, signer, runtime)
					assert.Equal(err, errMessageEnvelope)
					saved, err := AdmitIncomingEnvelopeV2(n.own.vault,
						f.root.public, n.local, signer, runtime, reverse)
					assert.Equal(err, errIncoming)
					assert.ThatNot(saved)
					_, err = IssueMessageReceiptV2(n.own.vault, f.root.public,
						n.local, signer, runtime, reverse)
					assert.Equal(err, errMessageReceipt)
				})
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				assert.DeepEqual(outgoingTestState(t, n.other.vault), other)
			})
		}
	}
}
