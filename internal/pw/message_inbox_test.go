package pw

import (
	"bytes"
	"errors"
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

var AdmitIncomingEnvelopeForTest = admitIncomingEnvelope

func TestMessageInboxEitherFirstOwnedAndReopen(t *testing.T) {
	for receiver := range 2 {
		t.Run(fmt.Sprint(receiver), func(t *testing.T) {
			defer assert.PushTester(t)()
			text := strings.Repeat("é", 512)
			f, n, raw := incomingTest(t, receiver, text)
			assert.DeepEqual(try.To1(ReadMessageInbox(n.own.vault,
				f.root.public, n.local)), MessageInbox{})
			assert.That(try.To1(admitIncomingEnvelope(n.own.vault,
				f.root.public, n.local, n.signer, raw)))
			var packet messageEnvelope
			var message outgoingMessage
			try.To(wire.UnmarshalCanonical(&packet, raw))
			try.To(wire.UnmarshalCanonical(&message, packet.Message))
			want := MessageInbox{Present: true, ID: [16]byte(message.ID),
				Text: text}
			assert.That(want.ID[6]>>4 == 4 && want.ID[8]>>6 == 2)
			// Historical expiry does not erase a successful first use.
			f.now = f.now.Add(24 * time.Hour)
			assert.That(try.To1(f.expireUse(false)))
			before := outgoingTestState(t, n.own.vault)
			other := outgoingTestState(t, n.other.vault)
			for range 2 {
				n.own.reopen(t)
				n.own.lease.remaining.Store(0)
				n.other.unchanged(t, func() {
					n.own.unchanged(t, func() {
						got := try.To1(ReadMessageInbox(n.own.vault,
							f.root.public, n.local))
						assert.DeepEqual(got, want)
						got.ID[0] ^= 1
						got.Text = "caller-owned replacement"
						assert.DeepEqual(try.To1(ReadMessageInbox(n.own.vault,
							f.root.public, n.local)), want)
						assert.DeepEqual(try.To1(ReadMessageInbox(n.other.vault,
							f.root.public, n.peer)), MessageInbox{})
					})
				})
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				assert.DeepEqual(outgoingTestState(t, n.other.vault), other)
			}
		})
	}
}

func TestMessageInboxHistoricalReadGrantsNoCurrentPermission(t *testing.T) {
	for receiver := range 2 {
		for _, guard := range []string{"deny", "delete", "own Known",
			"peer Known", "authorization", "signer"} {
			t.Run(fmt.Sprint(receiver, "/", guard), func(t *testing.T) {
				defer assert.PushTester(t)()
				f, n, raw := incomingTest(t, receiver, "retained history")
				assert.That(try.To1(admitIncomingEnvelope(n.own.vault,
					f.root.public, n.local, n.signer, raw)))
				want := try.To1(ReadMessageInbox(n.own.vault,
					f.root.public, n.local))
				signer := &probeSigner{Handle: n.signer}
				if guard == "signer" {
					signer.signErr = errors.New("private signer lost")
				} else {
					try.To(mutateEnvelopeGuard(n, f.root.public, guard))
				}
				n.own.reopen(t)
				n.other.unchanged(t, func() {
					n.own.unchanged(t, func() {
						assert.DeepEqual(try.To1(ReadMessageInbox(n.own.vault,
							f.root.public, n.local)), want)
						assert.Equal(signer.signCalls.Load(), 0)
						_, err := PrepareMessageSend(n.own.vault, f.root.public,
							n.local, signer, "new outgoing")
						assert.Error(err)
						refuseIncoming(t, f, n, signer, raw)
					})
				})
				// Also exercise admission into an empty slot under the changed
				// permission, not just an exact retry of the retained message.
				try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
					return tx.Delete([]byte(inboxKey))
				}))
				refuseIncoming(t, f, n, signer, raw)
				assert.DeepEqual(try.To1(ReadMessageInbox(n.own.vault,
					f.root.public, n.local)), MessageInbox{})
			})
		}
	}
}

func refuseMessageInbox(t *testing.T, f *requesterFixture,
	n outgoingTestNode,
) {
	t.Helper()
	defer assert.PushTester(t)()
	n.other.unchanged(t, func() {
		n.own.unchanged(t, func() {
			got, err := ReadMessageInbox(n.own.vault, f.root.public, n.local)
			assert.Equal(err, errMessageInbox)
			assert.DeepEqual(got, MessageInbox{})
		})
	})
}

func TestMessageInboxRejectsSavedCorruption(t *testing.T) {
	defer assert.PushTester(t)()
	for receiver := range 2 {
		f, n, raw := incomingTest(t, receiver, "sensitive retained text")
		sender := outgoingTestNodes(f)[1-receiver]
		assert.That(try.To1(admitIncomingEnvelope(n.own.vault,
			f.root.public, n.local, n.signer, raw)))
		original := outgoingTestState(t, n.own.vault)["root"][inboxKey]
		invalid := map[string][]byte{
			"empty": {}, "malformed": {0xff},
			"oversize":     make([]byte, maxInboxBytes+1),
			"noncanonical": append([]byte{0x98, 2}, original[1:]...),
			"tag":          append([]byte{0xc0}, original...),
			"trailing":     append(bytes.Clone(original), 0),
			"version": try.To1(wire.Marshal(inboxMessage{
				Version: 2, Envelope: raw,
			})),
		}
		_, _, foreign := incomingTest(t, receiver, "foreign text")
		invalid["foreign"] = try.To1(wire.Marshal(inboxMessage{
			Version: 1, Envelope: foreign,
		}))
		for name, bad := range incomingWireCases(t, raw, sender.signer,
			f.root.handle) {
			// A freshly signed body or ID is a valid first message. The local
			// authenticated Vault is the retained envelope's integrity anchor;
			// this read cannot compare against the sender's private Vault.
			if name == "signed/changed ID" || name == "signed/changed body" {
				continue
			}
			invalid["envelope/"+name] = try.To1(wire.Marshal(inboxMessage{
				Version: 1, Envelope: bad,
			}))
		}
		n.own.lease.remaining.Store(int64(len(invalid) + 1))
		for name, bad := range invalid {
			t.Run(n.name+"/"+name, func(t *testing.T) {
				defer assert.PushTester(t)()
				try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
					return tx.Put([]byte(inboxKey), bad)
				}))
				refuseMessageInbox(t, f, n)
			})
		}
		try.To(n.own.vault.Update(func(tx storage.WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			try.To(tx.Delete([]byte(inboxKey)))
			try.To1(tx.EnsureChild([]byte(inboxKey)))
			return nil
		}))
		refuseMessageInbox(t, f, n)
	}
}

func TestMessageInboxRequiresHistoricalEvidenceEvenWhenEmpty(t *testing.T) {
	defer assert.PushTester(t)()
	for receiver := range 2 {
		f, n, raw := incomingTest(t, receiver, "exact history")
		for _, present := range []bool{false, true} {
			if present {
				assert.That(try.To1(admitIncomingEnvelope(n.own.vault,
					f.root.public, n.local, n.signer, raw)))
			}
			rows := outgoingTestState(t, n.own.vault)["root"]
			for _, mode := range []string{"missing acceptance", "corrupt acceptance",
				"foreign acceptance", "acceptance version", "acceptance noncanonical",
				"role", "missing first use", "first use version", "first use request",
				"first use response", "first use noncanonical", "no historical response",
				"Await", "contradictory role", "invitation", "resigned acceptance"} {
				if !present && mode == "resigned acceptance" {
					continue // The inbox pins the exact accepted-history digest.
				}
				t.Run(
					fmt.Sprint(n.name, "/", present, "/", mode),
					func(t *testing.T) {
						defer assert.PushTester(t)()
						name, bad := changedACKHistory(t, f, n, rows, mode)
						try.To(
							n.own.vault.Update(func(tx storage.WriteTx) error {
								if bad == nil {
									return tx.Delete([]byte(name))
								}
								return tx.Put([]byte(name), bad)
							}),
						)
						refuseMessageInbox(t, f, n)
						try.To(
							n.own.vault.Update(func(tx storage.WriteTx) error {
								if old := rows[name]; old != nil {
									return tx.Put([]byte(name), old)
								}
								return tx.Delete([]byte(name))
							}),
						)
					},
				)
			}
		}
	}
}

func TestMessageInboxRejectsWrongPinsAndVault(t *testing.T) {
	defer assert.PushTester(t)()
	f, n, raw := incomingTest(t, 0, "bound local inbox")
	assert.That(try.To1(admitIncomingEnvelope(n.own.vault,
		f.root.public, n.local, n.signer, raw)))
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
				got, err := ReadMessageInbox(tc.vault, tc.root, tc.local)
				assert.Equal(err, errMessageInbox)
				assert.DeepEqual(got, MessageInbox{})
			})
		})
	}
	try.To(n.own.db.Close())
	got, err := ReadMessageInbox(n.own.vault, f.root.public, n.local)
	assert.Equal(err, errMessageInbox)
	assert.DeepEqual(got, MessageInbox{})
}
