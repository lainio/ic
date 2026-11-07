package pw

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/storage"
)

func TestMessageACKAtomicFailureAndExplicitRetryV2(t *testing.T) {
	for sender := range 2 {
		for _, mode := range []string{"write", "callback", "seal"} {
			t.Run(fmt.Sprint(sender, "/", mode), func(t *testing.T) {
				defer assert.PushTester(t)()
				f, n, _, receipt := ackTestV2(t, sender)
				before := outgoingTestState(t, n.own.vault)
				disk := try.To1(os.ReadFile(n.own.path))
				n.other.unchanged(t, func() {
					if mode == "seal" {
						n.own.lease.remaining.Store(0)
						refuseMessageACKV2(t, f, n, receipt)
						return
					}
					cause := errors.New("failure after pending ACK")
					err := n.own.vault.Update(
						func(tx storage.WriteTx) (err error) {
							defer err2.Handle(&err, nil)
							if mode == "write" {
								failing := &failingAcceptanceTx{WriteTx: tx,
									failAfter: 1, cause: cause}
								err = commitMessageACKV2(failing, f.root.public,
									n.local, receipt)
								assert.Equal(failing.writes, 1)
								return err
							}
							try.To(
								commitMessageACKV2(tx, f.root.public, n.local,
									receipt),
							)
							return cause
						},
					)
					assert.ErrorIs(err, cause)
				})
				assert.DeepEqual(try.To1(os.ReadFile(n.own.path)), disk)
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				n.own.reopen(t)
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				n.own.lease.remaining.Store(1)
				n.other.unchanged(t, func() {
					assert.That(try.To1(ObserveMessageReceiptV2(n.own.vault,
						f.root.public, n.local, receipt)))
				})
				assert.Equal(n.own.lease.remaining.Load(), 0)
				before["root"][messageACKKey] = try.To1(wire.Marshal(messageACK{
					Version: 2, Receipt: receipt,
				}))
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				n.own.unchanged(t, func() {
					assert.ThatNot(try.To1(ObserveMessageReceiptV2(n.own.vault,
						f.root.public, n.local, receipt)))
				})
			})
		}
	}
}

func TestMessageACKCompetingCommitV2(t *testing.T) {
	defer assert.PushTester(t)()
	for sender := range 2 {
		f, n, envelope, receipt := ackTestV2(t, sender)
		receiver := outgoingTestNodes(f.requesterFixture)[1-sender]
		try.To(n.own.vault.View(func(tx storage.ReadTx) (err error) {
			defer err2.Handle(&err, nil)
			assert.ThatNot(try.To1(checkMessageACKV2(tx, f.root.public,
				n.local, receipt)))
			return nil
		}))
		second := try.To1(IssueMessageReceiptV2(n.other.vault, f.root.public,
			n.peer, receiver.signer, f.messageRuntime(receiver), envelope))
		assert.ThatNot(bytes.Equal(receipt, second))
		// Deterministic competing writer between preflight and commit; drop its
		// return value to model an outcome that the original caller did not see.
		try.To1(
			ObserveMessageReceiptV2(
				n.own.vault,
				f.root.public,
				n.local,
				second,
			),
		)
		before := outgoingTestState(t, n.own.vault)
		n.own.lease.remaining.Store(0)
		n.other.unchanged(t, func() {
			n.own.unchanged(t, func() {
				err := n.own.vault.Update(func(tx storage.WriteTx) error {
					return commitMessageACKV2(
						tx,
						f.root.public,
						n.local,
						receipt,
					)
				})
				assert.Equal(err, errACKUnchanged)
			})
		})
		n.own.reopen(t)
		n.own.unchanged(t, func() {
			assert.ThatNot(try.To1(ObserveMessageReceiptV2(n.own.vault,
				f.root.public, n.local, receipt)))
		})
		assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
		var ack messageACK
		try.To(wire.UnmarshalCanonical(&ack, before["root"][messageACKKey]))
		assert.DeepEqual(ack.Receipt, second)
	}
}

func TestMessageACKCorruptSlotsAndFinalRecheckV2(t *testing.T) {
	defer assert.PushTester(t)()
	for sender := range 2 {
		f, n, envelope, receipt := ackTestV2(t, sender)
		receiver := outgoingTestNodes(f.requesterFixture)[1-sender]
		rows := outgoingTestState(t, n.own.vault)["root"]
		ack := try.To1(wire.Marshal(messageACK{Version: 2, Receipt: receipt}))
		var contradictory messageReceiptV2
		try.To(wire.UnmarshalCanonical(&contradictory, receipt))
		contradictory.Payload.ID[0] ^= 1
		badReceipt := signTestReceiptV2(t, contradictory, receiver.signer,
			messageReceiptPurposeV2)
		cases := map[string]map[string][]byte{
			outgoingKey: changedEnvelopeMessages(t, rows[outgoingKey]),
			messageEnvelopeKey: incomingWireCasesV2(t, envelope, n.signer,
				f.root.handle),
			messageACKKey: {
				"empty": {}, "malformed": {0xff},
				"oversize":     make([]byte, maxMessageACKBytesV2+1),
				"noncanonical": append([]byte{0x98, 2}, ack[1:]...),
				"tag":          append([]byte{0xc0}, ack...),
				"trailing":     append(bytes.Clone(ack), 0),
				"version": try.To1(wire.Marshal(messageACK{
					Version: 1, Receipt: receipt,
				})),
				"contradictory": try.To1(wire.Marshal(messageACK{
					Version: 2, Receipt: badReceipt,
				})),
				"forged": try.To1(wire.Marshal(messageACK{
					Version: 2, Receipt: []byte{0xff},
				})),
			},
		}
		cases[messageEnvelopeKey]["resigned"] = signMessageEnvelopeV2(t,
			rows[outgoingKey], n.signer)
		cases[messageEnvelopeKey]["missing"] = nil
		cases[outgoingKey]["missing"] = nil
		n.own.lease.remaining.Store(1000)
		for slot, invalid := range cases {
			for name, bad := range invalid {
				t.Run(n.name+"/"+slot+"/"+name, func(t *testing.T) {
					defer assert.PushTester(t)()
					try.To(
						n.own.vault.View(func(tx storage.ReadTx) (err error) {
							defer err2.Handle(&err, nil)
							assert.ThatNot(
								try.To1(checkMessageACKV2(tx, f.root.public,
									n.local, receipt)),
							)
							return nil
						}),
					)
					try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
						if bad == nil {
							return tx.Delete([]byte(slot))
						}
						return tx.Put([]byte(slot), bad)
					}))
					refuseMessageACKV2(t, f, n, receipt)
					n.own.unchanged(t, func() {
						err := n.own.vault.Update(
							func(tx storage.WriteTx) error {
								return commitMessageACKV2(
									tx,
									f.root.public,
									n.local,
									receipt,
								)
							},
						)
						assert.Error(err)
						assert.That(err != errACKUnchanged)
					})
					if slot != messageACKKey {
						// A preexisting ACK must not conceal orphaned or corrupt
						// outgoing/envelope state by looking like a duplicate.
						try.To(
							n.own.vault.Update(func(tx storage.WriteTx) error {
								return tx.Put([]byte(messageACKKey), ack)
							}),
						)
						refuseMessageACKV2(t, f, n, receipt)
					}
					try.To(
						n.own.vault.Update(
							func(tx storage.WriteTx) (err error) {
								defer err2.Handle(&err, nil)
								try.To(tx.Delete([]byte(messageACKKey)))
								if original := rows[slot]; original != nil {
									return tx.Put([]byte(slot), original)
								}
								return nil
							},
						),
					)
				})
			}
		}
	}
}

func TestMessageACKOwnsInputsV2(t *testing.T) {
	defer assert.PushTester(t)()
	f, n, _, receipt := ackTestV2(t, 1)
	root, local := bytes.Clone(f.root.public), bytes.Clone(n.local)
	original := bytes.Clone(receipt)
	lease := &ackInputLease{testLease: n.own.lease}
	vault := try.To1(n.own.db.OpenVault(t.Context(), storage.VaultID{1},
		storage.KeyID{7}, lease))
	defer func() { assert.NoError(vault.Close()) }()
	lease.check = func() { clear(root); clear(local); clear(receipt) }
	n.other.unchanged(t, func() {
		assert.That(
			try.To1(ObserveMessageReceiptV2(vault, root, local, receipt)),
		)
	})
	assert.DeepEqual(receipt, make([]byte, len(receipt)))
	var ack messageACK
	try.To(wire.UnmarshalCanonical(&ack,
		outgoingTestState(t, n.own.vault)["root"][messageACKKey]))
	assert.DeepEqual(ack.Receipt, original)
}
