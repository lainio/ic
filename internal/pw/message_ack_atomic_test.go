package pw

import (
	"bytes"
	"context"
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

func TestMessageACKAtomicFailure(t *testing.T) {
	for sender := range 2 {
		for _, mode := range []string{"write", "callback", "seal"} {
			t.Run(fmt.Sprint(sender, "/", mode), func(t *testing.T) {
				defer assert.PushTester(t)()
				f, n, _, receipt := ackTest(t, sender)
				before := outgoingTestState(t, n.own.vault)
				disk := try.To1(os.ReadFile(n.own.path))
				n.other.unchanged(t, func() {
					if mode == "seal" {
						n.own.lease.remaining.Store(0)
						refuseMessageACK(t, f, n, receipt)
						return
					}
					cause := errors.New("sensitive failure after pending ACK")
					err := n.own.vault.Update(
						func(tx storage.WriteTx) (err error) {
							defer err2.Handle(&err, nil)
							if mode == "write" {
								failing := &failingAcceptanceTx{WriteTx: tx,
									failAfter: 1, cause: cause}
								err = commitMessageACK(failing, f.root.public,
									n.local, receipt)
								assert.Equal(failing.writes, 1)
								return err
							}
							try.To(
								commitMessageACK(
									tx,
									f.root.public,
									n.local,
									receipt,
								),
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
			})
		}
	}
}

func TestMessageACKFinalTransactionRevalidation(t *testing.T) {
	for sender := range 2 {
		for _, mode := range []string{"competing", "corrupt ACK", "conflicting ACK",
			"unknown ACK", "missing outgoing", "changed outgoing",
			"resigned envelope", "missing acceptance", "resigned acceptance",
			"role", "first use response", "no historical response"} {
			t.Run(fmt.Sprint(sender, "/", mode), func(t *testing.T) {
				defer assert.PushTester(t)()
				f, n, envelope, receipt := ackTest(t, sender)
				// Arrange a deterministic interleaving between the same initial
				// read and final transactional validator used by the operation.
				// No production hook, signer callback or nested transaction.
				try.To(n.own.vault.View(func(tx storage.ReadTx) (err error) {
					defer err2.Handle(&err, nil)
					assert.ThatNot(try.To1(checkMessageACK(tx, f.root.public,
						n.local, receipt)))
					return nil
				}))
				receiver := outgoingTestNodes(f)[1-sender]
				second := try.To1(issueMessageReceipt(n.other.vault,
					f.root.public, n.peer, receiver.signer, envelope))
				assert.ThatNot(bytes.Equal(second, receipt))
				switch mode {
				case "competing":
					// Discard the competing caller's result. Its authenticated
					// first receipt wins even though the signature differs.
					try.To1(observeMessageReceipt(n.own.vault, f.root.public,
						n.local, second))
				default:
					rows := outgoingTestState(t, n.own.vault)["root"]
					name, bad := messageACKKey, []byte{0xff}
					switch mode {
					case "corrupt ACK":
					case "unknown ACK":
						bad = try.To1(wire.Marshal(messageACK{Version: 2,
							Receipt: second}))
					case "conflicting ACK":
						var r messageReceipt
						try.To(wire.UnmarshalCanonical(&r, second))
						r.Payload.ID[0] ^= 1
						bad = try.To1(wire.Marshal(messageACK{Version: 1,
							Receipt: signTestReceipt(t, r, receiver.signer,
								messageReceiptPurpose)}))
					default:
						name, bad = changedACKHistory(t, f, n, rows, mode)
					}
					try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
						if bad == nil {
							return tx.Delete([]byte(name))
						}
						return tx.Put([]byte(name), bad)
					}))
				}
				before := outgoingTestState(t, n.own.vault)
				n.own.lease.remaining.Store(0)
				n.other.unchanged(t, func() {
					n.own.unchanged(t, func() {
						err := n.own.vault.Update(
							func(tx storage.WriteTx) error {
								return commitMessageACK(
									tx,
									f.root.public,
									n.local,
									receipt,
								)
							},
						)
						if mode == "competing" {
							assert.Equal(err, errACKUnchanged)
						} else {
							assert.Error(err)
							assert.That(err != errACKUnchanged)
						}
					})
				})
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				n.own.reopen(t)
				if mode == "competing" {
					n.own.unchanged(t, func() {
						assert.ThatNot(
							try.To1(observeMessageReceipt(n.own.vault,
								f.root.public, n.local, receipt)),
						)
					})
					var ack messageACK
					try.To(
						wire.UnmarshalCanonical(
							&ack,
							before["root"][messageACKKey],
						),
					)
					assert.DeepEqual(ack.Receipt, second)
				} else {
					refuseMessageACK(t, f, n, receipt)
				}
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
			})
		}
	}
}

// Test-only lease callback mutates caller-owned input at first storage access,
// after the operation must have bounded and copied it. No Vault calls occur.
type ackInputLease struct {
	*testLease
	check func()
}

func (p *ackInputLease) Acquire(ctx context.Context, vault storage.VaultID,
	id storage.KeyID,
) (storage.Lease, error) {
	if _, err := p.testLease.Acquire(ctx, vault, id); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *ackInputLease) Check() error {
	if p.check != nil {
		callback := p.check
		p.check = nil
		callback()
	}
	return nil
}

func TestMessageACKOwnsInputs(t *testing.T) {
	defer assert.PushTester(t)()
	f, n, _, receipt := ackTest(t, 1)
	root, local := bytes.Clone(f.root.public), bytes.Clone(n.local)
	original := bytes.Clone(receipt)
	lease := &ackInputLease{testLease: n.own.lease}
	vault := try.To1(n.own.db.OpenVault(t.Context(), storage.VaultID{1},
		storage.KeyID{7}, lease))
	defer func() { assert.NoError(vault.Close()) }()
	lease.check = func() {
		clear(root)
		clear(local)
		clear(receipt)
	}
	n.other.unchanged(t, func() {
		assert.That(try.To1(observeMessageReceipt(vault, root, local, receipt)))
	})
	assert.DeepEqual(receipt, make([]byte, len(receipt)))
	var ack messageACK
	try.To(wire.UnmarshalCanonical(&ack,
		outgoingTestState(t, n.own.vault)["root"][messageACKKey]))
	assert.DeepEqual(ack.Receipt, original)
}
