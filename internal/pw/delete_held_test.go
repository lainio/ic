package pw

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestDeleteHeldAbsentIsNotPreemptive(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, true)
	// Both an Active invitation and a valid pending requester are unchanged.
	for _, saved := range []bool{false, true} {
		if saved {
			try.To1(f.save())
		}
		for _, node := range []struct {
			fixture *vaultFixture
			local   key.Public
		}{{&f.f, f.local.public}, {&f.alice, f.peer.public}} {
			calls := f.signer.signCalls.Load()
			node.fixture.unchanged(t, func() {
				assert.ThatNot(try.To1(DeleteHeldLocal(
					node.fixture.vault, f.root.public, node.local,
				)))
			})
			assert.Equal(f.signer.signCalls.Load(), calls)
		}
	}
	assert.That(try.To1(f.receive(f.response(t))))
	for _, node := range []struct {
		fixture *vaultFixture
		local   key.Public
	}{{&f.f, f.local.public}, {&f.alice, f.peer.public}} {
		// Delete calls no Seal at all, even with an exhausted encryption lease.
		node.fixture.lease.remaining.Store(0)
		assert.That(try.To1(DeleteHeldLocal(
			node.fixture.vault, f.root.public, node.local,
		)))
		assert.Equal(node.fixture.lease.remaining.Load(), int64(0))
		node.fixture.reopen(t)
		node.fixture.unchanged(t, func() {
			assert.ThatNot(try.To1(DeleteHeldLocal(
				node.fixture.vault, f.root.public, node.local,
			)))
		})
	}
}

func TestDeleteHeldDenyAndUnavailableGuards(t *testing.T) {
	for _, alice := range []bool{false, true} {
		for _, denied := range []bool{false, true} {
			t.Run(strings.Join([]string{
				map[bool]string{false: "Bob", true: "Alice"}[alice],
				map[bool]string{false: "Delete", true: "DenyThenDelete"}[denied],
			}, "/"), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newFirstUse(t)
				node, local, peer := &f.f, f.local.public, f.peer.public
				other := &f.alice
				if alice {
					node, other, local, peer = other, node, peer, local
				}
				try.To(node.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					try.To(tx.Put([]byte("unrelated-root"), []byte("retain")))
					ns := try.To1(tx.EnsureChild([]byte("unrelated")))
					return ns.Put([]byte("sentinel"), []byte("retain"))
				}))
				other.unchanged(t, func() {
					history := requesterRecords(t, node.vault)
					if denied {
						// Combined faults are Go engineering evidence, beyond TLC's
						// single local invalidation per Vault bound.
						assert.That(try.To1(policy.DenyLocal(
							node.vault, f.root.public, local, peer,
						)))
						assert.DeepEqual(
							requesterRecords(t, node.vault),
							history,
						)
						err := node.vault.View(
							func(tx storage.ReadTx) (err error) {
								defer err2.Handle(&err, nil)
								p := try.To1(
									firstUseHistory(
										tx,
										f.root.public,
										local,
										alice,
									),
								)
								return firstUseGuards(tx, p, alice)
							},
						)
						assert.Error(err)
					}
					f.now = f.now.Add(
						24 * time.Hour,
					) // Historical ads have expired.
					f.signer.signErr = errors.New("signer unavailable")
					calls := f.signer.signCalls.Load()
					before := heldTestState(t, node.vault)
					assert.That(
						try.To1(
							DeleteHeldLocal(node.vault, f.root.public, local),
						),
					)
					delete(before["root"], heldKey)
					assert.DeepEqual(heldTestState(t, node.vault), before)
					assert.Equal(f.signer.signCalls.Load(), calls)
					assert.Equal(try.To1(policy.IsDenied(
						node.vault, f.root.public, local, peer,
					)), denied)
				})
			})
		}
	}
}

// Snapshot every root record and all namespaces used by these fixtures.
func heldTestState(
	t *testing.T,
	vault *storage.Vault,
) map[string]map[string][]byte {
	t.Helper()
	defer assert.PushTester(t)()
	result := make(map[string]map[string][]byte)
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		for _, name := range []string{"root", knownNS, receivedNS, authNS,
			"introduction-choice-demo", "unrelated"} {
			var ns storage.ReadNS = tx
			if name != "root" {
				if !try.To1(tx.HasChild([]byte(name))) {
					continue
				}
				ns = try.To1(tx.Child([]byte(name)))
			}
			result[name] = make(map[string][]byte)
			try.To(ns.Each(func(k, v []byte) error {
				result[name][string(k)] = v
				return nil
			}))
		}
		return nil
	}))
	return result
}

func TestDeleteHeldCorruptionFailsWithoutRepair(t *testing.T) {
	for _, alice := range []bool{false, true} {
		for _, mode := range []string{
			"history absent", "history malformed", "history noncanonical",
			"history signature", "holding digest", "holding noncanonical",
			"holding version", "cross role", "binding", "history after delete",
			"first use malformed", "invitation consumed without history",
		} {
			t.Run(map[bool]string{false: "Bob", true: "Alice"}[alice]+"/"+mode,
				func(t *testing.T) {
					defer assert.PushTester(t)()
					f := newFirstUse(t)
					node, local := &f.f, f.local.public
					if alice {
						node, local = &f.alice, f.peer.public
					}
					try.To(
						node.vault.Update(func(tx storage.WriteTx) (err error) {
							defer err2.Handle(&err, nil)
							history, _ := try.To2(tx.Get([]byte(acceptedKey)))
							holding, _ := try.To2(tx.Get([]byte(heldKey)))
							switch mode {
							case "history absent":
								return tx.Delete([]byte(acceptedKey))
							case "history malformed", "history after delete":
								if mode == "history after delete" {
									try.To(tx.Delete([]byte(heldKey)))
								}
								return tx.Put([]byte(acceptedKey), []byte{0xff})
							case "history noncanonical":
								return tx.Put(
									[]byte(acceptedKey),
									append([]byte{0x98, 3}, history[1:]...),
								)
							case "history signature":
								var record acceptedRecord
								try.To(
									wire.UnmarshalCanonical(&record, history),
								)
								record.Response[len(record.Response)-1] ^= 1
								return tx.Put(
									[]byte(acceptedKey),
									try.To1(wire.Marshal(record)),
								)
							case "holding digest", "holding version":
								var record heldRecord
								try.To(
									wire.UnmarshalCanonical(&record, holding),
								)
								if mode == "holding digest" {
									record.RequestDigest[0] ^= 1
								} else {
									record.Version++
								}
								return tx.Put(
									[]byte(heldKey),
									try.To1(wire.Marshal(record)),
								)
							case "holding noncanonical":
								return tx.Put(
									[]byte(heldKey),
									append([]byte{0x98, 2}, holding[1:]...),
								)
							case "cross role":
								if alice {
									return tx.Delete([]byte(attemptKey))
								}
								var record acceptedRecord
								try.To(
									wire.UnmarshalCanonical(&record, history),
								)
								return tx.Put(
									[]byte(attemptKey),
									record.Request,
								)
							case "first use malformed":
								name := useSeenKey
								if alice {
									name = firstUseKey
								}
								return tx.Put([]byte(name), []byte{0xff})
							case "invitation consumed without history":
								try.To(tx.Delete([]byte(acceptedKey)))
								try.To(tx.Delete([]byte(heldKey)))
								row := f.invitation
								row.Target, row.State = local, InvitationConsumed
								row.Audience, row.Recipient = InvitationAny, nil
								return tx.Put(
									[]byte(invitationKey),
									try.To1(wire.Marshal(row)),
								)
							}
							return nil
						}),
					)
					root := f.root.public
					if mode == "binding" {
						root = local
					}
					node.unchanged(t, func() {
						deleted, err := DeleteHeldLocal(node.vault, root, local)
						assert.Equal(err, ErrDeleteHeld)
						assert.ThatNot(deleted)
					})
				})
		}
	}
}

func TestDeleteHeldNamespaceAndPartialEmpty(t *testing.T) {
	defer assert.PushTester(t)()
	root, local := newSigner(t).public, newSigner(t).public
	for _, name := range []string{invitationKey, attemptKey, acceptedKey,
		heldKey, firstUseKey, useSeenKey} {
		for _, namespace := range []bool{false, true} {
			f := newVault(t)
			try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				if namespace {
					try.To1(tx.EnsureChild([]byte(name)))
					return nil
				}
				return tx.Put([]byte(name), []byte{0xff})
			}))
			f.unchanged(t, func() {
				deleted, err := DeleteHeldLocal(f.vault, root, local)
				assert.Equal(err, ErrDeleteHeld)
				assert.ThatNot(deleted)
			})
		}
	}
	f := newVault(t)
	f.lease.remaining.Store(0)
	f.unchanged(t, func() {
		assert.ThatNot(try.To1(DeleteHeldLocal(f.vault, root, local)))
		for _, pins := range [][2]key.Public{{nil, local}, {root, nil}, {bytes.Repeat([]byte{1}, 129), local}} {
			deleted, err := DeleteHeldLocal(f.vault, pins[0], pins[1])
			assert.Equal(err, ErrDeleteHeld)
			assert.ThatNot(deleted)
		}
	})
}

type failedHeldDeleteTx struct {
	storage.WriteTx
	cause error
}

func (tx failedHeldDeleteTx) Delete(k []byte) error {
	if err := tx.WriteTx.Delete(k); err != nil {
		return err
	}
	return tx.cause
}

func TestDeleteHeldCallbackRollback(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUse(t)
	cause := errors.New("failure after pending deletion")
	for _, node := range []struct {
		fixture *vaultFixture
		local   key.Public
	}{{&f.f, f.local.public}, {&f.alice, f.peer.public}} {
		before := heldTestState(t, node.fixture.vault)
		node.fixture.unchanged(t, func() {
			err := node.fixture.vault.Update(
				func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					return deleteHeldInTx(
						failedHeldDeleteTx{tx, cause},
						f.root.public,
						node.local,
					)
				},
			)
			assert.ErrorIs(err, cause)
		})
		node.fixture.reopen(t)
		assert.DeepEqual(heldTestState(t, node.fixture.vault), before)
	}
}

func TestDeleteHeldRollbackOnInjectedSealFailure(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUse(t)
	for _, node := range []struct {
		fixture *vaultFixture
		local   key.Public
	}{{&f.f, f.local.public}, {&f.alice, f.peer.public}} {
		before := heldTestState(t, node.fixture.vault)
		node.fixture.lease.remaining.Store(0)
		node.fixture.unchanged(t, func() {
			err := node.fixture.vault.Update(
				func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					try.To(deleteHeldInTx(tx, f.root.public, node.local))
					// Fault injection only: the production operation never seals.
					// A subsequent encryption failure must roll back the pending Delete.
					return tx.Put([]byte("injected-seal"), []byte("failure"))
				},
			)
			assert.ErrorIs(err, storage.ErrKeyUsageExhausted)
		})
		node.fixture.reopen(t)
		assert.DeepEqual(heldTestState(t, node.fixture.vault), before)
	}
}

func TestDeleteHeldHistoricalReadyAndReceiptDoNotGrantUse(t *testing.T) {
	for _, alice := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "Bob", true: "Alice"}[alice],
			func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newFirstUse(t)
				saved := try.To1(f.startUse())
				response := try.To1(f.bobUse(saved.request, f.local.handle))
				assert.That(try.To1(f.receiveUse(response)))
				beforeAlice, beforeBob := useRecords(
					t,
					f.alice.vault,
				), useRecords(
					t,
					f.f.vault,
				)
				node, local := &f.f, f.local.public
				if alice {
					node, local = &f.alice, f.peer.public
				}
				assert.NoError(
					node.vault.View(func(tx storage.ReadTx) (err error) {
						defer err2.Handle(&err, nil)
						p := try.To1(
							firstUseHistory(tx, f.root.public, local, alice),
						)
						return firstUseGuards(tx, p, alice)
					}),
				)
				assert.That(
					try.To1(DeleteHeldLocal(node.vault, f.root.public, local)),
				)
				assert.Error(
					node.vault.View(func(tx storage.ReadTx) (err error) {
						defer err2.Handle(&err, nil)
						p := try.To1(
							firstUseHistory(tx, f.root.public, local, alice),
						)
						return firstUseGuards(tx, p, alice)
					}),
				)
				assert.DeepEqual(useRecords(t, f.alice.vault), beforeAlice)
				assert.DeepEqual(useRecords(t, f.f.vault), beforeBob)
			},
		)
	}
}
