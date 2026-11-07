package pw

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/storage"
)

func TestFirstUseOnlyLocalEffectAndContactsV2(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseV2(t)
	alice, bob := heldTestState(t, f.alice.vault), heldTestState(t, f.f.vault)
	var saved SavedFirstUseV2
	f.f.unchanged(t, func() { saved = try.To1(f.startUseV2()) })
	assert.Equal(saved.peerOrigin, f.bobRuntime.BoundOrigin)
	alice["root"][firstUseKey] = useRecords(t, f.alice.vault)[0]
	assert.DeepEqual(heldTestState(t, f.alice.vault), alice)
	assert.DeepEqual(heldTestState(t, f.f.vault), bob)

	var response []byte
	f.alice.unchanged(t, func() {
		response = try.To1(f.bobUseV2(saved.request, f.local.handle))
	})
	bob["root"][useSeenKey] = useRecords(t, f.f.vault)[1]
	assert.DeepEqual(heldTestState(t, f.f.vault), bob)
	assert.Equal(useRecordV2(t, f).State, useAwait)
	assert.Equal(useRecordV2(t, f).Version, 2)
	// Response loss leaves Await; reopening must neither resend nor make Ready.
	f.alice.reopen(t)
	f.f.reopen(t)
	assert.DeepEqual(heldTestState(t, f.alice.vault), alice)
	assert.DeepEqual(heldTestState(t, f.f.vault), bob)
	checkFirstUseContactsV2(t, f)
	f.f.unchanged(t, func() { assert.That(try.To1(f.receiveUseV2(response))) })
	alice["root"][firstUseKey] = useRecords(t, f.alice.vault)[0]
	assert.DeepEqual(heldTestState(t, f.alice.vault), alice)
	f.alice.reopen(t)
	assert.DeepEqual(heldTestState(t, f.alice.vault), alice)
	f.alice.lease.remaining.Store(0)
	f.alice.unchanged(t, func() {
		assert.That(try.To1(f.receiveUseV2(response)))
	})
	checkFirstUseContactsV2(t, f)
	// Full local snapshots differ only by the named first-use records above;
	// there is no persisted shared PWOpen, Trust or new contact row.
}

func checkFirstUseContactsV2(t *testing.T, f *firstUseFixtureV2) {
	t.Helper()
	defer assert.PushTester(t)()
	assert.Equal(try.To1(RequesterContactV2(f.alice.vault, f.root.public,
		f.peer.public)), f.bobRuntime.BoundOrigin)
	assert.Equal(try.To1(BobContactV2(f.f.vault, f.root.public,
		f.local.public)), f.aliceRuntime.BoundOrigin)
	assert.Equal(try.To1(f.usableContactV2(true, f.aliceRuntime)),
		f.bobRuntime.BoundOrigin)
	assert.Equal(try.To1(f.usableContactV2(false, f.bobRuntime)),
		f.aliceRuntime.BoundOrigin)
}

func TestFirstUseHistoryDeleteDenyAndExpiryV2(t *testing.T) {
	for _, phase := range []string{useAwait, useReady, useExpired} {
		for _, alice := range []bool{false, true} {
			for _, deleted := range []bool{false, true} {
				t.Run(fmt.Sprint(phase, alice, deleted), func(t *testing.T) {
					defer assert.PushTester(t)()
					f := newFirstUseV2(t)
					saved := try.To1(f.startUseV2())
					response := try.To1(
						f.bobUseV2(saved.request, f.local.handle),
					)
					if phase != useAwait {
						assert.That(try.To1(f.receiveUseV2(response)))
					}
					if phase == useExpired {
						before := useRecordV2(t, f)
						assert.That(try.To1(f.expireUseV2(true)))
						after := useRecordV2(t, f)
						assert.DeepEqual(after.Request, before.Request)
						assert.DeepEqual(after.Response, before.Response)
					}
					checkFirstUseContactsV2(
						t,
						f,
					) // Even Expired needs no Ready.
					node, other := &f.f, &f.alice
					local, peer := f.local.public, f.peer.public
					read, runtime := BobContactV2, f.bobRuntime
					want := f.aliceRuntime.BoundOrigin
					if alice {
						node, other, local, peer = other, node, peer, local
						read, runtime = RequesterContactV2, f.aliceRuntime
						want = f.bobRuntime.BoundOrigin
					}
					history, use := requesterRecords(
						t,
						node.vault,
					), useRecords(
						t,
						node.vault,
					)
					before := heldTestState(t, node.vault)
					other.unchanged(t, func() {
						if deleted {
							assert.That(
								try.To1(
									DeleteHeldLocal(
										node.vault,
										f.root.public,
										local,
									),
								),
							)
							delete(before["root"], heldKey)
							assert.DeepEqual(
								heldTestState(t, node.vault),
								before,
							)
							history[2] = nil
						} else {
							try.To1(policy.DenyLocal(node.vault, f.root.public, local, peer))
						}
					})
					node.reopen(t)
					assert.DeepEqual(requesterRecords(t, node.vault), history)
					assert.DeepEqual(useRecords(t, node.vault), use)
					node.unchanged(t, func() {
						assert.Equal(
							try.To1(read(node.vault, f.root.public, local)),
							want,
						)
						assert.Equal(
							try.To1(f.usableContactV2(alice, runtime)),
							"",
						)
						if alice {
							_, err := f.startUseV2()
							assert.Equal(err, ErrFirstUse)
							_, err = f.receiveUseV2(response)
							assert.Equal(err, ErrFirstUse)
						} else {
							_, err := f.bobUseV2(saved.request, f.local.handle)
							assert.Equal(err, ErrFirstUse)
						}
						if deleted {
							assert.ThatNot(
								try.To1(
									DeleteHeldLocal(
										node.vault,
										f.root.public,
										local,
									),
								),
							)
						}
					})
					if alice && phase != useExpired {
						assert.That(try.To1(f.expireUseV2(true)))
						assert.DeepEqual(
							useRecordV2(t, f).Request,
							saved.request,
						)
					}
					assert.DeepEqual(requesterRecords(t, node.vault), history)
				})
			}
		}
	}
}

func TestFirstUseAlreadySentBeforeBobDeleteV2(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseV2(t)
	saved := try.To1(f.startUseV2())
	response := try.To1(f.bobUseV2(saved.request, f.local.handle))
	assert.That(
		try.To1(DeleteHeldLocal(f.f.vault, f.root.public, f.local.public)),
	)
	f.f.unchanged(t, func() {
		_, err := f.bobUseV2(saved.request, f.local.handle)
		assert.Equal(err, ErrFirstUse)
		try.To(f.f.db.Close()) // Alice cannot consult Bob's Vault or policy.
		assert.That(try.To1(f.receiveUseV2(response)))
	})
	f.f.reopen(t)
	assert.Equal(useRecordV2(t, f).State, useReady)
	assert.Equal(try.To1(f.usableContactV2(false, f.bobRuntime)), "")
	assert.Equal(try.To1(f.usableContactV2(true, f.aliceRuntime)),
		f.bobRuntime.BoundOrigin)
}

func TestFirstUseBootstrapExpiryAndNoFreshPairingV2(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseV2(t)
	f.now = f.now.Add(2 * ads.TTL)
	assert.That(f.now.After(time.Unix(0, f.invitation.ExpiresUnixNano)))
	// Remove Alice's discovery cache as well: accepted history is sufficient.
	try.To(f.invalidateAliceV2("received"))
	try.To(f.invalidateAliceV2("verified"))
	saved := try.To1(f.startUseV2())
	response := try.To1(f.bobUseV2(saved.request, f.local.handle))
	assert.That(try.To1(f.receiveUseV2(response)))
	assert.Equal(try.To1(RequesterContactV2(f.alice.vault, f.root.public,
		f.peer.public)), f.bobRuntime.BoundOrigin)
	fresh := newRequester(t, true)
	attempt := try.To1(fresh.saveV2(aliceServiceOrigin))
	fresh.now = fresh.now.Add(2 * ads.TTL)
	fresh.f.unchanged(t, func() {
		assert.Equal(fresh.acceptV2(attempt.request, fresh.local.handle),
			ErrEstablishment)
	})
	fresh.unconsumed(t)
	newAttempt := newRequester(t, true)
	newAttempt.now = newAttempt.now.Add(2 * ads.TTL)
	newAttempt.alice.unchanged(t, func() {
		_, err := newAttempt.saveV2(aliceServiceOrigin)
		assert.Equal(err, ErrEstablishment)
	})
}

func corruptFirstUseV2(tx storage.WriteTx, alice bool, mode string,
) (err error) {
	defer err2.Handle(&err, nil)
	name := useSeenKey
	if alice {
		name = firstUseKey
	}
	raw, _ := try.To2(tx.Get([]byte(name)))
	switch mode {
	case "namespace":
		try.To(tx.Delete([]byte(name)))
		try.To1(tx.EnsureChild([]byte(name)))
		return nil
	case "wrong slot":
		if alice {
			name = useSeenKey
		} else {
			name = firstUseKey
		}
	case "malformed":
		raw = []byte{0xff}
	case "noncanonical":
		raw = append([]byte{0x98, raw[0] & 0x1f}, raw[1:]...)
	case "oversize":
		raw = make([]byte, 2*MaxFirstUseBytesV2+65)
	default:
		var version *uint8
		var request, response *[]byte
		var record firstUseRecord
		var receipt firstUseReceipt
		if alice {
			try.To(wire.UnmarshalCanonical(&record, raw))
			version, request, response = &record.Version, &record.Request, &record.Response
		} else {
			try.To(wire.UnmarshalCanonical(&receipt, raw))
			version, request, response = &receipt.Version, &receipt.Request, &receipt.Response
		}
		switch mode {
		case "foreign version":
			*version = 1
		case "request":
			(*request)[len(*request)-1] ^= 1
		case "response":
			(*response)[len(*response)-1] ^= 1
		case "missing response":
			*response = nil
		case "unknown state":
			record.State = "Idle"
		case "Await with response":
			record.State = useAwait
		}
		if alice {
			raw = try.To1(wire.Marshal(record))
		} else {
			raw = try.To1(wire.Marshal(receipt))
		}
	}
	return tx.Put([]byte(name), raw)
}

func TestFirstUseCorruptHistoryRejectsReadUseDeleteV2(t *testing.T) {
	for _, alice := range []bool{false, true} {
		for _, mode := range []string{"namespace", "wrong slot", "malformed",
			"noncanonical", "oversize", "foreign version", "request", "response",
			"missing response", "unknown state", "Await with response"} {
			if !alice &&
				(mode == "unknown state" || mode == "Await with response") {
				continue
			}
			t.Run(fmt.Sprint(alice, mode), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newFirstUseV2(t)
				saved := try.To1(f.startUseV2())
				response := try.To1(f.bobUseV2(saved.request, f.local.handle))
				assert.That(try.To1(f.receiveUseV2(response)))
				node, local, read := &f.f, f.local.public, BobContactV2
				if alice {
					node, local, read = &f.alice, f.peer.public, RequesterContactV2
				}
				try.To(node.vault.Update(func(tx storage.WriteTx) error {
					return corruptFirstUseV2(tx, alice, mode)
				}))
				node.reopen(t)
				node.unchanged(t, func() {
					_, err := read(node.vault, f.root.public, local)
					assert.Equal(err, ErrEstablishment)
					_, err = f.usableContactV2(alice, ContactRuntimeV2{})
					assert.Equal(err, ErrEstablishment)
					_, err = DeleteHeldLocal(node.vault, f.root.public, local)
					assert.Equal(err, ErrDeleteHeld)
					if alice {
						_, err = f.receiveUseV2(response)
						assert.Equal(err, ErrFirstUse)
						_, err = f.expireUseV2(true)
						assert.Equal(err, ErrFirstUse)
					} else {
						_, err = f.bobUseV2(saved.request, f.local.handle)
						assert.Equal(err, ErrFirstUse)
					}
				})
			})
		}
	}
}

func TestFirstUseBeforeAcceptanceAndForeignHistoryV2(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseV2(t)
	saved := try.To1(f.startUseV2())
	try.To1(f.bobUseV2(saved.request, f.local.handle))
	for _, alice := range []bool{false, true} {
		node, local, read := &f.f, f.local.public, BobContactV2
		if alice {
			node, local, read = &f.alice, f.peer.public, RequesterContactV2
		}
		try.To(node.vault.Update(func(tx storage.WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			try.To(tx.Delete([]byte(heldKey)))
			try.To(tx.Delete([]byte(acceptedKey)))
			// Bob's consumed invitation itself would already refuse. Remove
			// it here to exercise pre-acceptance first-use rejection directly.
			return tx.Delete([]byte(invitationKey))
		}))
		node.unchanged(t, func() {
			_, err := read(node.vault, f.root.public, local)
			assert.Equal(err, ErrEstablishment)
			_, err = DeleteHeldLocal(node.vault, f.root.public, local)
			assert.Equal(err, ErrDeleteHeld)
		})
	}
	// A well-signed receipt from a different relationship is also corruption.
	other := newFirstUseV2(t)
	foreign := useRecords(t, f.f.vault)[1]
	try.To(other.f.vault.Update(func(tx storage.WriteTx) error {
		return tx.Put([]byte(useSeenKey), bytes.Clone(foreign))
	}))
	other.f.unchanged(t, func() {
		_, err := BobContactV2(
			other.f.vault,
			other.root.public,
			other.local.public,
		)
		assert.Equal(err, ErrEstablishment)
	})
}
