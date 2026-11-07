package pw

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestContactV2LocalEligibilityAndImmutableHistory(t *testing.T) {
	for _, alice := range []bool{false, true} {
		for _, guard := range []string{"deny", "known self", "known peer",
			"device", "expiry", "ad", "delete", "stopped", "origin", "unusable"} {
			for _, duringProbe := range []bool{false, true} {
				if duringProbe && (guard == "stopped" || guard == "origin") {
					continue // Configuration is supplied under the owner's lock.
				}
				t.Run(fmt.Sprint(alice, "/", guard, "/", duringProbe),
					func(t *testing.T) {
						defer assert.PushTester(t)()
						f := newRequester(t, false)
						assert.That(try.To1(f.receiveV2(f.responseV2(t))))
						node, local, read, signer := &f.f, f.local.public,
							BobContactV2, &probeSigner{Handle: f.local.handle}
						origin, want := "http://127.0.0.1:12345", aliceServiceOrigin
						if alice {
							node, local, read, signer = &f.alice, f.peer.public,
								RequesterContactV2, f.signer
							origin, want = want, origin
						}
						runtime := ContactRuntimeV2{true, origin}
						before := requesterRecords(t, node.vault)
						invalidate := func() (err error) {
							defer err2.Handle(&err, nil)
							switch guard {
							case "delete":
								try.To1(DeleteHeldLocal(node.vault, f.root.public, local))
							case "stopped":
								runtime.Running = false
							case "origin":
								runtime.BoundOrigin = "http://127.0.0.1:4041"
							case "unusable":
								signer.signErr = errors.New("unavailable")
							case "expiry":
								f.now = f.now.Add(2 * ads.TTL)
							case "ad":
								if alice {
									replaceRequesterAd(t, f, establishmentEndpoint)
								} else {
									try.To(f.invalidateBobV2("ad"))
								}
							default:
								if alice {
									return f.invalidateAliceV2(guard)
								}
								return f.invalidateBobV2(guard)
							}
							return nil
						}
						if duringProbe {
							signer.sign = func(d []byte) (_ []byte, err error) {
								defer err2.Handle(&err, nil)
								try.To(invalidate())
								if guard == "unusable" {
									return nil, signer.signErr
								}
								return signer.Handle.Sign(d)
							}
						} else {
							try.To(invalidate())
						}
						contact, err := usableContactV2(node.vault, f.root.public,
							local, signer, runtime, alice,
							func() time.Time { return f.now })
						assert.Equal(contact, "")
						if guard == "device" {
							assert.Equal(err, ErrEstablishment) // Partial auth namespace.
						} else {
							assert.NoError(err)
						}
						if guard == "delete" {
							before[2] = nil
						}
						assert.DeepEqual(requesterRecords(t, node.vault), before)
						node.reopen(t)
						signer.sign = nil
						node.lease.remaining.Store(0)
						node.unchanged(t, func() {
							assert.Equal(try.To1(read(node.vault, f.root.public, local)), want)
							contact, err := usableContactV2(node.vault, f.root.public,
								local, signer, runtime, alice,
								func() time.Time { return f.now })
							assert.Equal(contact, "")
							if guard == "device" {
								assert.Equal(err, ErrEstablishment)
							} else {
								assert.NoError(err)
							}
						})
					})
			}
		}
	}
}

func TestContactV2CurrentAdAbsenceAndCorruption(t *testing.T) {
	for _, mode := range []string{"received", "verified", "bad received",
		"bad verified", "bad Bob ad"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			try.To1(f.receiveV2(f.responseV2(t)))
			alice := mode != "bad Bob ad"
			node, local, read, origin, want := &f.alice, f.peer.public,
				RequesterContactV2, aliceServiceOrigin, "http://127.0.0.1:12345"
			if !alice {
				node, local, read, origin, want = &f.f, f.local.public,
					BobContactV2, want, origin
				putRecord(t, node.vault, "local-current-ad-v1", []byte("slot-1"),
					[]byte{0xff})
			} else if mode == "received" || mode == "verified" {
				try.To(f.invalidateAliceV2(mode))
			} else {
				name := "received-ad-claims-v1"
				if mode == "bad verified" {
					name = "verified-ad-claims-v1"
				}
				try.To(node.vault.Update(func(tx storage.WriteTx) error {
					return tx.Put([]byte(name), []byte{0xff})
				}))
			}
			node.unchanged(t, func() {
				assert.Equal(try.To1(read(node.vault, f.root.public, local)), want)
				contact, err := f.usableContactV2(alice, ContactRuntimeV2{true, origin})
				assert.Equal(contact, "")
				if mode == "received" || mode == "verified" {
					assert.NoError(err)
				} else {
					assert.Equal(err, ErrEstablishment)
				}
			})
		})
	}
}

func TestContactV2LegacyAndWrongRoles(t *testing.T) {
	for _, phase := range []string{"pending", "accepted", "first use", "deleted"} {
		t.Run(phase, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			if phase == "pending" {
				try.To1(f.save())
			} else {
				try.To1(f.receive(f.response(t)))
				if phase == "first use" {
					saved := try.To1(f.startUse())
					try.To1(f.receiveUse(try.To1(f.bobUse(saved.request,
						f.local.handle))))
				}
			}
			for _, alice := range []bool{false, true} {
				node, local, read := &f.f, f.local.public, BobContactV2
				if alice {
					node, local, read = &f.alice, f.peer.public, RequesterContactV2
				}
				if phase == "deleted" {
					try.To1(DeleteHeldLocal(node.vault, f.root.public, local))
				}
				node.unchanged(t, func() {
					assert.Equal(try.To1(read(node.vault, f.root.public, local)), "")
				})
			}
		})
	}
	for _, alice := range []bool{false, true} {
		t.Run(fmt.Sprint("v2/", alice), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			response := f.responseV2(t)
			try.To1(f.receiveV2(response))
			node, local, read, wrongRole := &f.f, f.local.public,
				BobContactV2, RequesterContactV2
			if alice {
				node, local, read, wrongRole = &f.alice, f.peer.public,
					wrongRole, read
			}
			node.unchanged(t, func() {
				for _, pins := range [][2]key.Public{
					{local, local}, {f.root.public, f.root.public}, {nil, local},
				} {
					contact, err := read(node.vault, pins[0], pins[1])
					assert.Equal(err, ErrEstablishment)
					assert.Equal(contact, "")
				}
				contact, err := wrongRole(node.vault, f.root.public, local)
				assert.Equal(err, ErrEstablishment)
				assert.Equal(contact, "")
				assert.Error(node.vault.View(func(tx storage.ReadTx) (err error) {
					defer err2.Handle(&err, nil)
					try.To1(firstUseHistory(tx, f.root.public, local, alice))
					return nil
				}))
			})
			f.alice.unchanged(t, func() {
				_, err := f.receive(response) // V1 must not interpret v2 history.
				assert.Equal(err, ErrEstablishment)
				_, err = f.startUse()
				assert.Equal(err, ErrFirstUse)
			})
		})
	}
}

func TestContactV2PublicAPIs(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, false)
	f.now = time.Now()
	// Replace the unused fixture ad/invitation using the real-clock APIs.
	try.To(f.f.vault.Update(func(tx storage.WriteTx) error {
		return tx.Delete([]byte(invitationKey))
	}))
	f.invitation = try.To1(IssueInvitation(f.f.vault, f.root.public,
		f.local.public, nil))
	ad := try.To1(ads.PublishLocal(f.f.vault, f.root.public, f.local.public,
		f.local.handle, establishmentEndpoint, f.now))
	raw := try.To1(wire.Marshal(ad))
	try.To1(ads.ReceiveClaim(f.alice.vault, f.root.public, f.local.public, raw))
	try.To(f.alice.vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return tx.Put([]byte("verified-ad-claims-v1"), try.To1(wire.Marshal(
			[]any{uint8(1), []any{[]any{f.local.public, raw}}})))
	}))
	saved := try.To1(SaveAttemptV2(f.alice.vault, f.root.public, f.peer.public,
		f.local.public, f.signer, f.invitation.ID, f.invitation.Audience,
		aliceServiceOrigin))
	try.To(BobAcceptV2(f.f.vault, f.root.public, f.local.public,
		f.local.handle, establishmentEndpoint, saved.request))
	response := try.To1(BobReplyV2(f.f.vault, f.root.public, f.local.public,
		f.local.handle, establishmentEndpoint, saved.request))
	assert.That(try.To1(ReceiveAcceptanceV2(f.alice.vault, f.root.public,
		f.peer.public, f.signer, response)))
	f.alice.unchanged(t, func() {
		assert.Equal(try.To1(RequesterUsableContactV2(f.alice.vault,
			f.root.public, f.peer.public, f.signer,
			ContactRuntimeV2{true, aliceServiceOrigin})), "http://127.0.0.1:12345")
	})
	f.f.unchanged(t, func() {
		assert.Equal(try.To1(BobUsableContactV2(f.f.vault, f.root.public,
			f.local.public, f.local.handle,
			ContactRuntimeV2{true, "http://127.0.0.1:12345"})), aliceServiceOrigin)
	})
}
