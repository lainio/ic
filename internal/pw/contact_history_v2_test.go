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
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func corruptContactHistoryV2(tx storage.WriteTx, local key.Public,
	alice bool, mode string,
) (err error) {
	defer err2.Handle(&err, nil)
	raw, _ := try.To2(tx.Get([]byte(acceptedKey)))
	var history acceptedRecord
	try.To(wire.UnmarshalCanonical(&history, raw))
	switch mode {
	case "history absent":
		return tx.Delete([]byte(acceptedKey))
	case "history malformed", "history after delete":
		if mode == "history after delete" {
			try.To(tx.Delete([]byte(heldKey)))
		}
		return tx.Put([]byte(acceptedKey), []byte{0xff})
	case "history noncanonical":
		return tx.Put([]byte(acceptedKey), append([]byte{0x98, 3}, raw[1:]...))
	case "history version":
		history.Version = 1
	case "request signature", "response signature":
		if mode == "request signature" {
			history.Request[len(history.Request)-1] ^= 1
		} else {
			history.Response[len(history.Response)-1] ^= 1
		}
	case "request contact", "request target", "request ad", "request canonical":
		var request SignedEstablishmentV2
		try.To(wire.UnmarshalCanonical(&request, history.Request))
		switch mode {
		case "request contact":
			request.Payload.RequesterContact = "http://127.0.0.1:4041"
		case "request target":
			request.Payload.TargetContact = request.Payload.RequesterContact
		case "request ad":
			request.Payload.Ad[len(request.Payload.Ad)-1] ^= 1
		case "request canonical":
			history.Request = append([]byte{0x98, 2}, history.Request[1:]...)
		}
		if mode != "request canonical" {
			history.Request = try.To1(wire.Marshal(request))
		}
	case "held digest", "held version", "held canonical":
		holding, _ := try.To2(tx.Get([]byte(heldKey)))
		var held heldRecord
		try.To(wire.UnmarshalCanonical(&held, holding))
		if mode == "held canonical" {
			return tx.Put([]byte(heldKey), append([]byte{0x98, 2}, holding[1:]...))
		}
		if mode == "held digest" {
			held.RequestDigest[0] ^= 1
		} else {
			held.Version = 1
		}
		return tx.Put([]byte(heldKey), try.To1(wire.Marshal(held)))
	case "role", "attempt":
		if !alice {
			return tx.Put([]byte(attemptKey), history.Request)
		}
		if mode == "role" {
			return tx.Delete([]byte(attemptKey))
		}
		return tx.Put([]byte(attemptKey), []byte{0xff})
	case "invitation":
		var request SignedEstablishmentV2
		try.To(wire.UnmarshalCanonical(&request, history.Request))
		p := request.Payload
		row := Invitation{Version: 1, Root: p.Root, Target: local,
			ID: bytes.Clone(p.InvitationID), Audience: InvitationAny,
			State: InvitationConsumed, ExpiresUnixNano: 1}
		row.ID[0] ^= 1
		return tx.Put([]byte(invitationKey), try.To1(wire.Marshal(row)))
	}
	return tx.Put([]byte(acceptedKey), try.To1(wire.Marshal(history)))
}

func TestContactV2CorruptionNeverBecomesAbsenceOrDeletion(t *testing.T) {
	for _, alice := range []bool{false, true} {
		for _, mode := range []string{"history absent", "history malformed",
			"history noncanonical", "history version", "history after delete",
			"request signature", "response signature", "request contact",
			"request target", "request ad", "request canonical", "held digest",
			"held version", "held canonical", "role", "attempt", "invitation"} {
			t.Run(fmt.Sprint(alice, "/", mode), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRequester(t, false)
				response := f.responseV2(t)
				try.To1(f.receiveV2(response))
				node, local, read := &f.f, f.local.public, BobContactV2
				if alice {
					node, local, read = &f.alice, f.peer.public, RequesterContactV2
				}
				try.To(node.vault.Update(func(tx storage.WriteTx) error {
					return corruptContactHistoryV2(tx, local, alice, mode)
				}))
				node.reopen(t)
				node.unchanged(t, func() {
					contact, err := read(node.vault, f.root.public, local)
					assert.Equal(err, ErrEstablishment)
					assert.Equal(contact, "")
					// Stopped runtime must not disguise corrupt retained history.
					contact, err = f.usableContactV2(alice, ContactRuntimeV2{})
					assert.Equal(err, ErrEstablishment)
					assert.Equal(contact, "")
					deleted, err := DeleteHeldLocal(node.vault, f.root.public, local)
					assert.Equal(err, ErrDeleteHeld)
					assert.ThatNot(deleted)
					if alice {
						_, err = f.receiveV2(response)
						assert.Equal(err, ErrEstablishment)
						_, err = f.saveV2(aliceServiceOrigin)
						assert.Equal(err, ErrEstablishment)
					}
				})
			})
		}
	}
}

func TestContactV2NamespaceConflicts(t *testing.T) {
	for _, alice := range []bool{false, true} {
		for _, name := range []string{invitationKey, attemptKey, acceptedKey,
			heldKey, firstUseKey, useSeenKey} {
			t.Run(fmt.Sprint(alice, name), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRequester(t, false)
				try.To1(f.receiveV2(f.responseV2(t)))
				node, local, read := &f.f, f.local.public, BobContactV2
				if alice {
					node, local, read = &f.alice, f.peer.public, RequesterContactV2
				}
				try.To(node.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					try.To(tx.Delete([]byte(name)))
					try.To1(tx.EnsureChild([]byte(name)))
					return nil
				}))
				node.unchanged(t, func() {
					contact, err := read(node.vault, f.root.public, local)
					assert.Equal(err, ErrEstablishment)
					assert.Equal(contact, "")
					deleted, err := DeleteHeldLocal(node.vault, f.root.public, local)
					assert.Equal(err, ErrDeleteHeld)
					assert.ThatNot(deleted)
				})
			})
		}
	}
}

func TestDeleteHeldV2PendingAndRollback(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, false)
	saved := try.To1(f.saveV2(aliceServiceOrigin))
	f.alice.unchanged(t, func() {
		assert.ThatNot(try.To1(DeleteHeldLocal(f.alice.vault,
			f.root.public, f.peer.public)))
	})
	try.To(f.acceptV2(saved.request, f.local.handle))
	try.To1(f.receiveV2(try.To1(f.replyV2(saved.request, f.local.handle))))
	cause := errors.New("failure after pending deletion")
	for _, alice := range []bool{false, true} {
		node, local := &f.f, f.local.public
		if alice {
			node, local = &f.alice, f.peer.public
		}
		before := heldTestState(t, node.vault)
		node.unchanged(t, func() {
			err := node.vault.Update(func(tx storage.WriteTx) error {
				return deleteHeldInTx(failedHeldDeleteTx{tx, cause},
					f.root.public, local)
			})
			assert.ErrorIs(err, cause)
		})
		node.reopen(t)
		assert.DeepEqual(heldTestState(t, node.vault), before)
		try.To1(DeleteHeldLocal(node.vault, f.root.public, local))
		node.unchanged(t, func() {
			assert.ThatNot(try.To1(DeleteHeldLocal(node.vault, f.root.public, local)))
		})
	}
}

func TestDeleteHeldV2WithoutLivePrerequisites(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, false)
	try.To1(f.receiveV2(f.responseV2(t)))
	for _, guard := range []string{"known self", "known peer", "device", "deny"} {
		try.To(f.invalidateAliceV2(guard))
		try.To(f.invalidateBobV2(guard))
	}
	f.now = f.now.Add(24 * time.Hour)
	f.signer.signErr = errors.New("signer unavailable")
	calls := f.signer.signCalls.Load()
	for _, alice := range []bool{false, true} {
		node, local, read, want := &f.f, f.local.public, BobContactV2,
			aliceServiceOrigin
		if alice {
			node, local, read, want = &f.alice, f.peer.public,
				RequesterContactV2, "http://127.0.0.1:12345"
		}
		node.lease.remaining.Store(0)
		before := heldTestState(t, node.vault)
		assert.That(try.To1(DeleteHeldLocal(node.vault, f.root.public, local)))
		delete(before["root"], heldKey)
		assert.DeepEqual(heldTestState(t, node.vault), before)
		node.reopen(t)
		node.unchanged(t, func() {
			assert.Equal(try.To1(read(node.vault, f.root.public, local)), want)
			assert.ThatNot(try.To1(DeleteHeldLocal(node.vault, f.root.public, local)))
		})
	}
	assert.Equal(f.signer.signCalls.Load(), calls)
}
