package pw

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
)

func (f *requesterFixture) receiveV2(response []byte) (bool, error) {
	return receiveAcceptanceV2(f.alice.vault, f.root.public, f.peer.public,
		f.signer, response, func() time.Time { return f.now })
}

func (f *requesterFixture) responseV2(t *testing.T) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	saved := try.To1(f.saveV2(aliceServiceOrigin))
	try.To(f.acceptV2(saved.request, f.local.handle))
	return try.To1(f.replyV2(saved.request, f.local.handle))
}

func TestReceiveAcceptanceV2IndependentContacts(t *testing.T) {
	for _, directed := range []bool{false, true} {
		t.Run(fmt.Sprint(directed), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, directed)
			assert.Equal(try.To1(BobContactV2(f.f.vault,
				f.root.public, f.local.public)), "")
			assert.Equal(try.To1(RequesterContactV2(f.alice.vault,
				f.root.public, f.peer.public)), "")
			saved := try.To1(f.saveV2(aliceServiceOrigin))
			assert.Equal(try.To1(RequesterContactV2(f.alice.vault,
				f.root.public, f.peer.public)), "")
			f.alice.unchanged(t, func() {
				try.To(f.acceptV2(saved.request, f.local.handle))
			})
			assert.Equal(try.To1(BobContactV2(f.f.vault,
				f.root.public, f.local.public)), aliceServiceOrigin)
			assert.Equal(try.To1(RequesterContactV2(f.alice.vault,
				f.root.public, f.peer.public)), "")
			assert.Equal(try.To1(f.usableContactV2(false,
				ContactRuntimeV2{true, "http://127.0.0.1:12345"})),
				aliceServiceOrigin) // No Alice commit or first use is needed.
			response := try.To1(f.replyV2(saved.request, f.local.handle))
			beforeCommit := heldTestState(t, f.alice.vault)
			f.f.unchanged(t, func() {
				assert.That(try.To1(f.receiveV2(response)))
			})
			afterCommit := heldTestState(t, f.alice.vault)
			delete(afterCommit["root"], acceptedKey)
			delete(afterCommit["root"], heldKey)
			assert.DeepEqual(afterCommit, beforeCommit)
			assert.Equal(try.To1(RequesterContactV2(f.alice.vault,
				f.root.public, f.peer.public)), "http://127.0.0.1:12345")
			assert.Equal(try.To1(f.usableContactV2(true,
				ContactRuntimeV2{true, aliceServiceOrigin})),
				"http://127.0.0.1:12345")
			assert.DeepEqual(useRecords(t, f.alice.vault), [2][]byte{})
			assert.DeepEqual(useRecords(t, f.f.vault), [2][]byte{})
			before := requesterRecords(t, f.alice.vault)
			assert.DeepEqual(before[0], saved.request)
			_, bobHistory, bobHeld := f.records(t)
			assert.DeepEqual(before[1], bobHistory)
			assert.DeepEqual(before[2], bobHeld)
			f.alice.reopen(t)
			f.alice.lease.remaining.Store(0)
			f.alice.unchanged(t, func() {
				assert.That(try.To1(f.receiveV2(response)))
				again := try.To1(f.saveV2(aliceServiceOrigin))
				assert.DeepEqual(again.request, saved.request)
				assert.That(again.Accepted && again.Held)
			})
			assert.DeepEqual(requesterRecords(t, f.alice.vault), before)
		})
	}
}

func TestReceiveAcceptanceV2RejectsSignedConflicts(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, true)
	response := f.responseV2(t)
	for name, change := range map[string]func(*AcceptedV2){
		"version":         func(p *AcceptedV2) { p.Version = 1 },
		"binding version": func(p *AcceptedV2) { p.Binding.Version = 1 },
		"digest":          func(p *AcceptedV2) { p.RequestDigest[0] ^= 1 },
		"root":            func(p *AcceptedV2) { p.Binding.Root = p.Binding.Target },
		"requester":       func(p *AcceptedV2) { p.Binding.Requester = p.Binding.Root },
		"target":          func(p *AcceptedV2) { p.Binding.Target = p.Binding.Root },
		"invitation":      func(p *AcceptedV2) { p.Binding.InvitationID[0] ^= 1 },
		"attempt":         func(p *AcceptedV2) { p.Binding.AttemptID[0] ^= 1 },
		"audience":        func(p *AcceptedV2) { p.Binding.Audience = InvitationAny },
		"recipient":       func(p *AcceptedV2) { p.Binding.Recipient = p.Binding.Root },
		"device":          func(p *AcceptedV2) { p.Binding.Device = p.Binding.Root },
		"epoch":           func(p *AcceptedV2) { p.Binding.Epoch++ },
		"ad":              func(p *AcceptedV2) { p.Binding.Ad[0] ^= 1 },
		"requester contact": func(p *AcceptedV2) {
			p.Binding.RequesterContact = "http://127.0.0.1:4041"
		},
		"target contact": func(p *AcceptedV2) {
			p.Binding.TargetContact = "http://127.0.0.1:12346"
		},
		"swap": func(p *AcceptedV2) {
			p.Binding.RequesterContact, p.Binding.TargetContact =
				p.Binding.TargetContact, p.Binding.RequesterContact
		},
	} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			var accepted SignedAcceptedV2
			try.To(wire.UnmarshalCanonical(&accepted, response))
			change(&accepted.Payload)
			raw := signAcceptedV2(t, accepted.Payload, f.local.handle,
				AcceptedPurposeV2)
			f.f.unchanged(t, func() {
				f.alice.unchanged(t, func() {
					held, err := f.receiveV2(raw)
					assert.Equal(err, ErrEstablishment)
					assert.ThatNot(held)
				})
			})
		})
	}
	assert.Equal(try.To1(RequesterContactV2(f.alice.vault,
		f.root.public, f.peer.public)), "")
}

func signAcceptedV2(t *testing.T, p AcceptedV2, signer key.Handle,
	purpose string,
) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	digest := key.HashTagged(purpose, try.To1(wire.Marshal(p)))
	return try.To1(wire.Marshal(SignedAcceptedV2{Payload: p,
		Signature: try.To1(signer.Sign(digest[:]))}))
}

func TestReceiveAcceptanceV2RejectsBytesAndSignatures(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, false)
	response := f.responseV2(t)
	var accepted SignedAcceptedV2
	try.To(wire.UnmarshalCanonical(&accepted, response))
	p := accepted.Payload
	accepted.Signature = nil
	v1 := newRequester(t, false).response(t)
	for _, raw := range [][]byte{nil, {0xff}, response[:len(response)-1],
		append(bytes.Clone(response), 0), append([]byte{0x98, 2}, response[1:]...),
		append([]byte{0xc0}, response...), make([]byte, MaxEstablishmentBytes+1),
		v1, try.To1(wire.Marshal(accepted)),
		signAcceptedV2(t, p, f.peer.handle, AcceptedPurposeV2),
		signAcceptedV2(t, p, f.local.handle, AcceptedPurpose),
	} {
		f.alice.unchanged(t, func() {
			_, err := f.receiveV2(raw)
			assert.Equal(err, ErrEstablishment)
		})
	}
	assert.That(try.To1(f.receiveV2(response)))
	other := signAcceptedV2(t, p, f.local.handle, AcceptedPurposeV2)
	assert.ThatNot(bytes.Equal(other, response))
	f.alice.unchanged(t, func() {
		_, err := f.receiveV2(other) // Valid signature, not the saved exact result.
		assert.Equal(err, ErrEstablishment)
	})
}

func TestReceiveAcceptanceV2FalseDeclaration(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, false)
	saved := try.To1(f.saveV2(aliceServiceOrigin))
	p := try.To1(decodeEstablishmentV2(saved.request,
		f.root.public, f.local.public)).Payload
	p.RequesterContact = "http://127.0.0.1:4041"
	falseRequest := signEstablishmentV2(t, p, f.peer.handle, EstablishPurposeV2)
	try.To(f.acceptV2(falseRequest, f.local.handle))
	response := try.To1(f.replyV2(falseRequest, f.local.handle))
	f.f.unchanged(t, func() {
		f.alice.unchanged(t, func() {
			_, err := f.receiveV2(response)
			assert.Equal(err, ErrEstablishment)
		})
	})
	assert.Equal(try.To1(BobContactV2(f.f.vault, f.root.public,
		f.local.public)), p.RequesterContact)
	assert.Equal(try.To1(RequesterContactV2(f.alice.vault,
		f.root.public, f.peer.public)), "")
}

func TestReceiveAcceptanceV2AfterBobDenyOrDelete(t *testing.T) {
	for _, deleted := range []bool{false, true} {
		t.Run(fmt.Sprint(deleted), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			response := f.responseV2(t)
			if deleted {
				assert.That(try.To1(DeleteHeldLocal(f.f.vault,
					f.root.public, f.local.public)))
			} else {
				try.To1(policy.DenyLocal(f.f.vault, f.root.public,
					f.local.public, f.peer.public))
			}
			f.f.unchanged(t, func() {
				// Neither Alice's TX-A nor her usable view can read Bob now.
				try.To(f.f.db.Close())
				assert.That(try.To1(f.receiveV2(response)))
			})
			assert.Equal(try.To1(f.usableContactV2(true,
				ContactRuntimeV2{true, aliceServiceOrigin})),
				"http://127.0.0.1:12345")
			f.f.reopen(t)
		})
	}
}
