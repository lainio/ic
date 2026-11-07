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
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func (f *establishmentFixture) acceptV2(raw []byte, signer key.Handle) error {
	return bobAcceptV2(f.f.vault, f.root.public, f.local.public, signer,
		establishmentEndpoint, raw, func() time.Time { return f.now })
}

func (f *establishmentFixture) replyV2(raw []byte, signer key.Handle,
) ([]byte, error) {
	return bobReplyV2(f.f.vault, f.root.public, f.local.public, signer,
		establishmentEndpoint, raw, func() time.Time { return f.now })
}

func TestBobAcceptV2IndependentContactCommit(t *testing.T) {
	for _, directed := range []bool{false, true} {
		t.Run(fmt.Sprint(directed), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, directed)
			saved := try.To1(f.saveV2(aliceServiceOrigin))
			signer := &probeSigner{Handle: f.local.handle}
			f.alice.unchanged(t, func() {
				response, err := f.replyV2(saved.request, signer)
				assert.Equal(err, ErrEstablishment)
				assert.SNil(response)
				calls := signer.signCalls.Load()
				try.To(f.acceptV2(saved.request, signer))
				assert.Equal(signer.signCalls.Load(), calls+2)
			})
			row, raw, holding := f.records(t)
			assert.Equal(row.Version, 1)
			assert.Equal(row.State, InvitationConsumed)
			var history acceptedRecord
			try.To(wire.UnmarshalCanonical(&history, raw))
			assert.Equal(history.Version, 2)
			assert.DeepEqual(history.Request, saved.request)
			var result SignedAcceptedV2
			try.To(wire.UnmarshalCanonical(&result, history.Response))
			p := try.To1(decodeEstablishmentV2(saved.request,
				f.root.public, f.local.public)).Payload
			assert.Equal(result.Payload.Version, 2)
			assert.DeepEqual(result.Payload.Binding, p)
			assert.Equal(p.RequesterContact, aliceServiceOrigin)
			assert.Equal(p.TargetContact, "http://127.0.0.1:12345")
			assert.DeepEqual(p.Requester, f.peer.public)
			assert.DeepEqual(p.Target, f.local.public)
			digest := key.HashTagged(requestPurposeV2, saved.request)
			assert.DeepEqual(result.Payload.RequestDigest, digest[:])
			unsigned := key.HashTagged(requestPurposeV2,
				try.To1(wire.Marshal(p)))
			assert.ThatNot(bytes.Equal(digest[:], unsigned[:]))
			signed := key.HashTagged(AcceptedPurposeV2,
				try.To1(wire.Marshal(result.Payload)))
			assert.That(result.Signature.Verify(f.local.public, signed[:]))
			assert.ThatNot(result.Signature.Verify(f.peer.public, signed[:]))
			var held heldRecord
			try.To(wire.UnmarshalCanonical(&held, holding))
			assert.Equal(held.Version, 2)
			assert.DeepEqual(held.RequestDigest, digest[:])
			assert.DeepEqual(requesterRecords(t, f.alice.vault),
				[3][]byte{saved.request, nil, nil})
			try.To(f.f.vault.View(func(tx storage.ReadTx) (err error) {
				defer err2.Handle(&err, nil)
				for _, name := range []string{attemptKey, firstUseKey, useSeenKey} {
					_, found := try.To2(tx.Get([]byte(name)))
					assert.ThatNot(found)
				}
				return nil
			}))
		})
	}
}

func TestBobAcceptV2RejectsSignedBindings(t *testing.T) {
	f := newRequester(t, true)
	saved, err := f.saveV2(aliceServiceOrigin)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*EstablishmentV2){
		"version":   func(p *EstablishmentV2) { p.Version = 1 },
		"root":      func(p *EstablishmentV2) { p.Root = p.Requester },
		"requester": func(p *EstablishmentV2) { p.Requester = p.Root },
		"target":    func(p *EstablishmentV2) { p.Target = p.Root },
		"invitation": func(p *EstablishmentV2) {
			p.InvitationID[0] ^= 1
		},
		"recipient": func(p *EstablishmentV2) { p.Recipient = p.Root },
		"audience": func(p *EstablishmentV2) {
			p.Audience, p.Recipient = InvitationAny, nil
		},
		"attempt": func(p *EstablishmentV2) { p.AttemptID = p.AttemptID[:31] },
		"device":  func(p *EstablishmentV2) { p.Device = p.Root },
		"epoch":   func(p *EstablishmentV2) { p.Epoch++ },
		"wrong target origin": func(p *EstablishmentV2) {
			p.TargetContact = "http://127.0.0.1:12346"
		},
		"swapped contacts": func(p *EstablishmentV2) {
			p.RequesterContact, p.TargetContact = p.TargetContact, p.RequesterContact
		},
		"noncanonical contact": func(p *EstablishmentV2) {
			p.RequesterContact = "http://localhost:4040"
		},
	} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			p := try.To1(decodeEstablishmentV2(saved.request,
				f.root.public, f.local.public)).Payload
			change(&p)
			raw := signEstablishmentV2(t, p, f.peer.handle, EstablishPurposeV2)
			f.f.unchanged(t, func() {
				assert.Equal(f.acceptV2(raw, f.local.handle), ErrEstablishment)
			})
			f.unconsumed(t)
		})
	}
}

func TestBobAcceptV2RejectsUnauthenticatedBytes(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, false)
	saved := try.To1(f.saveV2(aliceServiceOrigin))
	request := try.To1(decodeEstablishmentV2(saved.request,
		f.root.public, f.local.public))
	unsigned := request
	unsigned.Signature = nil
	tampered := request
	tampered.Payload.RequesterContact = "http://127.0.0.1:4041"
	for _, raw := range [][]byte{
		nil, {0xff}, saved.request[:len(saved.request)-1],
		append(bytes.Clone(saved.request), 0),
		append([]byte{0x98, 2}, saved.request[1:]...),
		append([]byte{0xc0}, saved.request...),
		make([]byte, MaxEstablishmentBytes+1), f.raw,
		try.To1(wire.Marshal(unsigned)), try.To1(wire.Marshal(tampered)),
		signEstablishmentV2(t, request.Payload, f.local.handle, EstablishPurposeV2),
		signEstablishmentV2(t, request.Payload, f.peer.handle, EstablishPurpose),
	} {
		f.f.unchanged(t, func() {
			assert.Equal(f.acceptV2(raw, f.local.handle), ErrEstablishment)
		})
		f.unconsumed(t)
	}
}

func TestBobAcceptV2AuthenticatesOwnCurrentAd(t *testing.T) {
	for _, field := range []string{"slot", "device", "epoch", "root",
		"target", "token", "origin", "forged"} {
		t.Run(field, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			saved := try.To1(f.saveV2(aliceServiceOrigin))
			p := try.To1(decodeEstablishmentV2(saved.request,
				f.root.public, f.local.public)).Payload
			var ad ads.Current
			try.To(wire.UnmarshalCanonical(&ad, p.Ad))
			switch field {
			case "slot":
				ad.Payload.Slot++
			case "device":
				ad.Payload.Device = f.root.public
			case "epoch":
				ad.Payload.Epoch++
			case "root":
				ad.Payload.Root = f.local.public
			case "target":
				ad.Payload.Node = f.root.public
			case "token", "forged":
				ad.Payload.Token[0] ^= 1
			case "origin":
				p.TargetContact = "http://127.0.0.1:12346"
				ad.Payload.PeerIntroductionURL = p.TargetContact + "/peer/introduction"
			}
			if field != "forged" {
				digest := key.HashTagged(ads.SignaturePurpose,
					try.To1(wire.Marshal(ad.Payload)))
				ad.Signature = try.To1(f.local.handle.Sign(digest[:]))
			}
			p.Ad = try.To1(wire.Marshal(ad))
			raw := signEstablishmentV2(t, p, f.peer.handle, EstablishPurposeV2)
			f.f.unchanged(t, func() {
				assert.Equal(f.acceptV2(raw, f.local.handle), ErrEstablishment)
			})
			f.unconsumed(t)
		})
	}
}

func TestBobAcceptV2SignedFalseDeclaration(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, false)
	saved := try.To1(f.saveV2(aliceServiceOrigin))
	p := try.To1(decodeEstablishmentV2(saved.request,
		f.root.public, f.local.public)).Payload
	p.RequesterContact = "http://127.0.0.1:4041" // No listener or ownership proof.
	raw := signEstablishmentV2(t, p, f.peer.handle, EstablishPurposeV2)
	f.alice.unchanged(t, func() {
		try.To(f.acceptV2(raw, f.local.handle))
		response := try.To1(f.replyV2(raw, f.local.handle))
		try.To(verifyAcceptedV2(response, acceptedPayloadV2(p, raw)))
		original := try.To1(decodeEstablishmentV2(saved.request,
			f.root.public, f.local.public)).Payload
		assert.Equal(verifyAcceptedV2(response,
			acceptedPayloadV2(original, saved.request)), ErrEstablishment)
	})
	assert.DeepEqual(requesterRecords(t, f.alice.vault),
		[3][]byte{saved.request, nil, nil})
}
