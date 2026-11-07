package pw

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
)

func signEstablishmentV2(t *testing.T, p EstablishmentV2,
	signer key.Handle, purpose string,
) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	digest := key.HashTagged(purpose, try.To1(wire.Marshal(p)))
	return try.To1(wire.Marshal(SignedEstablishmentV2{Payload: p,
		Signature: try.To1(signer.Sign(digest[:]))}))
}

func TestEstablishmentV2RejectsContactEvidence(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, true)
	saved := try.To1(f.saveV2(aliceServiceOrigin))
	for name, change := range map[string]func(*EstablishmentV2){
		"changed requester": func(p *EstablishmentV2) {
			p.RequesterContact = "http://127.0.0.1:4041"
		},
		"changed target": func(p *EstablishmentV2) {
			p.TargetContact = "http://127.0.0.1:12346"
		},
		"swapped": func(p *EstablishmentV2) {
			p.RequesterContact, p.TargetContact = p.TargetContact, p.RequesterContact
		},
	} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			request := try.To1(decodeEstablishmentV2(saved.request,
				f.root.public, f.local.public))
			change(&request.Payload) // Keep the original signature.
			f.alice.unchanged(t, func() {
				_, err := decodeEstablishmentV2(try.To1(wire.Marshal(request)),
					f.root.public, f.local.public)
				assert.Equal(err, ErrEstablishment)
			})
		})
	}
	request := try.To1(decodeEstablishmentV2(saved.request,
		f.root.public, f.local.public))
	for _, raw := range [][]byte{
		nil, {0xff}, saved.request[:len(saved.request)-1],
		append(bytes.Clone(saved.request), 0),
		append([]byte{0x98, 2}, saved.request[1:]...),
		append([]byte{0xc0}, saved.request...),
		make([]byte, MaxEstablishmentBytes+1), f.raw,
		signEstablishmentV2(t, request.Payload, f.local.handle, EstablishPurposeV2),
		signEstablishmentV2(t, request.Payload, f.peer.handle, EstablishPurpose),
	} {
		_, err := decodeEstablishmentV2(raw, f.root.public, f.local.public)
		assert.Equal(err, ErrEstablishment)
	}
	request.Signature = nil
	_, err := decodeEstablishmentV2(try.To1(wire.Marshal(request)),
		f.root.public, f.local.public)
	assert.Equal(err, ErrEstablishment)
	_, err = decodeEstablishment(saved.request, f.root.public, f.local.public)
	assert.Equal(err, ErrEstablishment)
	assert.DeepEqual(requesterRecords(t, f.alice.vault),
		[3][]byte{saved.request, nil, nil})
	f.unconsumed(t)
}

func TestEstablishmentV2RejectsSignedInvalidBindings(t *testing.T) {
	f := newRequester(t, true)
	saved, err := f.saveV2(aliceServiceOrigin)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*EstablishmentV2){
		"version":          func(p *EstablishmentV2) { p.Version = 1 },
		"root":             func(p *EstablishmentV2) { p.Root = p.Requester },
		"requester":        func(p *EstablishmentV2) { p.Requester = p.Root },
		"target":           func(p *EstablishmentV2) { p.Target = p.Root },
		"invitation":       func(p *EstablishmentV2) { p.InvitationID = nil },
		"attempt":          func(p *EstablishmentV2) { p.AttemptID = nil },
		"audience":         func(p *EstablishmentV2) { p.Audience = "Other" },
		"recipient":        func(p *EstablishmentV2) { p.Recipient = p.Target },
		"device":           func(p *EstablishmentV2) { p.Device = p.Target },
		"epoch":            func(p *EstablishmentV2) { p.Epoch = 1 },
		"ad":               func(p *EstablishmentV2) { p.Ad[0] ^= 1 },
		"own unconfigured": func(p *EstablishmentV2) { p.RequesterContact = "" },
		"own alias": func(p *EstablishmentV2) {
			p.RequesterContact = "http://localhost:4040"
		},
		"own path": func(p *EstablishmentV2) {
			p.RequesterContact += "/peer/introduction"
		},
		"target alias": func(p *EstablishmentV2) {
			p.TargetContact = "http://localhost:12345"
		},
		"target path": func(p *EstablishmentV2) {
			p.TargetContact += "/peer/introduction"
		},
		"target differs from ad": func(p *EstablishmentV2) {
			p.TargetContact = "http://127.0.0.1:12346"
		},
		"swapped": func(p *EstablishmentV2) {
			p.RequesterContact, p.TargetContact = p.TargetContact, p.RequesterContact
		},
	} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			request := try.To1(decodeEstablishmentV2(saved.request,
				f.root.public, f.local.public))
			change(&request.Payload)
			raw := signEstablishmentV2(t, request.Payload, f.peer.handle,
				EstablishPurposeV2)
			_, err := decodeEstablishmentV2(raw, f.root.public, f.local.public)
			assert.Equal(err, ErrEstablishment)
		})
	}
}

func TestEstablishmentV2AuthenticatesAdContact(t *testing.T) {
	for _, mode := range []string{"forged", "alias", "ipv6"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			saved := try.To1(f.saveV2(aliceServiceOrigin))
			request := try.To1(decodeEstablishmentV2(saved.request,
				f.root.public, f.local.public))
			var ad ads.Current
			try.To(wire.UnmarshalCanonical(&ad, request.Payload.Ad))
			origin := "http://[::1]:12345"
			if mode == "alias" {
				origin = "http://localhost:12345"
			}
			ad.Payload.PeerIntroductionURL = origin + "/peer/introduction"
			digest := key.HashTagged(ads.SignaturePurpose,
				try.To1(wire.Marshal(ad.Payload)))
			if mode != "forged" {
				ad.Signature = try.To1(f.local.handle.Sign(digest[:]))
			}
			request.Payload.Ad = try.To1(wire.Marshal(ad))
			request.Payload.TargetContact = origin
			raw := signEstablishmentV2(t, request.Payload, f.peer.handle,
				EstablishPurposeV2)
			_, err := decodeEstablishmentV2(raw, f.root.public, f.local.public)
			if mode == "ipv6" {
				assert.NoError(err)
			} else {
				assert.Equal(err, ErrEstablishment)
			}
		})
	}
}

// Freeze the v1 array and purposes independently of v2. Small byte values here
// are encoding vectors, not valid keys or authenticated establishment evidence.
func TestEstablishmentV1CanonicalVector(t *testing.T) {
	defer assert.PushTester(t)()
	p := Establishment{Version: 1, Root: []byte{1}, Requester: []byte{2},
		Target: []byte{3}, InvitationID: []byte{4}, Audience: InvitationAny,
		AttemptID: []byte{5}, Device: []byte{2}, Ad: []byte{6}}
	const payload = "8b01410141024103410463416e79f641054102004106"
	assert.Equal(hex.EncodeToString(try.To1(wire.Marshal(p))), payload)
	assert.Equal(hex.EncodeToString(try.To1(wire.Marshal(SignedEstablishment{
		Payload: p, Signature: []byte{7}}))), "82"+payload+"4107")
	assert.Equal(EstablishPurpose, "pw-invitation-establish/v1")
	assert.Equal(AcceptedPurpose, "pw-invitation-accepted/v1")
	assert.Equal(requestPurpose, "pw-invitation-request-digest/v1")
}
