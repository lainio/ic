package pw

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
)

const (
	EstablishPurpose      = "pw-invitation-establish/v1"
	AcceptedPurpose       = "pw-invitation-accepted/v1"
	requestPurpose        = "pw-invitation-request-digest/v1"
	MaxEstablishmentBytes = 2048
)

var ErrEstablishment = errors.New("pairwise establishment refused")

// Establishment is the v1 canonical CBOR array in declaration order. The
// requester signs HashTagged(EstablishPurpose, wire.Marshal(payload)). Attempt
// is a stable 32-byte establishment ID, independent of ephemeral challenges.
// Only Device == Requester, epoch 0 and the existing slot-1 ad are supported.
// This is an implementation encoding, not an authenticated key-exchange proof.
type Establishment struct {
	_            struct{} `cbor:",toarray"`
	Version      uint8
	Root         key.Public
	Requester    key.Public
	Target       key.Public
	InvitationID []byte
	Audience     string
	Recipient    key.Public
	AttemptID    []byte
	Device       key.Public
	Epoch        uint64
	Ad           []byte
}

type SignedEstablishment struct {
	_         struct{} `cbor:",toarray"`
	Payload   Establishment
	Signature key.Signature
}

// Accepted authenticates the entire binding and a domain-separated digest of
// the exact signed request, including its signature. Different signed bytes
// are never an exact retry, even if they express the same payload.
type Accepted struct {
	_             struct{} `cbor:",toarray"`
	Version       uint8
	Binding       Establishment
	RequestDigest []byte
}

type SignedAccepted struct {
	_         struct{} `cbor:",toarray"`
	Payload   Accepted
	Signature key.Signature
}

// Decode into owned storage before authentication. Decoder diagnostics must
// not reach tracing or HTTP; re-encoding rejects tags, aliases and extra data.
func decodeEstablishment(raw []byte, root, local key.Public,
) (_ SignedEstablishment, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.That(validPublic(root) && validPublic(local), ErrEstablishment)
	var request SignedEstablishment
	try.To(decodeEstablishmentCanonical(raw, &request))
	p := request.Payload
	assert.That(p.Version == 1 && bytes.Equal(p.Root, root) &&
		bytes.Equal(p.Target, local) && validPublic(p.Requester) &&
		!bytes.Equal(p.Requester, local), ErrEstablishment)
	assert.That(len(p.InvitationID) == 32 && len(p.AttemptID) == 32 &&
		bytes.Equal(p.Device, p.Requester) && p.Epoch == 0, ErrEstablishment)
	assert.That((p.Audience == InvitationAny && p.Recipient == nil) ||
		(p.Audience == InvitationDirected &&
			bytes.Equal(p.Recipient, p.Requester)), ErrEstablishment)
	assert.That(ads.ValidateClaim(root, local, p.Ad) == nil, ErrEstablishment)
	var ad ads.Current
	assert.That(wire.DecMode.Unmarshal(p.Ad, &ad) == nil, ErrEstablishment)
	adDigest := key.HashTagged(ads.SignaturePurpose,
		try.To1(wire.Marshal(ad.Payload)))
	assert.That(ad.Signature.Verify(local, adDigest[:]), ErrEstablishment)
	digest := key.HashTagged(EstablishPurpose, try.To1(wire.Marshal(p)))
	assert.That(len(request.Signature) > 0 && len(request.Signature) <= 72 &&
		request.Signature.Verify(p.Requester, digest[:]), ErrEstablishment)
	return request, nil
}

func decodeEstablishmentCanonical(raw []byte, result any) error {
	if len(raw) == 0 || len(raw) > MaxEstablishmentBytes ||
		wire.DecMode.Unmarshal(raw, result) != nil {
		return ErrEstablishment
	}
	canonical, err := wire.EncMode.Marshal(result)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ErrEstablishment
	}
	return nil
}

func acceptedPayload(p Establishment, raw []byte) Accepted {
	digest := key.HashTagged(requestPurpose, raw)
	return Accepted{Version: 1, Binding: p, RequestDigest: digest[:]}
}

func verifyAccepted(raw []byte, expected Accepted) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	var result SignedAccepted
	try.To(decodeEstablishmentCanonical(raw, &result))
	payload := try.To1(wire.Marshal(result.Payload))
	assert.That(bytes.Equal(payload, try.To1(wire.Marshal(expected))),
		ErrEstablishment)
	digest := key.HashTagged(AcceptedPurpose, payload)
	assert.That(len(result.Signature) > 0 && len(result.Signature) <= 72 &&
		result.Signature.Verify(expected.Binding.Target, digest[:]),
		ErrEstablishment)
	return nil
}

const (
	EstablishPurposeV2     = "pw-invitation-establish/v2"
	maxServiceContactBytes = 256
)

// EstablishmentV2 is a separate canonical CBOR array in declaration order.
// It binds both service origins with every v1 field, under EstablishPurposeV2.
// The v1 array, signing purposes and accepted evidence retain v1 meaning only.
// RequesterContact authenticates a declaration, not listener control or
// reachability. TargetContact must equal the authenticated ad's service origin.
type EstablishmentV2 struct {
	_                struct{} `cbor:",toarray"`
	Version          uint8
	Root             key.Public
	Requester        key.Public
	Target           key.Public
	InvitationID     []byte
	Audience         string
	Recipient        key.Public
	AttemptID        []byte
	Device           key.Public
	Epoch            uint64
	Ad               []byte
	RequesterContact string
	TargetContact    string
}

type SignedEstablishmentV2 struct {
	_         struct{} `cbor:",toarray"`
	Payload   EstablishmentV2
	Signature key.Signature
}

// Shared local prerequisite/descriptor checks only. Never encode this
// projection, authenticate it as v1, or use it to construct accepted evidence.
func (p EstablishmentV2) guardBinding() Establishment {
	return Establishment{Version: p.Version, Root: p.Root,
		Requester: p.Requester, Target: p.Target, InvitationID: p.InvitationID,
		Audience: p.Audience, Recipient: p.Recipient, AttemptID: p.AttemptID,
		Device: p.Device, Epoch: p.Epoch, Ad: p.Ad}
}

// Request authentication only: no Bob acceptance, holding or contact authority.
// Like v1, this decodes into owned storage and rejects noncanonical bytes before
// verifying independent pinned identities. Freshness/currentness is a separate
// Vault guard; this does not turn a supplied ad into locally verified evidence.
func decodeEstablishmentV2(raw []byte, root, target key.Public,
) (_ SignedEstablishmentV2, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.That(validPublic(root) && validPublic(target), ErrEstablishment)
	var request SignedEstablishmentV2
	try.To(decodeEstablishmentCanonical(raw, &request))
	p := request.Payload
	assert.That(p.Version == 2 && bytes.Equal(p.Root, root) &&
		bytes.Equal(p.Target, target) && validPublic(p.Requester) &&
		!bytes.Equal(p.Requester, target), ErrEstablishment)
	assert.That(len(p.InvitationID) == 32 && len(p.AttemptID) == 32 &&
		bytes.Equal(p.Device, p.Requester) && p.Epoch == 0, ErrEstablishment)
	assert.That((p.Audience == InvitationAny && p.Recipient == nil) ||
		(p.Audience == InvitationDirected &&
			bytes.Equal(p.Recipient, p.Requester)), ErrEstablishment)
	assert.That(canonicalServiceContact(p.RequesterContact) &&
		canonicalServiceContact(p.TargetContact), ErrEstablishment)
	assert.That(ads.ValidateClaim(root, target, p.Ad) == nil, ErrEstablishment)
	var ad ads.Current
	assert.That(wire.DecMode.Unmarshal(p.Ad, &ad) == nil, ErrEstablishment)
	adDigest := key.HashTagged(ads.SignaturePurpose,
		try.To1(wire.Marshal(ad.Payload)))
	assert.That(ad.Signature.Verify(target, adDigest[:]), ErrEstablishment)
	assert.That(p.TargetContact == try.To1(serviceContactFromAd(p.Ad)),
		ErrEstablishment)
	digest := key.HashTagged(EstablishPurposeV2, try.To1(wire.Marshal(p)))
	assert.That(len(request.Signature) > 0 && len(request.Signature) <= 72 &&
		request.Signature.Verify(p.Requester, digest[:]), ErrEstablishment)
	return request, nil
}

// Match ads' strict canonical loopback literal convention without calling the
// address normalizer (whose traced parse diagnostics can contain raw inputs).
// A service origin has no aliases, port zero, zone, userinfo, path or suffix.
func canonicalServiceContact(value string) bool {
	const prefix = "http://"
	if len(value) > maxServiceContactBytes ||
		!strings.HasPrefix(value, prefix) || strings.Contains(value, "%") {
		return false
	}
	parsed, err := netip.ParseAddrPort(strings.TrimPrefix(value, prefix))
	return err == nil && parsed.Port() != 0 && parsed.Addr().IsLoopback() &&
		value == prefix+netip.AddrPortFrom(
			parsed.Addr().Unmap(), parsed.Port()).String()
}

// Call only after authenticating the ad, with local VerifiedAd/currentness
// checks as appropriate. The protocol path is never part of the signed origin.
func serviceContactFromAd(raw []byte) (_ string, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)
	var ad ads.Current
	assert.That(wire.DecMode.Unmarshal(raw, &ad) == nil, ErrEstablishment)
	const path = "/peer/introduction"
	endpoint := ad.Payload.PeerIntroductionURL
	assert.That(strings.HasSuffix(endpoint, path), ErrEstablishment)
	origin := strings.TrimSuffix(endpoint, path)
	assert.That(canonicalServiceContact(origin), ErrEstablishment)
	return origin, nil
}
