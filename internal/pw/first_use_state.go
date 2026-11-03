package pw

import (
	"bytes"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const (
	firstUseKey = "local-pw-first-use-v1"
	useSeenKey  = "local-pw-use-seen-v1"
	useAwait    = "Await"
	useReady    = "Ready"
	useExpired  = "Expired"
)

// Separate local observations. Neither record is PWOpen, Trust, or live state.
// Existing acceptedRecord/heldRecord formats remain unchanged.
type firstUseRecord struct {
	_        struct{} `cbor:",toarray"`
	Version  uint8
	State    string
	Request  []byte
	Response []byte
}

type firstUseReceipt struct {
	_        struct{} `cbor:",toarray"`
	Version  uint8
	Request  []byte
	Response []byte
}

// Authenticate retained history without bootstrap's live-ad/expiry guards.
// The historical ad, including device/epoch/slot/endpoint and its signature,
// is checked by decodeEstablishment. This v1 supports only the pinned software
// device and epoch 0; it defines no rotation or ad-renewal protocol for reuse.
func firstUseHistory(tx storage.ReadTx, root, local key.Public, alice bool,
) (_ Accepted, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.That(validPublic(root) && validPublic(local), ErrFirstUse)
	raw, found := try.To2(tx.Get([]byte(acceptedKey)))
	assert.That(found && len(raw) <= 2*MaxEstablishmentBytes+16, ErrFirstUse)
	var history acceptedRecord
	assert.That(wire.DecMode.Unmarshal(raw, &history) == nil, ErrFirstUse)
	assert.That(history.Version == 1 &&
		bytes.Equal(raw, try.To1(wire.Marshal(history))), ErrFirstUse)
	var request SignedEstablishment
	try.To(decodeEstablishmentCanonical(history.Request, &request))
	target := local
	if alice {
		target = request.Payload.Target
	}
	request = try.To1(decodeEstablishment(history.Request, root, target))
	p := acceptedPayload(request.Payload, history.Request)
	try.To(verifyAccepted(history.Response, p))
	attempt, attempting := try.To2(tx.Get([]byte(attemptKey)))
	if alice {
		assert.That(bytes.Equal(p.Binding.Requester, local) && attempting &&
			bytes.Equal(attempt, history.Request), ErrFirstUse)
		_, seen := try.To2(tx.Get([]byte(useSeenKey)))
		assert.ThatNot(seen, ErrFirstUse)
	} else {
		assert.ThatNot(attempting, ErrFirstUse)
		row, exists := try.To2(readInvitation(tx, root, local))
		assert.That(exists && row.State == InvitationConsumed &&
			matchesInvitation(row, p.Binding), ErrFirstUse)
		_, using := try.To2(tx.Get([]byte(firstUseKey)))
		assert.ThatNot(using, ErrFirstUse)
	}
	return p, nil
}

func firstUseGuards(tx storage.ReadTx, p Accepted, alice bool) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	root, local, peer := p.Binding.Root, p.Binding.Target, p.Binding.Requester
	if alice {
		local, peer = peer, local
	}
	own := try.To1(onboarding.IsKnownIntroductionInTx(tx, root, local))
	other := try.To1(onboarding.IsKnownIntroductionInTx(tx, root, peer))
	assert.That((own || bytes.Equal(root, local)) &&
		(other || bytes.Equal(root, peer)), ErrFirstUse)
	assert.ThatNot(
		try.To1(policy.IsDeniedInTx(tx, root, local, peer)),
		ErrFirstUse,
	)
	assert.That(
		try.To1(device.IsAuthorizedLocalInTx(tx, root, local)),
		ErrFirstUse,
	)

	raw, found := try.To2(tx.Get([]byte(heldKey)))
	assert.That(found && len(raw) <= 128, ErrFirstUse)
	var held heldRecord
	assert.That(wire.DecMode.Unmarshal(raw, &held) == nil, ErrFirstUse)
	assert.That(held.Version == 1 &&
		bytes.Equal(raw, try.To1(wire.Marshal(held))) &&
		bytes.Equal(held.RequestDigest, p.RequestDigest), ErrFirstUse)
	return nil
}

func readFirstUse(tx storage.ReadTx, expected Accepted,
) (_ firstUseRecord, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	raw, found := try.To2(tx.Get([]byte(firstUseKey)))
	if !found {
		return firstUseRecord{}, nil
	}
	assert.That(len(raw) <= 2*MaxEstablishmentBytes+64, ErrFirstUse)
	var record firstUseRecord
	assert.That(wire.DecMode.Unmarshal(raw, &record) == nil, ErrFirstUse)
	assert.That(record.Version == 1 &&
		bytes.Equal(raw, try.To1(wire.Marshal(record))), ErrFirstUse)
	p := try.To1(decodeFirstUse(record.Request, expected))
	switch record.State {
	case useAwait:
		assert.That(record.Response == nil, ErrFirstUse)
	case useReady:
		assert.SNotEmpty(record.Response, ErrFirstUse)
	case useExpired:
	default:
		return firstUseRecord{}, ErrFirstUse
	}
	if record.Response != nil {
		try.To(verifyFirstUseResponse(record.Response,
			firstUseResponsePayload(p, record.Request)))
	}
	return record, nil
}
