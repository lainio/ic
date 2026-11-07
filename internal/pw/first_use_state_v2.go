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
	"github.com/lainio/ic/storage"
)

// Authenticate the shared firstUseKey/useSeenKey slots only AFTER the complete
// v2 establishment history. These readers never call readLocalHistoryV2: no
// recursion, bootstrap currentness, signer or live permission belongs here.
// The existing record arrays retain their layout, with explicit Version 2.
func readUseHistoryV2(tx storage.ReadTx, expected AcceptedV2, alice bool,
) (_ firstUseRecord, _ bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	raw, using := try.To2(tx.Get([]byte(firstUseKey)))
	receipt, seen := try.To2(tx.Get([]byte(useSeenKey)))
	if alice {
		assert.ThatNot(seen, ErrFirstUse)
		if !using {
			return firstUseRecord{}, false, nil
		}
		return try.To1(readFirstUseV2(raw, expected)), false, nil
	}
	assert.ThatNot(using, ErrFirstUse)
	if seen {
		assert.That(len(receipt) <= 2*MaxFirstUseBytesV2+16, ErrFirstUse)
		var record firstUseReceipt
		assert.That(wire.DecMode.Unmarshal(receipt, &record) == nil &&
			record.Version == 2 &&
			bytes.Equal(receipt, try.To1(wire.Marshal(record))), ErrFirstUse)
		p := try.To1(decodeFirstUseV2(record.Request, expected))
		try.To(verifyFirstUseResponseV2(record.Response,
			firstUseResponsePayloadV2(p, record.Request)))
	}
	return firstUseRecord{}, seen, nil
}

func readFirstUseV2(raw []byte, expected AcceptedV2,
) (_ firstUseRecord, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.That(len(raw) <= 2*MaxFirstUseBytesV2+64, ErrFirstUse)
	var record firstUseRecord
	assert.That(wire.DecMode.Unmarshal(raw, &record) == nil &&
		record.Version == 2 &&
		bytes.Equal(raw, try.To1(wire.Marshal(record))), ErrFirstUse)
	p := try.To1(decodeFirstUseV2(record.Request, expected))
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
		try.To(verifyFirstUseResponseV2(record.Response,
			firstUseResponsePayloadV2(p, record.Request)))
	}
	return record, nil
}

// Reuse authenticates historical evidence and CURRENT LOCAL permission. It
// does not require a fresh public ad or invitation. The bounded device/epoch
// binding is authenticated by readLocalHistoryV2; no rotation is introduced.
// runtime is trusted configuration held stable by the caller's owner lock,
// including signer lifecycle, throughout preflight, probe, signing and commit.
func firstUseGuardsV2(tx storage.ReadTx, h localHistoryV2,
	runtime ContactRuntimeV2, alice bool,
) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.That(h.version == 2 && h.accepted && h.held, ErrFirstUse)
	p := h.binding
	root, local, peer := p.Root, p.Target, p.Requester
	ownOrigin := p.TargetContact
	if alice {
		local, peer = peer, local
		ownOrigin = p.RequesterContact
	}
	assert.That(
		runtime.Running && canonicalServiceContact(runtime.BoundOrigin) &&
			runtime.BoundOrigin == ownOrigin,
		ErrFirstUse,
	)
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
	return nil
}
