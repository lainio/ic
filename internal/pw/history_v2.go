package pw

import (
	"bytes"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// Owned, authenticated local evidence only. Version 1 deliberately has no v2
// binding/request projection. Callers creating v2 state must reject it.
type localHistoryV2 struct {
	version  uint8
	request  []byte
	response []byte
	binding  EstablishmentV2
	accepted bool
	held     bool
	firstUse firstUseRecord
	useSeen  bool
}

// No current Known, device, ad-expiry, policy, runtime or signer guard belongs
// here. A missing holding is legal only with intact accepted history. Role is
// supplied by the local API, never inferred from an untrusted peer selector.
func readLocalHistoryV2(tx storage.ReadTx, root, local key.Public, alice bool,
) (_ localHistoryV2, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.That(validPublic(root) && validPublic(local), ErrEstablishment)
	row, issued := try.To2(readInvitation(tx, root, local))
	attempt, attempting := try.To2(tx.Get([]byte(attemptKey)))
	raw, accepted := try.To2(tx.Get([]byte(acceptedKey)))
	_, held := try.To2(tx.Get([]byte(heldKey)))
	assert.That(alice || !attempting, ErrEstablishment)
	assert.That(!issued || row.State != InvitationConsumed ||
		(accepted && !attempting), ErrEstablishment)
	if !accepted {
		assert.ThatNot(held, ErrEstablishment)
		try.To(noFirstUseV2(tx))
		if !attempting {
			return localHistoryV2{}, nil
		}
		return readPendingHistoryV2(attempt, root, local)
	}

	assert.That(len(raw) <= 2*MaxEstablishmentBytes+16, ErrEstablishment)
	var record acceptedRecord
	assert.That(wire.DecMode.Unmarshal(raw, &record) == nil &&
		bytes.Equal(raw, try.To1(wire.Marshal(record))), ErrEstablishment)
	if record.Version == 1 {
		try.To(validateLegacyContactHistory(tx, root, local, alice))
		return localHistoryV2{version: 1}, nil
	}
	assert.That(record.Version == 2, ErrEstablishment)
	var request SignedEstablishmentV2
	try.To(decodeEstablishmentCanonical(record.Request, &request))
	target := local
	if alice {
		target = request.Payload.Target
		assert.That(attempting && bytes.Equal(attempt, record.Request) &&
			bytes.Equal(request.Payload.Requester, local), ErrEstablishment)
	}
	request = try.To1(decodeEstablishmentV2(record.Request, root, target))
	p := request.Payload
	if !alice {
		assert.That(issued && row.State == InvitationConsumed &&
			matchesInvitation(row, p.guardBinding()), ErrEstablishment)
	}
	payload := acceptedPayloadV2(p, record.Request)
	try.To(verifyAcceptedV2(record.Response, payload))
	held = try.To1(readHistoryHolding(tx, 2, payload.RequestDigest))
	firstUse, useSeen := try.To2(readUseHistoryV2(tx, payload, alice))
	return localHistoryV2{version: 2, request: bytes.Clone(record.Request),
		response: bytes.Clone(record.Response), binding: p,
		accepted: true, held: held, firstUse: firstUse, useSeen: useSeen}, nil
}

func readPendingHistoryV2(raw []byte, root, local key.Public,
) (_ localHistoryV2, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	var request SignedEstablishmentV2
	if decodeEstablishmentCanonical(raw, &request) != nil {
		// The array layouts are disjoint. Authenticate a genuine v1 pending
		// attempt as legacy absence, never as a fresh v2 slot.
		var legacy SignedEstablishment
		try.To(decodeEstablishmentCanonical(raw, &legacy))
		legacy = try.To1(decodeEstablishment(raw, root, legacy.Payload.Target))
		assert.That(bytes.Equal(legacy.Payload.Requester, local), ErrEstablishment)
		return localHistoryV2{version: 1}, nil
	}
	request = try.To1(decodeEstablishmentV2(raw, root, request.Payload.Target))
	assert.That(bytes.Equal(request.Payload.Requester, local), ErrEstablishment)
	return localHistoryV2{version: 2, request: bytes.Clone(raw),
		binding: request.Payload}, nil
}

func noFirstUseV2(tx storage.ReadTx) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)
	_, using := try.To2(tx.Get([]byte(firstUseKey)))
	_, seen := try.To2(tx.Get([]byte(useSeenKey)))
	assert.That(!using && !seen, ErrEstablishment)
	return nil
}

func readHistoryHolding(tx storage.ReadTx, version uint8, digest []byte,
) (_ bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)
	raw, found := try.To2(tx.Get([]byte(heldKey)))
	if !found {
		return false, nil
	}
	assert.That(len(raw) <= 128, ErrEstablishment)
	var record heldRecord
	assert.That(wire.DecMode.Unmarshal(raw, &record) == nil, ErrEstablishment)
	assert.That(record.Version == version &&
		bytes.Equal(raw, try.To1(wire.Marshal(record))) &&
		bytes.Equal(record.RequestDigest, digest), ErrEstablishment)
	return true, nil
}

// Valid v1 history has no contact. Authenticate its original role, holding and
// optional first-use evidence before reporting that absence; do not upgrade it.
func validateLegacyContactHistory(tx storage.ReadTx, root, local key.Public,
	alice bool,
) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)
	p := try.To1(firstUseHistory(tx, root, local, alice))
	try.To1(readHistoryHolding(tx, 1, p.RequestDigest))
	if alice {
		try.To1(readFirstUse(tx, p))
		return nil
	}
	raw, seen := try.To2(tx.Get([]byte(useSeenKey)))
	if seen {
		assert.That(len(raw) <= 2*MaxEstablishmentBytes+16, ErrEstablishment)
		var record firstUseReceipt
		assert.That(wire.DecMode.Unmarshal(raw, &record) == nil &&
			record.Version == 1 &&
			bytes.Equal(raw, try.To1(wire.Marshal(record))), ErrEstablishment)
		request := try.To1(decodeFirstUse(record.Request, p))
		try.To(verifyFirstUseResponse(record.Response,
			firstUseResponsePayload(request, record.Request)))
	}
	return nil
}
