package pw

import (
	"bytes"
	"errors"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

var (
	ErrDeleteHeld    = errors.New("local holding deletion refused")
	errHeldUnchanged = errors.New("local holding unchanged")
)

// DeleteHeldLocal forgets only this Vault's accepted held half. It implements
// ChangeBob/ChangeRequester("Delete"), not full V19 DeleteLocalPW. Immutable
// invitation/attempt/acceptance and first-use history remain byte-for-byte;
// neither a retained Ready nor useSeen is authority to use a deleted holding.
//
// Only an explicit authorized local owner request may call this. The caller
// supplies independently pinned Root/local configuration and its already-bound
// Vault, and holds the same owner mutation lock as acceptance, first use,
// publication/policy and signer lifecycle operations. No remote input selects
// the Vault, identity or key. Release that lock before response I/O.
//
// One Update authenticates the complete local binding before removing heldKey.
// There is no signer, current ad/expiry, device or policy requirement. True is
// returned only after commit. Valid absence aborts without writes or encryption
// spending; corrupt/partial state is never repaired or treated as empty. Existing
// accepted history prevents resurrection; no tombstone or Deny is added.
func DeleteHeldLocal(vault *storage.Vault, root, local key.Public,
) (_ bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return ErrDeleteHeld })

	assert.That(validInvitationBinding(vault, root, local), ErrDeleteHeld)
	root, local = bytes.Clone(root), bytes.Clone(local)
	updateErr := vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return deleteHeldInTx(tx, root, local)
	})
	if updateErr == errHeldUnchanged {
		return false, nil
	}
	try.To(updateErr)
	return true, nil
}

func deleteHeldInTx(tx storage.WriteTx, root, local key.Public) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	row, issued := try.To2(readInvitation(tx, root, local))
	attempt, attempting := try.To2(tx.Get([]byte(attemptKey)))
	history, accepted := try.To2(tx.Get([]byte(acceptedKey)))
	holding, held := try.To2(tx.Get([]byte(heldKey)))
	_, using := try.To2(tx.Get([]byte(firstUseKey)))
	receipt, seen := try.To2(tx.Get([]byte(useSeenKey)))
	// An unused local invitation may coexist with a requester attempt, but
	// consumption belongs exclusively to Bob's accepted binding.
	assert.That(!issued || row.State != InvitationConsumed ||
		(accepted && !attempting), ErrDeleteHeld)
	// The shared slots retain their versioned meanings. V2 authenticates its
	// complete role-specific tuple and refuses all first-use state. It needs
	// no live guard or signer, and removes only the separately held half.
	if try.To1(hasV2History(history, attempt)) {
		saved := try.To1(readLocalHistoryV2(tx, root, local, attempting))
		assert.That(saved.version == 2, ErrDeleteHeld)
		if !saved.held {
			return errHeldUnchanged
		}
		return tx.Delete([]byte(heldKey))
	}
	if !accepted {
		assert.That(!held && !using && !seen, ErrDeleteHeld)
		if attempting {
			var request SignedEstablishment
			try.To(decodeEstablishmentCanonical(attempt, &request))
			request = try.To1(decodeEstablishment(
				attempt, root, request.Payload.Target,
			))
			assert.That(bytes.Equal(request.Payload.Requester, local),
				ErrDeleteHeld)
		}
		return errHeldUnchanged
	}

	// This validates signed acceptance, exact attempt or consumed invitation,
	// and role without consulting current usability or bootstrap guards.
	p := try.To1(firstUseHistory(tx, root, local, attempting))
	if attempting {
		try.To1(readFirstUse(tx, p))
	} else if seen {
		assert.That(len(receipt) <= 2*MaxEstablishmentBytes+16, ErrDeleteHeld)
		var record firstUseReceipt
		assert.That(wire.DecMode.Unmarshal(receipt, &record) == nil,
			ErrDeleteHeld)
		assert.That(record.Version == 1 &&
			bytes.Equal(receipt, try.To1(wire.Marshal(record))), ErrDeleteHeld)
		request := try.To1(decodeFirstUse(record.Request, p))
		try.To(verifyFirstUseResponse(record.Response,
			firstUseResponsePayload(request, record.Request)))
	}
	if !held {
		return errHeldUnchanged
	}
	assert.That(len(holding) <= 128, ErrDeleteHeld)
	var record heldRecord
	assert.That(wire.DecMode.Unmarshal(holding, &record) == nil, ErrDeleteHeld)
	assert.That(record.Version == 1 &&
		bytes.Equal(holding, try.To1(wire.Marshal(record))) &&
		bytes.Equal(record.RequestDigest, p.RequestDigest), ErrDeleteHeld)
	return tx.Delete([]byte(heldKey))
}

func hasV2History(history, attempt []byte) (_ bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)
	if history != nil {
		assert.That(len(history) <= 2*MaxEstablishmentBytes+16, ErrDeleteHeld)
		var record acceptedRecord
		assert.That(wire.DecMode.Unmarshal(history, &record) == nil,
			ErrDeleteHeld)
		return record.Version == 2, nil // Full authentication follows dispatch.
	}
	if attempt != nil {
		var request SignedEstablishmentV2
		return decodeEstablishmentCanonical(attempt, &request) == nil, nil
	}
	return false, nil
}
