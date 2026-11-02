package pw

import (
	"bytes"
	"crypto/rand"
	"errors"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const attemptKey = "local-pw-attempt-v1"

var errRequesterUnchanged = errors.New("requester acceptance unchanged")

// SavedAttempt is an owned snapshot obtained only from SaveAttempt. Its private
// request and endpoint prevent caller-selected bytes/URLs at SendEstablish.
// Accepted and Held describe only this Vault, never current peer permission.
type SavedAttempt struct {
	request  []byte
	endpoint string
	Accepted bool
	Held     bool
}

// SaveAttempt implements SaveAttempt for one bounded requester attempt per
// independently Root/local-bound Vault. The descriptor is out-of-band; Directed
// always means this local identity. All ad/endpoint evidence comes from the
// Vault. The caller MUST hold its owner mutation/signer lock across this call.
// Signing/probing occurs outside transactions; durable guards are reread in the
// sole Update. Existing exact attempts are read-only and never re-signed.
func SaveAttempt(vault *storage.Vault, root, local, target key.Public,
	signer key.Handle, invitationID []byte, audience string,
) (SavedAttempt, error) {
	return saveAttempt(vault, root, local, target, signer, invitationID,
		audience, time.Now)
}

func saveAttempt(
	vault *storage.Vault,
	root, local, target key.Public,
	signer key.Handle,
	invitationID []byte,
	audience string,
	now func() time.Time,
) (_ SavedAttempt, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return ErrEstablishment })

	assert.That(vault != nil && validPublic(root) && validPublic(local) &&
		validPublic(target) && !bytes.Equal(local, target) &&
		len(invitationID) == 32 &&
		(audience == InvitationAny || audience == InvitationDirected),
		ErrEstablishment)
	p := Establishment{Version: 1, Root: bytes.Clone(root),
		Requester: bytes.Clone(local), Target: bytes.Clone(target),
		InvitationID: bytes.Clone(invitationID), Audience: audience,
		Device: bytes.Clone(local)}
	if audience == InvitationDirected {
		p.Recipient = bytes.Clone(local)
	}

	var saved SavedAttempt
	read := func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		saved = try.To1(readRequester(tx, p.Root, p.Requester, now))
		if saved.request != nil {
			request := try.To1(
				decodeEstablishment(saved.request, p.Root, p.Target),
			)
			assert.That(matchesInvitation(Invitation{Root: p.Root,
				Target: p.Target, ID: p.InvitationID, Audience: p.Audience,
				Recipient: p.Recipient}, request.Payload), ErrEstablishment)
		} else {
			p.Ad = try.To1(requesterGuards(tx, p, now))
		}
		return nil
	}
	try.To(vault.View(read)) // Reject denied/conflicting state before signing.
	state := try.To1(device.InspectLocal(vault, p.Root, p.Requester,
		localSigner{signer}))
	assert.That(state.Authorized && state.Usable, ErrEstablishment)
	try.To(vault.View(read)) // Recheck after the external signer probe.
	if saved.request != nil {
		return saved, nil
	}

	p.AttemptID = make([]byte, 32)
	try.To1(rand.Read(p.AttemptID))
	digest := key.HashTagged(EstablishPurpose, try.To1(wire.Marshal(p)))
	signature := try.To1((localSigner{signer}).Sign(bytes.Clone(digest[:])))
	raw := try.To1(wire.Marshal(SignedEstablishment{
		Payload: p, Signature: bytes.Clone(signature),
	}))
	try.To1(decodeEstablishment(raw, p.Root, p.Target))
	try.To(vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		prior := try.To1(readRequester(tx, p.Root, p.Requester, now))
		assert.That(prior.request == nil, ErrEstablishment)
		try.To1(requesterGuards(tx, p, now))
		return tx.Put([]byte(attemptKey), raw)
	}))
	return attemptSnapshot(raw, p.Ad, false, false), nil
}

// ReceiveAcceptance implements the independent Alice-local commit. The saved
// request, not a supplied binding, is authority. Hold the same owner lock as
// SaveAttempt; probe outside transactions, then revalidate in one Update. An
// exact duplicate uses only Views and cannot resurrect a deleted holding.
func ReceiveAcceptance(vault *storage.Vault, root, local key.Public,
	signer key.Handle, response []byte,
) (bool, error) {
	return receiveAcceptance(vault, root, local, signer, response, time.Now)
}

func receiveAcceptance(vault *storage.Vault, root, local key.Public,
	signer key.Handle, response []byte, now func() time.Time,
) (_ bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return ErrEstablishment })

	assert.NotNil(vault, ErrEstablishment)
	root, local = bytes.Clone(root), bytes.Clone(local)
	response = bytes.Clone(response)
	var saved SavedAttempt
	read := func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		saved = try.To1(
			checkRequesterAcceptance(tx, root, local, response, now),
		)
		return nil
	}
	try.To(vault.View(read))
	state := try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	assert.That(state.Authorized && state.Usable, ErrEstablishment)
	if saved.Accepted {
		try.To(vault.View(read))
		return saved.Held, nil
	}
	updateErr := vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		saved = try.To1(
			commitRequesterAcceptance(tx, root, local, response, now),
		)
		if saved.Accepted {
			return errRequesterUnchanged
		}
		return nil
	})
	if updateErr == errRequesterUnchanged {
		return saved.Held, nil
	}
	try.To(updateErr)
	return true, nil
}

func commitRequesterAcceptance(tx storage.WriteTx, root, local key.Public,
	response []byte, now func() time.Time,
) (_ SavedAttempt, err error) {
	defer err2.Handle(&err, nil)
	saved := try.To1(checkRequesterAcceptance(tx, root, local, response, now))
	if saved.Accepted {
		return saved, nil
	}
	digest := key.HashTagged(requestPurpose, saved.request)
	try.To(tx.Put([]byte(acceptedKey), try.To1(wire.Marshal(acceptedRecord{
		Version: 1, Request: saved.request, Response: response,
	}))))
	try.To(tx.Put([]byte(heldKey), try.To1(wire.Marshal(heldRecord{
		Version: 1, RequestDigest: digest[:],
	}))))
	return saved, nil
}

func checkRequesterAcceptance(tx storage.ReadTx, root, local key.Public,
	response []byte, now func() time.Time,
) (_ SavedAttempt, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)
	saved := try.To1(readRequester(tx, root, local, now))
	assert.That(saved.request != nil, ErrEstablishment)
	var request SignedEstablishment
	try.To(decodeEstablishmentCanonical(saved.request, &request))
	payload := acceptedPayload(request.Payload, saved.request)
	try.To(verifyAccepted(response, payload))
	if saved.Accepted {
		raw, _ := try.To2(tx.Get([]byte(acceptedKey)))
		var history acceptedRecord
		// readRequester validated this history in the same transaction.
		try.To(wire.DecMode.Unmarshal(raw, &history))
		assert.That(bytes.Equal(history.Response, response), ErrEstablishment)
	}
	return saved, nil
}

// Validate the entire bounded attempt/history/holding tuple, including role.
// Absent holding is allowed ONLY with authenticated immutable history (delete).
func readRequester(tx storage.ReadTx, root, local key.Public,
	now func() time.Time,
) (_ SavedAttempt, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)
	raw, found := try.To2(tx.Get([]byte(attemptKey)))
	history, accepted := try.To2(tx.Get([]byte(acceptedKey)))
	holding, held := try.To2(tx.Get([]byte(heldKey)))
	if !found {
		assert.That(!accepted && !held, ErrEstablishment)
		return SavedAttempt{}, nil
	}
	var request SignedEstablishment
	try.To(decodeEstablishmentCanonical(raw, &request))
	request = try.To1(decodeEstablishment(raw, root, request.Payload.Target))
	assert.That(bytes.Equal(request.Payload.Requester, local), ErrEstablishment)
	try.To1(requesterGuards(tx, request.Payload, now))
	payload := acceptedPayload(request.Payload, raw)
	if accepted {
		assert.That(
			len(history) <= 2*MaxEstablishmentBytes+16,
			ErrEstablishment,
		)
		var record acceptedRecord
		assert.That(wire.DecMode.Unmarshal(history, &record) == nil,
			ErrEstablishment)
		assert.That(record.Version == 1 && bytes.Equal(record.Request, raw) &&
			bytes.Equal(history, try.To1(wire.Marshal(record))),
			ErrEstablishment)
		try.To(verifyAccepted(record.Response, payload))
	} else {
		assert.That(!held, ErrEstablishment)
	}
	if held {
		assert.That(len(holding) <= 128, ErrEstablishment)
		var record heldRecord
		assert.That(wire.DecMode.Unmarshal(holding, &record) == nil,
			ErrEstablishment)
		assert.That(record.Version == 1 &&
			bytes.Equal(holding, try.To1(wire.Marshal(record))) &&
			bytes.Equal(record.RequestDigest, payload.RequestDigest),
			ErrEstablishment)
	}
	return attemptSnapshot(raw, request.Payload.Ad, accepted, held), nil
}

func requesterGuards(tx storage.ReadTx, p Establishment,
	now func() time.Time,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)
	own := try.To1(onboarding.IsKnownIntroductionInTx(tx, p.Root, p.Requester))
	peer := try.To1(onboarding.IsKnownIntroductionInTx(tx, p.Root, p.Target))
	assert.That((own || bytes.Equal(p.Root, p.Requester)) &&
		(peer || bytes.Equal(p.Root, p.Target)), ErrEstablishment)
	assert.ThatNot(try.To1(policy.IsDeniedInTx(tx, p.Root, p.Requester,
		p.Target)), ErrEstablishment)
	assert.That(try.To1(device.IsAuthorizedLocalInTx(tx, p.Root, p.Requester)),
		ErrEstablishment)
	ad := try.To1(ads.ReadEstablishmentAdInTx(tx, p.Root, p.Target, now()))
	assert.That(p.Ad == nil || bytes.Equal(p.Ad, ad), ErrEstablishment)
	return ad, nil
}

func attemptSnapshot(raw, ad []byte, accepted, held bool) SavedAttempt {
	var current ads.Current
	// All callers have authenticated the exact ad and canonical endpoint.
	_ = wire.DecMode.Unmarshal(ad, &current)
	return SavedAttempt{request: bytes.Clone(raw),
		endpoint: current.Payload.PeerIntroductionURL, Accepted: accepted, Held: held}
}
