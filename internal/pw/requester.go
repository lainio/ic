package pw

import (
	"bytes"
	"crypto/rand"
	"errors"
	"time"

	"github.com/golang/glog"
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

// One slot across wire versions. The historical key name does not select a
// decoder: v1 and v2 readers each require their own exact version and layout.
// Keeping this slot also prevents the unchanged v1 Bob path from overwriting
// a requester attempt. No migration, second slot or reinterpretation is allowed.
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
	defer err2.Handle(&err, func(cause error) error {
		glog.V(1).Infof("intro_pw op=redeem side=requester "+
			"stage=attempt result=refused reason=%s", establishmentReason(cause))
		return ErrEstablishment
	})

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
				Recipient: p.Recipient}, request.Payload),
				establishmentRefusal("attempt_incompatible"))
		} else {
			p.Ad = try.To1(requesterGuards(tx, p, now))
		}
		return nil
	}
	try.To(vault.View(read)) // Reject denied/conflicting state before signing.
	state := try.To1(device.InspectLocal(vault, p.Root, p.Requester,
		localSigner{signer}))
	assert.That(state.Authorized,
		establishmentRefusal("device_not_authorized"))
	assert.That(state.Usable, establishmentRefusal("signer_unusable"))
	glog.V(1).Info("intro_pw op=redeem side=requester stage=signer result=usable")
	try.To(vault.View(read)) // Recheck after the external signer probe.
	if saved.request != nil {
		glog.V(1).Info("intro_pw op=redeem side=requester " +
			"stage=attempt result=retained")
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
	glog.V(1).Info("intro_pw op=redeem side=requester " +
		"stage=attempt result=committed")
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
	defer err2.Handle(&err, func(cause error) error {
		glog.V(1).Infof("intro_pw op=redeem side=requester "+
			"stage=acceptance result=refused reason=%s", establishmentReason(cause))
		return ErrEstablishment
	})

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
	assert.That(state.Authorized,
		establishmentRefusal("device_not_authorized"))
	assert.That(state.Usable, establishmentRefusal("signer_unusable"))
	if saved.Accepted {
		try.To(vault.View(read))
		glog.V(1).Info("intro_pw op=redeem side=requester " +
			"stage=acceptance result=retained")
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
		glog.V(1).Info("intro_pw op=redeem side=requester " +
			"stage=acceptance result=retained")
		return saved.Held, nil
	}
	try.To(updateErr)
	glog.V(1).Info("intro_pw op=redeem side=requester " +
		"stage=acceptance result=committed")
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
		assert.That(!accepted && !held, establishmentRefusal("state_incompatible"))
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
	assert.That(own || bytes.Equal(p.Root, p.Requester),
		establishmentRefusal("own_introduction_not_known"))
	assert.That(peer || bytes.Equal(p.Root, p.Target),
		establishmentRefusal("peer_not_known"))
	assert.ThatNot(try.To1(policy.IsDeniedInTx(tx, p.Root, p.Requester,
		p.Target)), establishmentRefusal("policy_deny"))
	assert.That(try.To1(device.IsAuthorizedLocalInTx(tx, p.Root, p.Requester)),
		establishmentRefusal("device_not_authorized"))
	ad := try.To1(ads.ReadEstablishmentAdInTx(tx, p.Root, p.Target, now()))
	assert.That(p.Ad == nil || bytes.Equal(p.Ad, ad),
		establishmentRefusal("ad_evidence_changed"))
	return ad, nil
}

func attemptSnapshot(raw, ad []byte, accepted, held bool) SavedAttempt {
	var current ads.Current
	// All callers have authenticated the exact ad and canonical endpoint.
	_ = wire.DecMode.Unmarshal(ad, &current)
	return SavedAttempt{request: bytes.Clone(raw),
		endpoint: current.Payload.PeerIntroductionURL, Accepted: accepted, Held: held}
}

// SavedAttemptV2 owns only an exact saved request, not acceptance or holding.
// Its separate type cannot be passed to the live v1 SendEstablish path.
type SavedAttemptV2 struct {
	request []byte
}

// SaveAttemptV2 prepares the contact-bound request in an independently
// Root/local-bound Vault. The internal caller MUST supply requesterContact
// from its own trusted, pinned service configuration, never from HTTP input,
// the target ad, UI/demo text or another Vault. Target contact and ad come only
// from this Vault's previously authenticated and verified Bob evidence.
//
// Hold the owner mutation/signer lock, including configuration changes, across
// this call. Sign outside transactions and revalidate durable guards at commit.
// Retained attempts are read, never re-signed or rebound. A new runtime port
// conflicts; disposable demos need fresh relationship state for a fresh port
// unless an explicit fixed contact is configured. No reachability is promised.
// This API does not enable v2 acceptance or change the live v1 owner route.
func SaveAttemptV2(vault *storage.Vault, root, local, target key.Public,
	signer key.Handle, invitationID []byte, audience, requesterContact string,
) (SavedAttemptV2, error) {
	return saveAttemptV2(vault, root, local, target, signer, invitationID,
		audience, requesterContact, time.Now)
}

func saveAttemptV2(vault *storage.Vault, root, local, target key.Public,
	signer key.Handle, invitationID []byte, audience, requesterContact string,
	now func() time.Time,
) (_ SavedAttemptV2, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(cause error) error {
		glog.V(1).Infof("intro_pw op=prepare_v2 side=requester "+
			"stage=attempt result=refused reason=%s", establishmentReason(cause))
		return ErrEstablishment
	})

	assert.That(vault != nil && validPublic(root) && validPublic(local) &&
		validPublic(target) && !bytes.Equal(local, target) &&
		len(invitationID) == 32 && canonicalServiceContact(requesterContact) &&
		(audience == InvitationAny || audience == InvitationDirected),
		ErrEstablishment)
	p := EstablishmentV2{Version: 2, Root: bytes.Clone(root),
		Requester: bytes.Clone(local), Target: bytes.Clone(target),
		InvitationID: bytes.Clone(invitationID), Audience: audience,
		Device: bytes.Clone(local), RequesterContact: requesterContact}
	if audience == InvitationDirected {
		p.Recipient = bytes.Clone(local)
	}

	var saved []byte
	read := func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		saved = try.To1(readAttemptV2(tx, p, now))
		if saved == nil {
			p.Ad = try.To1(requesterGuards(tx, p.guardBinding(), now))
			p.TargetContact = try.To1(serviceContactFromAd(p.Ad))
		}
		return nil
	}
	try.To(vault.View(read))
	state := try.To1(device.InspectLocal(vault, p.Root, p.Requester,
		localSigner{signer}))
	assert.That(state.Authorized,
		establishmentRefusal("device_not_authorized"))
	assert.That(state.Usable, establishmentRefusal("signer_unusable"))
	try.To(vault.View(read))
	if saved != nil {
		return SavedAttemptV2{request: saved}, nil
	}

	p.AttemptID = make([]byte, 32)
	try.To1(rand.Read(p.AttemptID))
	digest := key.HashTagged(EstablishPurposeV2, try.To1(wire.Marshal(p)))
	signature := try.To1((localSigner{signer}).Sign(bytes.Clone(digest[:])))
	raw := try.To1(wire.Marshal(SignedEstablishmentV2{
		Payload: p, Signature: bytes.Clone(signature),
	}))
	try.To1(decodeEstablishmentV2(raw, p.Root, p.Target))
	try.To(vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return commitAttemptV2(tx, p.Root, p.Requester, requesterContact, raw, now)
	}))
	return SavedAttemptV2{request: bytes.Clone(raw)}, nil
}

// This increment understands only unaccepted v2 attempts. Any v1 attempt or
// accepted/held evidence fails closed, including a v1 history after deletion.
func readAttemptV2(tx storage.ReadTx, expected EstablishmentV2,
	now func() time.Time,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)
	raw, found := try.To2(tx.Get([]byte(attemptKey)))
	_, accepted := try.To2(tx.Get([]byte(acceptedKey)))
	_, held := try.To2(tx.Get([]byte(heldKey)))
	assert.That(!accepted && !held, establishmentRefusal("state_incompatible"))
	if !found {
		return nil, nil
	}
	request := try.To1(decodeEstablishmentV2(raw, expected.Root, expected.Target))
	p := request.Payload
	assert.That(bytes.Equal(p.Requester, expected.Requester) &&
		p.RequesterContact == expected.RequesterContact &&
		matchesInvitation(Invitation{Root: expected.Root, Target: expected.Target,
			ID: expected.InvitationID, Audience: expected.Audience,
			Recipient: expected.Recipient}, p.guardBinding()),
		establishmentRefusal("attempt_incompatible"))
	assert.That(expected.Ad == nil || bytes.Equal(p.Ad, expected.Ad),
		establishmentRefusal("ad_evidence_changed"))
	try.To1(requesterGuards(tx, p.guardBinding(), now))
	return bytes.Clone(raw), nil
}

func commitAttemptV2(tx storage.WriteTx, root, local key.Public,
	requesterContact string, raw []byte, now func() time.Time,
) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)
	var request SignedEstablishmentV2
	try.To(decodeEstablishmentCanonical(raw, &request))
	request = try.To1(decodeEstablishmentV2(raw, root, request.Payload.Target))
	p := request.Payload
	assert.That(bytes.Equal(p.Requester, local) &&
		p.RequesterContact == requesterContact, ErrEstablishment)
	prior := try.To1(readAttemptV2(tx, p, now))
	assert.That(prior == nil, establishmentRefusal("attempt_incompatible"))
	try.To1(requesterGuards(tx, p.guardBinding(), now))
	return tx.Put([]byte(attemptKey), raw)
}
