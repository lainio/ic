package pw

import (
	"bytes"
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

const (
	acceptedKey = "local-pw-accepted-v1"
	heldKey     = "local-pw-held-v1"
)

// Private diagnostic causes survive transaction unwinding only. Public actions
// still return the exact ErrEstablishment sentinel. Never log error text.
type establishmentRefusal string

func (e establishmentRefusal) Error() string { return string(e) }
func (establishmentRefusal) Unwrap() error   { return ErrEstablishment }

func establishmentReason(err error) string {
	var refusal establishmentRefusal
	if errors.As(err, &refusal) {
		return string(refusal) // Constructed only from fixed codes below.
	}
	switch {
	case errors.Is(err, ads.ErrNoReceivedClaim):
		return "ad_evidence_missing"
	case errors.Is(err, ads.ErrReceivedClaimChanged):
		return "ad_evidence_changed"
	case errors.Is(err, ads.ErrInvalidRecord):
		return "ad_invalid_or_expired"
	case errors.Is(err, device.ErrInvalidAuthorization):
		return "device_authorization_invalid"
	default:
		return "undetermined"
	}
}

// One immutable history record and an independently removable holding. Both
// reference the exact signed request. The local role is checked against that
// request; there is no Trust, pipe or first-use observation. The existing
// invitation row keeps its v1 format.
type acceptedRecord struct {
	_        struct{} `cbor:",toarray"`
	Version  uint8
	Request  []byte
	Response []byte
}

type heldRecord struct {
	_             struct{} `cbor:",toarray"`
	Version       uint8
	RequestDigest []byte
}

// BobAccept implements IntroTreePWInvitationV1.BobAccept in one Vault.Update.
// Borrow an independently Root/local-bound Vault and installed software signer.
// The caller MUST hold the owner service mutation/signing lock across this call;
// participating Known, policy, publication and signer lifecycle changes use that
// same lock. The Vault orders independent durable writers including revocation.
// External signer changes cannot be made atomic with the Vault by this function.
//
// Authentication and signing precede Update. All durable guards are reread
// inside it, including a fresh server clock. Success means commit completed,
// never permission to send a response: initial delivery must use BobReply too.
func BobAccept(vault *storage.Vault, root, local key.Public, signer key.Handle,
	endpoint string, raw []byte,
) error {
	return bobAccept(vault, root, local, signer, endpoint, raw, time.Now)
}

func bobAccept(vault *storage.Vault, root, local key.Public, signer key.Handle,
	endpoint string, raw []byte, now func() time.Time,
) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(cause error) error {
		glog.V(1).Infof("intro_pw op=establish side=acceptor "+
			"stage=acceptance result=refused reason=%s", establishmentReason(cause))
		return ErrEstablishment
	})

	assert.NotNil(vault, ErrEstablishment)
	root, local, raw = bytes.Clone(root), bytes.Clone(local), bytes.Clone(raw)
	request := try.To1(decodeEstablishment(raw, root, local))
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		try.To1(newRedemption(tx, request.Payload, endpoint, now))
		return nil
	}))
	state := try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	assert.That(state.Authorized,
		establishmentRefusal("device_not_authorized"))
	assert.That(state.Usable, establishmentRefusal("signer_unusable"))
	glog.V(1).Info("intro_pw op=establish side=acceptor " +
		"stage=signer result=usable")
	payload := acceptedPayload(request.Payload, raw)
	digest := key.HashTagged(AcceptedPurpose, try.To1(wire.Marshal(payload)))
	signature := try.To1((localSigner{signer}).Sign(bytes.Clone(digest[:])))
	response := try.To1(wire.Marshal(SignedAccepted{
		Payload: payload, Signature: bytes.Clone(signature),
	}))
	try.To(verifyAccepted(response, payload))
	try.To(vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return commitAcceptance(tx, root, local, endpoint, raw, response, now)
	}))
	glog.V(1).Info("intro_pw op=establish side=acceptor " +
		"stage=acceptance result=committed")
	return nil
}

func commitAcceptance(tx storage.WriteTx, root, local key.Public,
	endpoint string, raw, response []byte, now func() time.Time,
) (err error) {
	defer err2.Handle(&err, nil)

	request := try.To1(decodeEstablishment(raw, root, local))
	payload := acceptedPayload(request.Payload, raw)
	try.To(verifyAccepted(response, payload))
	row := try.To1(newRedemption(tx, request.Payload, endpoint, now))
	row.State = InvitationConsumed
	try.To(tx.Put([]byte(invitationKey), try.To1(wire.Marshal(row))))
	try.To(tx.Put([]byte(acceptedKey), try.To1(wire.Marshal(acceptedRecord{
		Version: 1, Request: raw, Response: response,
	}))))
	return tx.Put([]byte(heldKey), try.To1(wire.Marshal(heldRecord{
		Version: 1, RequestDigest: payload.RequestDigest,
	})))
}

func newRedemption(tx storage.ReadTx, p Establishment, endpoint string,
	now func() time.Time,
) (_ Invitation, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	row, found := try.To2(readInvitation(tx, p.Root, p.Target))
	assert.That(found && row.State == InvitationActive &&
		matchesInvitation(row, p), establishmentRefusal("invitation_incompatible"))
	_, accepted := try.To2(tx.Get([]byte(acceptedKey)))
	_, held := try.To2(tx.Get([]byte(heldKey)))
	_, attempting := try.To2(tx.Get([]byte(attemptKey)))
	assert.That(!accepted && !held && !attempting,
		establishmentRefusal("state_incompatible"))
	timeNow := try.To1(currentEstablishmentGuards(tx, p, endpoint, now))
	assert.That(invitationBeforeExpiry(row, timeNow),
		establishmentRefusal("invitation_expired"))
	return row, nil
}

func matchesInvitation(row Invitation, p Establishment) bool {
	return bytes.Equal(row.Root, p.Root) && bytes.Equal(row.Target, p.Target) &&
		bytes.Equal(row.ID, p.InvitationID) && row.Audience == p.Audience &&
		bytes.Equal(row.Recipient, p.Recipient)
}

func currentEstablishmentGuards(tx storage.ReadTx, p Establishment,
	endpoint string, now func() time.Time,
) (_ time.Time, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	// Validate all Known records even when Bob is the pinned Root.
	ownKnown := try.To1(
		onboarding.IsKnownIntroductionInTx(tx, p.Root, p.Target),
	)
	peerKnown := try.To1(
		onboarding.IsKnownIntroductionInTx(tx, p.Root, p.Requester),
	)
	assert.That(ownKnown || bytes.Equal(p.Root, p.Target),
		establishmentRefusal("own_introduction_not_known"))
	assert.That(peerKnown || bytes.Equal(p.Root, p.Requester),
		establishmentRefusal("peer_not_known"))
	assert.ThatNot(try.To1(policy.IsDeniedInTx(tx, p.Root, p.Target,
		p.Requester)), establishmentRefusal("policy_deny"))
	assert.That(try.To1(device.IsAuthorizedLocalInTx(tx, p.Root, p.Target)),
		establishmentRefusal("device_not_authorized"))
	timeNow := now()
	current, found := try.To2(ads.ReadCurrentLocalInTx(tx, p.Root, p.Target,
		timeNow))
	assert.That(endpoint != "" && found &&
		current.Payload.PeerIntroductionURL == endpoint &&
		bytes.Equal(try.To1(wire.Marshal(current)), p.Ad),
		establishmentRefusal("ad_unavailable_or_mismatched"))
	return timeNow, nil
}
