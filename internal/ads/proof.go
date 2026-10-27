package ads

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const currentProofPurpose = "ad-currentness-proof/v1"

var (
	ErrNotCurrent   = errors.New("ad does not match the current local publication and endpoint")
	ErrInvalidProof = errors.New("invalid current ad proof signature")
)

// currentProofPayload is a deterministic CBOR array in declaration order, never
// a stored record. Subject is the full publisher/device key (Device == Node in
// v1); AdDigest covers the exact canonical Current bytes, including its original
// signature. The purpose tag and version separate this from other signatures.
type currentProofPayload struct {
	_         struct{} `cbor:",toarray"`
	Version   uint8
	Root      key.Public
	Subject   key.Public
	AdDigest  []byte
	Challenge []byte
}

// ProveCurrentLocal signs a challenge only for the exact authenticated current
// publication in the publisher's own Vault. The enclosing service must supply
// the independently configured Root/local keys used to open that Vault and its
// actual bound peer introduction URL, never identities or a URL chosen by a
// request. Vault itself exposes no identity binding. Own Known (or Root's
// explicit self-Known convention) and fresh authorized signer usability are
// required; InspectLocal performs a separate local diagnostic signature first.
//
// The caller must serialize publication, Known/device/configuration mutations,
// signer lifecycle, and proof callbacks. No Vault transaction spans randomness
// or signing. A final read rejects replacement during a signer callback, but
// replacement or device loss can still occur after that read/return. now must
// be trustworthy; there is no clock rollback protection or perpetual usability.
//
// The future receiver must generate its 32-byte challenge with crypto/rand.
// Length checking cannot establish unpredictability; no nonce is generated for
// it or cached here. This function writes/seals nothing, performs no network
// I/O, and implements no V19 transition, bootstrap, renewal, or promotion.
// Errors return no partial signature; success returns caller-owned bytes.
func ProveCurrentLocal(vault *storage.Vault, expectedRoot, expectedLocal key.Public,
	signer key.Handle, boundPeerIntroURL string, expectedAdCBOR, challenge []byte,
	now time.Time,
) (_ key.Signature, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.That(vault != nil, ErrInvalidInput)
	try.To(validateProofAd(expectedRoot, expectedLocal, expectedAdCBOR, challenge, now))
	expectedRoot, expectedLocal = bytes.Clone(expectedRoot), bytes.Clone(expectedLocal)
	expectedAdCBOR, challenge = bytes.Clone(expectedAdCBOR), bytes.Clone(challenge)
	try.To(requireCurrentLocal(vault, expectedRoot, expectedLocal,
		boundPeerIntroURL, expectedAdCBOR, now))
	if !bytes.Equal(expectedRoot, expectedLocal) {
		known := try.To1(onboarding.ListKnownIntroductions(vault, expectedRoot))
		found := false
		for _, subject := range known {
			found = found || bytes.Equal(subject, expectedLocal)
		}
		assert.That(found, ErrNotKnown)
	}
	// InspectLocal also rejects nil/typed-nil and foreign signers safely.
	state := try.To1(device.InspectLocal(vault, expectedRoot, expectedLocal, signer))
	assert.That(state.Authorized && state.Usable, ErrUnusable)

	digest := try.To1(currentProofDigest(expectedRoot, expectedLocal, expectedAdCBOR, challenge))
	signature := key.Signature(try.To1(signer.Sign(bytes.Clone(digest[:]))))
	assert.That(len(signature) > 0 && len(signature) <= 72, ErrInvalidProof)
	signature = bytes.Clone(signature)
	assert.That(signature.Verify(expectedLocal, digest[:]), ErrInvalidProof)
	try.To(requireCurrentLocal(vault, expectedRoot, expectedLocal,
		boundPeerIntroURL, expectedAdCBOR, now))
	return signature, nil
}

// VerifyCurrentProof authenticates the original canonical v1 ad and the proof
// against independently supplied Root/subject keys, exact ad bytes, nonce, and
// expiry. A future call site must obtain these expected identities from its own
// configuration and Known evidence, never from the ad. This is a pure check:
// no storage, I/O, or VerifiedAd, Known, PW, trust, or peer-view state is created.
//
// Success alone establishes neither source currentness/authorization nor Known,
// and MUST NOT serve as a standalone V19 VerifyAd implementation. Only a future
// online challenge with a fresh unpredictable receiver nonce tied to the exact
// previously received claim can supply evidence of current signer control. That
// owner workflow must check Known, freshness, and exact currentness before any
// durable VerifiedAd transition. A signed unexpired ad may already be replaced.
//
// A malicious key holder can sign without honestly reading local storage. This
// signature proves neither global AuthenticAds membership, authenticated remote
// transport, endpoint reachability, nor continuing device usability. It adds no
// ad history, rotation, epochs beyond v1's slot 1/epoch 0, or clock guarantees.
func VerifyCurrentProof(expectedRoot, expectedSubject key.Public,
	adCBOR, challenge []byte, proof key.Signature, now time.Time,
) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.That(len(proof) > 0 && len(proof) <= 72, ErrInvalidProof)
	try.To(validateProofAd(expectedRoot, expectedSubject, adCBOR, challenge, now))
	digest := try.To1(currentProofDigest(expectedRoot, expectedSubject, adCBOR, challenge))
	assert.That(proof.Verify(expectedSubject, digest[:]), ErrInvalidProof)
	return nil
}

func currentProofDigest(root, subject key.Public, adCBOR, challenge []byte) (_ key.Hash, err error) {
	defer err2.Handle(&err, nil)

	adDigest := sha256.Sum256(adCBOR)
	payload := currentProofPayload{Version: 1, Root: root, Subject: subject,
		AdDigest: adDigest[:], Challenge: challenge}
	return key.HashTagged(currentProofPurpose, try.To1(wire.Marshal(payload))), nil
}

func validateProofAd(root, subject key.Public, adCBOR, challenge []byte, now time.Time) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.That(len(challenge) == 32, ErrInvalidInput)
	try.To(validateTime(now))
	// Quiet bounded admission prevents hostile CBOR/key diagnostics from being
	// reflected through err2 tracing. Authentication follows shape admission.
	assert.That(ValidateClaim(root, subject, adCBOR) == nil, ErrInvalidInput)
	ad := try.To1(decodeCurrent(adCBOR, root, subject))
	assert.That(now.UnixNano() < ad.Payload.ExpiresUnixNano, ErrInvalidRecord)
	return nil
}

func requireCurrentLocal(vault *storage.Vault, root, local key.Public,
	boundPeerIntroURL string, adCBOR []byte, now time.Time,
) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	current, found := try.To2(ReadCurrentLocal(vault, root, local, now))
	assert.That(found && current.Payload.PeerIntroductionURL == boundPeerIntroURL, ErrNotCurrent)
	assert.That(bytes.Equal(try.To1(wire.Marshal(current)), adCBOR), ErrNotCurrent)
	return nil
}
