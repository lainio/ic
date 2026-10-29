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

const acceptancePurpose = "pw-local-acceptance/v1"

var ErrInvalidProof = errors.New("invalid local acceptance proof signature")

// Declaration order is the version-1 canonical CBOR array. This statement is
// neither a stored record nor a modeled CreatePW transition. Full public key
// bytes bind the independently pinned Root, acceptor and intended peer.
type acceptancePayload struct {
	_         struct{} `cbor:",toarray"`
	Version   uint8
	Root      key.Public
	Acceptor  key.Public
	Peer      key.Public
	Challenge []byte
}

// ProveLocalAcceptance attests a checked, momentary local acceptability
// decision for exactly one peer and one caller-generated challenge. It reuses
// CheckLocalAcceptor's Known/Deny guards and authorized, usable software signer
// probe. That operational probe is additional to V19 CanAccept, not identical
// to it. The discarded usability probe precedes one acceptance signature.
//
// The caller borrows an open Vault independently bound to its pinned root/local
// configuration and supplies its installed local signer. A Vault pointer alone
// authenticates no binding. Inputs are copied before callbacks; callers must
// not mutate them concurrently with this call. No Vault transaction spans a
// signer callback. The enclosing service MUST serialize mutable Known, Deny,
// device policy and signer lifecycle across preflight and acceptance signing.
// There is no global atomicity or revocation guarantee: subsequent denial,
// device loss or policy changes can invalidate acceptance immediately.
//
// The future requester MUST generate a fresh 32-byte challenge with crypto/rand
// for each exchange. This function neither generates nor caches challenges;
// length alone, or a challenge from an unauthenticated source, proves no
// freshness. Reusing a challenge provides no replay resistance. A future peer
// boundary must independently authenticate requester key possession and bind
// the proof to a live transcript and simultaneously verified current ad.
//
// This is only a protocol observation: no writes, seals, network I/O, Known
// promotion, Allow, cached eligibility, or changes to PWHeld, PWOpen,
// SeenPeerEpoch, SeenPeerDevice, Trust or VerifiedAd occur. MayAttemptVia and
// two-sided CreatePW remain separate guards and a future atomic commitment.
// Errors return no partial signature; success returns an owned signature copy.
func ProveLocalAcceptance(
	vault *storage.Vault,
	root, local, peer key.Public,
	signer key.Handle,
	challenge []byte,
) (_ key.Signature, err error) {
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()

	assert.NotNil(vault, ErrInvalidInput)
	try.To(validateAcceptanceInputs(root, local, peer, challenge))
	root, local, peer = bytes.Clone(root), bytes.Clone(local), bytes.Clone(peer)
	challenge = bytes.Clone(challenge)
	try.To(CheckLocalAcceptor(vault, root, local, peer, signer))

	digest := try.To1(localAcceptanceDigest(root, local, peer, challenge))
	signature := key.Signature(try.To1(
		(localSigner{signer}).Sign(bytes.Clone(digest[:])),
	))
	assert.That(len(signature) > 0 && len(signature) <= 72, ErrInvalidProof)
	signature = bytes.Clone(signature)
	assert.That(signature.Verify(local, digest[:]), ErrInvalidProof)
	return signature, nil
}

// VerifyLocalAcceptanceProof purely authenticates the expected acceptor's
// endorsement of exactly this Root, peer and challenge. Expected identities
// must be independently supplied, never extracted from a proof or peer claim.
// A key holder can sign without honestly checking policy; verification alone
// proves neither continuing acceptance, human consent, requester key control,
// current device usability, reachable current advertisement, trust, mutual PW,
// transport authentication nor an established relationship.
//
// No Vault, signer, policy, ad, clock, nonce cache or remote I/O is consulted,
// and no state is created. This MUST NOT authorize CreatePW or stand alone as
// evidence of current remote consent. Freshness requires an unpredictable
// receiver-generated nonce in a live exchange and final live guards.
func VerifyLocalAcceptanceProof(
	root, acceptor, peer key.Public,
	challenge []byte,
	proof key.Signature,
) (err error) {
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()

	try.To(validateAcceptanceInputs(root, acceptor, peer, challenge))
	assert.That(len(proof) > 0 && len(proof) <= 72, ErrInvalidProof)
	digest := try.To1(localAcceptanceDigest(root, acceptor, peer, challenge))
	assert.That(proof.Verify(acceptor, digest[:]), ErrInvalidProof)
	return nil
}

func validateAcceptanceInputs(root, acceptor, peer key.Public,
	challenge []byte,
) (err error) {
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()

	assert.That(len(challenge) == 32, ErrInvalidInput)
	assert.That(validPublic(root), ErrInvalidInput)
	assert.That(validPublic(acceptor), ErrInvalidInput)
	assert.That(validPublic(peer), ErrInvalidInput)
	assert.ThatNot(bytes.Equal(acceptor, peer), ErrInvalidInput)
	return nil
}

func localAcceptanceDigest(root, acceptor, peer key.Public,
	challenge []byte,
) (_ key.Hash, err error) {
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()

	payload, encodeErr := wire.Marshal(acceptancePayload{
		Version: 1, Root: root, Acceptor: acceptor, Peer: peer,
		Challenge: challenge,
	})
	// No encoder/provider diagnostics cross this fixed-sentinel boundary.
	assert.NoError(encodeErr, ErrInvalidInput)
	return key.HashTagged(acceptancePurpose, payload), nil
}
