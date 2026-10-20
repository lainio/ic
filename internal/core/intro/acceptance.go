package intro

import (
	"errors"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
)

const acceptancePurpose = "intro-acceptance/v1"

// ErrBadAcceptance reports missing acceptance inputs, a mismatched signer,
// or a signature that does not verify for the offered path's final child.
var ErrBadAcceptance = errors.New("invalid introduction acceptance")

// SignAcceptance signs the complete canonical path, including parent
// signatures, with its final child's matching handle. The signature is detached;
// the path is unchanged. Every returned error is accompanied by a nil signature.
// Key-access and signing errors retain their underlying error chains.
//
// The caller separately proves the path and selects its root and parent.
// Signing establishes neither human consent nor first acceptance, enrolls no
// node, and does not change Known.
func (p Path) SignAcceptance(child key.Handle) (
	acceptance key.Signature, err error,
) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err)

	assert.SLonger(p, 1, ErrBadAcceptance)
	assert.INotNil(child, ErrBadAcceptance)
	public := p.LastEdge().Public()
	assert.SNotEmpty(public, ErrBadAcceptance)
	signerPublic := try.To1(child.CBORPublicKey())
	assert.That(public.Equal(signerPublic), ErrBadAcceptance)

	digest := acceptanceDigest(p)
	signed := try.To1(child.Sign(digest[:]))

	return signed, nil
}

// VerifyAcceptance checks a detached signature over this exact path using only
// its final child's public key. Missing inputs and a false verification result
// return ErrBadAcceptance; underlying helper errors retain their chains.
//
// Like SignAcceptance, it leaves proof, root and parent choice, human consent,
// and enrollment to the caller/protocol. It does not mutate the path or Known,
// and exact copies may verify repeatedly without any one-time or replay policy.
func (p Path) VerifyAcceptance(acceptance key.Signature) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err)

	assert.SLonger(p, 1, ErrBadAcceptance)
	public := p.LastEdge().Public()
	assert.SNotEmpty(public, ErrBadAcceptance)
	assert.SNotEmpty(acceptance, ErrBadAcceptance)

	digest := acceptanceDigest(p)
	assert.That(acceptance.Verify(public, digest[:]), ErrBadAcceptance)

	return nil
}

func acceptanceDigest(p Path) key.Hash {
	return key.HashTagged(acceptancePurpose, p.Bytes())
}
