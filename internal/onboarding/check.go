package onboarding

import (
	"bytes"
	"encoding/base64"
	"errors"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/key"
)

// MaxIntroductionBytes bounds the development JSON transfer document.
const MaxIntroductionBytes = 128 * 1024

var ErrInvalidIntroduction = errors.New("invalid introduction")

// CheckIntroduction applies the owner-import admission policy without storage,
// a signer, or peer I/O. The subject is returned only after proof and acceptance
// verification under the independently configured Root. This does not promote
// evidence into Known or establish global parent uniqueness.
func CheckIntroduction(proposal []byte, acceptance key.Signature,
	expectedRoot key.Public,
) (_ key.Public, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.That(len(proposal) <= MaxIntroductionBytes &&
		len(acceptance) <= MaxIntroductionBytes, ErrInvalidIntroduction)
	const envelopeBytes = len(`{"version":1,"proposal":"","acceptance":""}`)
	assert.That(envelopeBytes+base64.StdEncoding.EncodedLen(len(proposal))+
		base64.StdEncoding.EncodedLen(len(acceptance)) <= MaxIntroductionBytes,
		ErrInvalidIntroduction)

	path := try.To1(intro.ParsePath(proposal))
	assert.SLonger(path, 1, ErrInvalidIntroduction)
	assert.That(PublicIntroduction(path), ErrInvalidIntroduction)
	for _, edge := range path {
		assert.That(edge.Body.Options.BackupKeyIndex == 0 &&
			!edge.Body.Options.Rotation, ErrInvalidIntroduction)
	}
	try.To(path.ProveFromRoot(expectedRoot))
	try.To(path.VerifyAcceptance(acceptance))
	return bytes.Clone(path.LeafPubKey()), nil
}

// PublicIntroduction rejects handle IDs without stripping signed fields.
func PublicIntroduction(proposal intro.Path) bool {
	for _, edge := range proposal {
		if len(edge.Body.Child.ID) != 0 {
			return false
		}
	}
	return true
}
