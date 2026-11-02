package ads

import (
	"bytes"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// ReadEstablishmentAdInTx validates both whole local collections and returns
// their identical, authenticated, unexpired claim. This is local evidence only:
// Bob must check his own current publication when accepting. No remote oracle,
// signer callback, nested transaction, promotion or repair occurs here.
func ReadEstablishmentAdInTx(tx storage.ReadTx, root, subject key.Public,
	now time.Time,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	try.To(validatePublic(root))
	try.To(validatePublic(subject))
	try.To(validateTime(now))
	received := try.To1(readReceivedClaims(tx, root))
	verified := try.To1(readVerifiedClaims(tx, root))
	i, found := claimIndex(received.Entries, subject)
	j, admitted := verifiedIndex(verified.Entries, subject)
	assert.That(found && admitted, ErrNoReceivedClaim)
	ad := received.Entries[i].Ad
	assert.That(
		bytes.Equal(ad, verified.Entries[j].Ad),
		ErrReceivedClaimChanged,
	)
	current := try.To1(decodeCurrent(ad, root, subject))
	assert.That(now.UnixNano() < current.Payload.ExpiresUnixNano,
		ErrInvalidRecord)
	return bytes.Clone(ad), nil
}
