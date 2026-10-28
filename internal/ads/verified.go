package ads

import (
	"bytes"
	"errors"
	"slices"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const (
	verifiedClaimsKey = "verified-ad-claims-v1"
	maxVerifiedClaims = 32
	maxVerifiedBytes  = 16 + maxVerifiedClaims*(maxPublicBytes+maxRecordBytes+16)
)

var (
	ErrInvalidVerifiedClaims  = errors.New("invalid stored verified ad claims")
	ErrVerifiedClaimsFull     = errors.New("verified ad claim collection full")
	errVerifiedClaimUnchanged = errors.New("verified ad claim unchanged")
)

// Like ReceivedAd, this is one bounded, sorted, versioned root record. A table
// cannot hide extra subject/slot records in unenumerable child namespaces. Its
// distinct storage name is the authenticated local provenance of verification;
// only VerifyReceivedRemote writes it. It retains exact ad identity, not a live
// flag. It is not a portable proof or a grant restored from untrusted snapshots.
type verifiedClaims struct {
	_       struct{} `cbor:",toarray"`
	Version uint8
	Entries []verifiedClaim
}

type verifiedClaim struct {
	_       struct{} `cbor:",toarray"`
	Subject key.Public
	Ad      []byte
}

// ReadVerifiedClaim returns owned historical ad bytes, never a claim of current
// reachability. It authenticates every stored subject, original signature and
// binding, even after expiry; reads neither delete nor repair records. The Vault
// must be independently bound to the reader/Root by the caller. Absence returns
// nil, false, nil. Corruption returns no partial result. No encryption is used.
// Future CreatePW MUST freshly check online currentness, expiry, Known, devices
// and mutual acceptance; this historical evidence alone grants no authority.
func ReadVerifiedClaim(vault *storage.Vault, expectedRoot, subject key.Public) (
	_ []byte, _ bool, err error,
) {
	defer err2.Handle(&err, nil)

	if vault == nil || validatePublic(expectedRoot) != nil || validatePublic(subject) != nil {
		return nil, false, ErrInvalidInput
	}
	expectedRoot, subject = bytes.Clone(expectedRoot), bytes.Clone(subject)
	var result []byte
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		claims := try.To1(readVerifiedClaims(tx, expectedRoot))
		if i, found := verifiedIndex(claims.Entries, subject); found {
			result = bytes.Clone(claims.Entries[i].Ad)
		}
		return nil
	}))
	return result, result != nil, nil
}

func verifiedIndex(entries []verifiedClaim, subject key.Public) (int, bool) {
	return slices.BinarySearchFunc(entries, subject, func(entry verifiedClaim, subject key.Public) int {
		return bytes.Compare(entry.Subject, subject)
	})
}

func readVerifiedClaims(tx storage.ReadTx, root key.Public) (_ verifiedClaims, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	record, found := try.To2(tx.Get([]byte(verifiedClaimsKey)))
	if !found {
		return verifiedClaims{Version: 1}, nil
	}
	assert.That(len(record) > 0 && len(record) <= maxVerifiedBytes, ErrInvalidVerifiedClaims)
	var claims verifiedClaims
	assert.That(wire.UnmarshalCanonical(&claims, record) == nil, ErrInvalidVerifiedClaims)
	assert.That(claims.Version == 1 && len(claims.Entries) > 0 &&
		len(claims.Entries) <= maxVerifiedClaims, ErrInvalidVerifiedClaims)
	for i, entry := range claims.Entries {
		assert.That(i == 0 || bytes.Compare(claims.Entries[i-1].Subject, entry.Subject) < 0,
			ErrInvalidVerifiedClaims)
		_, checkErr := decodeCurrent(entry.Ad, root, entry.Subject)
		assert.That(checkErr == nil, ErrInvalidVerifiedClaims)
	}
	return claims, nil
}

// Called only after the online proof and final transactional receipt/Known guard.
func replaceVerifiedClaim(tx storage.WriteTx, root, subject key.Public, ad []byte) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	claims := try.To1(readVerifiedClaims(tx, root))
	i, found := verifiedIndex(claims.Entries, subject)
	if found && bytes.Equal(claims.Entries[i].Ad, ad) {
		return errVerifiedClaimUnchanged // Roll back bookkeeping too; no seal.
	}
	entry := verifiedClaim{Subject: subject, Ad: ad}
	if found {
		claims.Entries[i] = entry
	} else {
		assert.That(len(claims.Entries) < maxVerifiedClaims, ErrVerifiedClaimsFull)
		claims.Entries = slices.Insert(claims.Entries, i, entry)
	}
	return tx.Put([]byte(verifiedClaimsKey), try.To1(wire.Marshal(claims)))
}
