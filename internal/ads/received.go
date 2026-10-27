package ads

import (
	"bytes"
	"errors"
	"slices"

	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const (
	receivedClaimsKey = "received-ad-claims-v1"
	maxReceivedClaims = 32
	maxReceivedBytes  = 16 + maxReceivedClaims*(maxPublicBytes+maxRecordBytes+16)
)

var (
	ErrInvalidClaim           = errors.New("invalid received ad claim input")
	ErrInvalidReceivedClaims  = errors.New("invalid stored received ad claims")
	ErrReceivedClaimsFull     = errors.New("received ad claim collection full")
	errReceivedClaimUnchanged = errors.New("received ad claim unchanged")
)

// ValidateClaim checks only the canonical v1 shape and its binding to an
// independently supplied Root and subject. It performs no storage, signature
// authentication, expiry, Known, device, or currentness check. ReceiveClaim
// repeats this admission check before writing; this helper permits composites
// to reject malformed claims before committing other received evidence.
func ValidateClaim(expectedRoot, subject key.Public, canonicalAd []byte) error {
	if len(canonicalAd) == 0 || len(canonicalAd) > maxRecordBytes ||
		len(expectedRoot) > maxPublicBytes || len(subject) > maxPublicBytes {
		return ErrInvalidClaim
	}
	// Discard raw CBOR diagnostics (which can contain hostile map keys)
	// before the existing canonical decoder's err2 tracing can see them.
	var current Current
	if wire.DecMode.Unmarshal(canonicalAd, &current) != nil {
		return ErrInvalidClaim
	}
	for _, public := range []key.Public{expectedRoot, subject} {
		var decoded webauthncose.EC2PublicKeyData
		if wire.DecMode.Unmarshal(public, &decoded) != nil {
			return ErrInvalidClaim
		}
	}
	if _, err := decodeAdShape(canonicalAd, expectedRoot, subject); err != nil {
		return ErrInvalidClaim
	}
	return nil
}

// This private versioned record is a bounded table indexed by the complete
// subject key, in strict byte order. Each subject has only slot 1. The table is
// one root record, not a child namespace: ReadNS cannot enumerate children, so
// a nested layout could silently overlook stray namespaces. Get rejects a child
// occupying this record's name; canonical arrays reject extra fields/slots.
// Every update validates the entire table before replacing its single seal.
type receivedClaims struct {
	_       struct{} `cbor:",toarray"`
	Version uint8
	Entries []receivedClaim
}

type receivedClaim struct {
	_       struct{} `cbor:",toarray"`
	Subject key.Public
	Ad      []byte
}

// ReceiveClaim projects V19 ReceiveAdClaim onto development slot 1, epoch 0.
// It borrows an open Vault independently bound to its node/Root by the caller.
// expectedRoot and subject must be independent of the untrusted canonicalAd,
// which is the inner Current CBOR, not the peer HTTP envelope.
//
// Admission is structural only: forged signatures and expired claims may be
// stored. There is no authentication, currentness/freshness assertion, Known or
// device check, signing, or I/O to peers. Only ReceivedAd changes; this is neither
// ReadAd (no introduction transfer) nor VerifyAd and cannot authorize a PW.
// A different claim replaces the previous one regardless of expiry. Exact byte
// retries abort without Put, encryption use, or backend bookkeeping changes.
// Inputs are copied; changed is true only after a successful commit.
func ReceiveClaim(vault *storage.Vault, expectedRoot, subject key.Public,
	canonicalAd []byte,
) (_ bool, err error) {
	defer err2.Handle(&err, nil)

	if vault == nil || len(canonicalAd) == 0 || len(canonicalAd) > maxRecordBytes ||
		len(expectedRoot) > maxPublicBytes || len(subject) > maxPublicBytes {
		return false, ErrInvalidClaim
	}
	expectedRoot, subject = bytes.Clone(expectedRoot), bytes.Clone(subject)
	canonicalAd = bytes.Clone(canonicalAd)
	if err := ValidateClaim(expectedRoot, subject, canonicalAd); err != nil {
		return false, err
	}
	updateErr := vault.Update(func(tx storage.WriteTx) error {
		return replaceReceivedClaim(tx, expectedRoot, subject, canonicalAd)
	})
	if updateErr == errReceivedClaimUnchanged {
		return false, nil
	}
	try.To(updateErr)
	return true, nil
}

// ReadReceivedClaim returns an owned copy of untrusted inner ad bytes. Absence
// is nil, false, nil; corruption returns no partial result. Every stored binding
// is checked, without signature authentication, expiry deletion, or promotion.
// Reads require no encryption allowance and never modify the database.
func ReadReceivedClaim(vault *storage.Vault, expectedRoot, subject key.Public) (
	_ []byte, _ bool, err error,
) {
	defer err2.Handle(&err, nil)

	if vault == nil || validatePublic(expectedRoot) != nil || validatePublic(subject) != nil {
		return nil, false, ErrInvalidClaim
	}
	expectedRoot, subject = bytes.Clone(expectedRoot), bytes.Clone(subject)
	var result []byte
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		claims := try.To1(readReceivedClaims(tx, expectedRoot))
		if i, found := claimIndex(claims.Entries, subject); found {
			result = bytes.Clone(claims.Entries[i].Ad)
		}
		return nil
	}))
	return result, result != nil, nil
}

// The caller has admitted and copied the new claim before opening the Update.
func replaceReceivedClaim(tx storage.WriteTx, root, subject key.Public,
	canonicalAd []byte,
) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	claims := try.To1(readReceivedClaims(tx, root))
	i, found := claimIndex(claims.Entries, subject)
	if found && bytes.Equal(claims.Entries[i].Ad, canonicalAd) {
		return errReceivedClaimUnchanged
	}
	entry := receivedClaim{Subject: subject, Ad: canonicalAd}
	if found {
		claims.Entries[i] = entry
	} else {
		assert.That(len(claims.Entries) < maxReceivedClaims, ErrReceivedClaimsFull)
		claims.Entries = slices.Insert(claims.Entries, i, entry)
	}
	return tx.Put([]byte(receivedClaimsKey), try.To1(wire.Marshal(claims)))
}

func claimIndex(entries []receivedClaim, subject key.Public) (int, bool) {
	return slices.BinarySearchFunc(entries, subject, func(entry receivedClaim, subject key.Public) int {
		return bytes.Compare(entry.Subject, subject)
	})
}

func readReceivedClaims(tx storage.ReadTx, root key.Public) (_ receivedClaims, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	record, found := try.To2(tx.Get([]byte(receivedClaimsKey)))
	if !found {
		return receivedClaims{Version: 1}, nil
	}
	assert.That(len(record) > 0 && len(record) <= maxReceivedBytes, ErrInvalidReceivedClaims)
	var claims receivedClaims
	assert.That(wire.UnmarshalCanonical(&claims, record) == nil, ErrInvalidReceivedClaims)
	assert.That(claims.Version == 1 && len(claims.Entries) > 0 &&
		len(claims.Entries) <= maxReceivedClaims, ErrInvalidReceivedClaims)
	for i, entry := range claims.Entries {
		assert.That(i == 0 || bytes.Compare(claims.Entries[i-1].Subject, entry.Subject) < 0,
			ErrInvalidReceivedClaims)
		_, checkErr := decodeAdShape(entry.Ad, root, entry.Subject)
		assert.That(checkErr == nil, ErrInvalidReceivedClaims)
	}
	return claims, nil
}
