package ads

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

var (
	ErrSubjectNotKnown      = errors.New("received ad subject is not Known-introduced")
	ErrNoReceivedClaim      = errors.New("no received ad claim")
	ErrReceivedClaimChanged = errors.New("received ad changed during verification")
	ErrRemoteProof          = errors.New("remote ad proof failed")
)

// VerifyReceivedRemote performs one explicit receiver-side online challenge for
// an already received ad. The Vault, Root, reader and subject must be configured
// independently of the ad; the caller binds the Vault to that reader and Root.
// The caller MUST serialize configuration, Known/Received evidence mutations
// and verification across this whole operation (the future owner mutation lock).
// Final transactional validation also rejects a replaced receipt or invalid Known
// evidence. No transaction spans network I/O or a signing/verification callback;
// transactional evidence checks use only local, pure signature verification.
//
// This is a scoped approximation of V19 VerifyAd for slot 1, epoch 0, Device ==
// subject. The existing publisher proves currentness and authorized signer
// control at the exchange. Asynchronous races and malicious key holders cannot
// be ruled out: Go has no global AuthenticAds/CurrentAd oracle. This is NOT a
// full distributed refinement of V19's instantaneous currentness predicate.
//
// Only a historical VerifiedAd snapshot changes. It is never a permanent
// HasVerifiedCurrentAd or CreatePW grant. Future CreatePW MUST freshly check
// online currentness, expiry, Known, devices and mutual acceptance. No receipt,
// introduction, device, PW or trust state is promoted or changed here.
//
// Every invocation uses a fresh random nonce, even an exact-ad retry. A successful
// retry returns false without writing/sealing. Errors return false and never
// repair/erase history. Cancellation or lost acknowledgement can follow a commit;
// callers must inspect/retry explicitly, never assume an error erased evidence.
func VerifyReceivedRemote(ctx context.Context, vault *storage.Vault,
	expectedRoot, expectedLocal, subject key.Public,
) (_ bool, err error) {
	defer err2.Handle(&err, nil)

	if ctx == nil || vault == nil || validatePublic(expectedRoot) != nil ||
		validatePublic(expectedLocal) != nil || validatePublic(subject) != nil ||
		bytes.Equal(expectedLocal, subject) {
		return false, ErrInvalidInput
	}
	expectedRoot, subject = bytes.Clone(expectedRoot), bytes.Clone(subject)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	try.To(ctx.Err())
	try.To(vault.View(func(tx storage.ReadTx) error {
		return requireKnownSubject(tx, expectedRoot, subject)
	}))
	ad, found := try.To2(ReadReceivedClaim(vault, expectedRoot, subject))
	if !found {
		return false, ErrNoReceivedClaim
	}
	// Independently authenticate the original signature and expiry before dialing.
	// The signed endpoint remains only a network hint, never identity authority.
	current := try.To1(decodeCurrent(ad, expectedRoot, subject))
	try.To(checkVerificationTime(ctx, current.Payload.ExpiresUnixNano))
	nonce := make([]byte, 32)
	try.To1(rand.Read(nonce))
	endpoint := strings.TrimSuffix(current.Payload.PeerIntroductionURL, "/peer/introduction") + "/peer/ad/proof"
	proof := try.To1(requestCurrentProof(ctx, endpoint, ad, nonce))
	try.To(VerifyCurrentProof(expectedRoot, subject, ad, nonce, proof, time.Now()))
	try.To(checkVerificationTime(ctx, current.Payload.ExpiresUnixNano))
	updateErr := vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		try.To(checkVerificationTime(ctx, current.Payload.ExpiresUnixNano))
		try.To(requireKnownSubject(tx, expectedRoot, subject))
		claims := try.To1(readReceivedClaims(tx, expectedRoot))
		i, present := claimIndex(claims.Entries, subject)
		if !present || !bytes.Equal(claims.Entries[i].Ad, ad) {
			return ErrReceivedClaimChanged
		}
		result := replaceVerifiedClaim(tx, expectedRoot, subject, ad)
		// Also abort if local validation/sealing crossed expiry or cancellation.
		try.To(checkVerificationTime(ctx, current.Payload.ExpiresUnixNano))
		return result
	})
	try.To(ctx.Err()) // A canceled/lost acknowledgement is never success.
	if updateErr == errVerifiedClaimUnchanged {
		return false, nil
	}
	try.To(updateErr)
	return true, nil
}

func requireKnownSubject(tx storage.ReadTx, root, subject key.Public) (err error) {
	defer err2.Handle(&err, nil)
	known := try.To1(onboarding.IsKnownIntroductionInTx(tx, root, subject))
	if !known {
		return ErrSubjectNotKnown
	}
	return nil
}

func checkVerificationTime(ctx context.Context, expires int64) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)
	try.To(ctx.Err())
	now := time.Now()
	try.To(validateTime(now))
	assert.That(now.UnixNano() < expires, ErrInvalidRecord)
	return nil
}
