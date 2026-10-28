// Package pw provides local prerequisites for a future pairwise ceremony.
// It implements no pairwise protocol or persistent relationship state.
package pw

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"reflect"

	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

var (
	ErrInvalidInput   = errors.New("invalid local acceptor input")
	ErrNotKnown       = errors.New("local acceptor requires own and peer Known introductions")
	ErrUnauthorized   = errors.New("local acceptor device is not authorized")
	ErrUnusableSigner = errors.New("local acceptor signer is not usable")
	ErrLocalState     = errors.New("invalid or unavailable local acceptor state")
)

// CheckLocalAcceptor checks local Known prerequisites and freshly probes the
// already-authorized local software signer. Only exact local == expectedRoot
// uses V19 Init's self-Known convention; the peer must always be in Known.
// This is restricted to v0.1's empty-Deny profile: no active Deny representation
// or DenyPeer/AllowPeer operation exists. It is NOT full V19 CanAccept,
// MayAttemptVia, mutual acceptance, remote liveness, ad currentness, or trust.
//
// The caller supplies independently pinned Root/local identities and an already
// open Vault independently bound to that Root/reader. A Vault pointer does not
// authenticate those identities; never derive them from a peer message or ad.
// The signer must be the caller's installed local software signer. The local
// probe signature is discarded, never returned, persisted, or sent to a peer.
// No network I/O, signer creation, Vault writes, or PW/trust changes occur.
//
// Success is instantaneous and must never become a cached eligibility flag.
// The caller coordinates evidence, authorization and signer changes if it needs
// a consistent interval; no service lock or Vault transaction spans the probe.
// A future handshake must reacquire guards at its decision/commit boundary,
// integrate an actual deny-policy guard and independently authenticate BOTH
// sides' live acceptance. CreatePW additionally requires a verified CURRENT ad,
// usable remote device and no mutual PW; a historical VerifiedAd is insufficient.
func CheckLocalAcceptor(vault *storage.Vault,
	expectedRoot, expectedLocal, peer key.Public, signer key.Handle,
) error {
	if vault == nil || !validPublic(expectedRoot) ||
		!validPublic(expectedLocal) || !validPublic(peer) ||
		bytes.Equal(expectedLocal, peer) {
		return ErrInvalidInput
	}
	expectedRoot = bytes.Clone(expectedRoot)
	expectedLocal, peer = bytes.Clone(expectedLocal), bytes.Clone(peer)

	// Always validate the whole collection, including for the Root convention.
	// Finding either subject early must not hide another corrupt Known binding.
	known, err := onboarding.ListKnownIntroductions(vault, expectedRoot)
	if err != nil {
		return ErrLocalState
	}
	ownKnown, peerKnown := bytes.Equal(expectedRoot, expectedLocal), false
	for _, subject := range known {
		ownKnown = ownKnown || bytes.Equal(subject, expectedLocal)
		peerKnown = peerKnown || bytes.Equal(subject, peer)
	}
	if !ownKnown || !peerKnown {
		return ErrNotKnown
	}

	state, err := device.InspectLocal(vault, expectedRoot, expectedLocal,
		localSigner{signer})
	if err != nil {
		return ErrLocalState
	}
	if !state.Authorized {
		return ErrUnauthorized
	}
	if !state.Usable {
		return ErrUnusableSigner
	}
	return nil
}

// Match ads' canonical COSE ES256/P-256 admission, including the installed
// software signer's potentially shortened coordinates. Keep decoder diagnostics
// out of err2 tracing: they can include caller-supplied map keys.
func validPublic(public key.Public) bool {
	if len(public) == 0 || len(public) > 128 {
		return false
	}
	var decoded webauthncose.EC2PublicKeyData
	if wire.DecMode.Unmarshal(public, &decoded) != nil {
		return false
	}
	canonical, err := wire.EncMode.Marshal(decoded)
	if err != nil || !bytes.Equal(public, canonical) ||
		decoded.KeyType != int64(webauthncose.EllipticKey) ||
		decoded.Algorithm != int64(webauthncose.AlgES256) ||
		decoded.Curve != int64(webauthncose.P256) ||
		len(decoded.XCoord) == 0 || len(decoded.XCoord) > 32 ||
		len(decoded.YCoord) == 0 || len(decoded.YCoord) > 32 {
		return false
	}
	var point [65]byte
	point[0] = 4
	copy(point[33-len(decoded.XCoord):33], decoded.XCoord)
	copy(point[65-len(decoded.YCoord):], decoded.YCoord)
	_, err = ecdh.P256().NewPublicKey(point[:])
	return err == nil
}

// Discard provider diagnostics before InspectLocal's err2 tracing, as the
// owner service's proof adapter does. This grants no new signer operation.
type localSigner struct{ key.Handle }

func (s localSigner) CBORPublicKey() ([]byte, error) {
	if s.Handle == nil {
		return nil, ErrUnusableSigner
	}
	value := reflect.ValueOf(s.Handle)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return nil, ErrUnusableSigner
		}
	}
	public, err := s.Handle.CBORPublicKey()
	if err != nil {
		return nil, ErrUnusableSigner
	}
	return public, nil
}

func (s localSigner) Sign(data []byte) ([]byte, error) {
	signature, err := s.Handle.Sign(data)
	if err != nil {
		return nil, ErrUnusableSigner
	}
	return signature, nil
}
