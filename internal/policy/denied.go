// Package policy implements only the durable local Deny-set projection of V19
// DenyPeer/AllowPeer. No PW, trust, ad, device, or introduction state is changed.
package policy

import (
	"bytes"
	"crypto/ecdh"
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
	deniedKey      = "local-denied-peers-v1"
	maxDeniedPeers = 32
	maxPublicBytes = 128
	maxDeniedBytes = 32 + (maxDeniedPeers+2)*(maxPublicBytes+2)
)

var (
	ErrInvalidInput  = errors.New("invalid local denial input")
	ErrInvalidRecord = errors.New("invalid stored local denial policy")
	ErrFull          = errors.New("local denial collection full")
	errUnchanged     = errors.New("local denial unchanged")
)

// One root record avoids unenumerable child namespaces. Get rejects a child
// occupying its name. Canonical arrays reject extra fields; every read checks
// the entire sorted, duplicate-free collection and its independent binding.
// A missing record is empty. After the last removal we retain a bound, versioned
// empty array (never null). Versions are rejected, never implicitly migrated.
type deniedPeers struct {
	_       struct{} `cbor:",toarray"`
	Version uint8
	Root    key.Public
	Local   key.Public
	Peers   []key.Public
}

// DenyLocal atomically inserts peer into this node's local Deny set. The peer
// need not be Known. Exact retries return false without writes, seals, or
// backend bookkeeping. True means the update committed; errors return false.
//
// The caller borrows an open Vault independently bound to root/local (for
// example nodevault.OpenForNode), and supplies those pinned identities from
// local configuration. A Vault pointer alone proves no node/Root binding.
// Neither peer data nor a future HTTP request supplies consent or authority to
// operate this policy. Inputs are copied; callers must not mutate them during
// the call. There is no signing, network I/O, or corresponding remote mutation.
//
// This is ONLY the local Deny-set projection, not full DenyPeer refinement:
// no modeled live PW pipe exists here yet. A later operational DenyPeer with
// existing live PW MUST atomically close that pipe while preserving reusable
// PWHeld, trust, and ad evidence. Do not compose this call with a later close.
func DenyLocal(
	vault *storage.Vault,
	root, local, peer key.Public,
) (bool, error) {
	return changeLocal(vault, root, local, peer, true)
}

// AllowLocal removes an already denied peer under DenyLocal's binding contract.
// Absence is an exact no-write/no-seal retry. It grants no Known, positive
// consent, usability, trust, reachability, PWHeld, or PWOpen, and never starts
// or reopens a remote operation. True is returned only after commit.
func AllowLocal(
	vault *storage.Vault,
	root, local, peer key.Public,
) (bool, error) {
	return changeLocal(vault, root, local, peer, false)
}

func changeLocal(vault *storage.Vault, root, local, peer key.Public,
	deny bool,
) (_ bool, err error) {
	defer err2.Handle(&err, nil)

	if vault == nil || !validInputs(root, local, peer) {
		return false, ErrInvalidInput
	}
	root, local, peer = bytes.Clone(root), bytes.Clone(local), bytes.Clone(peer)
	updateErr := vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return changeDenied(tx, root, local, peer, deny)
	})
	if updateErr == errUnchanged {
		return false, nil
	}
	try.To(updateErr)
	return true, nil
}

// IsDenied is a pure read under DenyLocal's independently pinned binding.
// It validates all entries even when peer is absent. An error is never an
// allowed result: callers MUST reject it. Reads spend no encryption allowance,
// repair nothing, and confer only a momentary observation, not authorization.
func IsDenied(vault *storage.Vault, root, local, peer key.Public) (
	_ bool, err error,
) {
	defer err2.Handle(&err, nil)

	if vault == nil || !validInputs(root, local, peer) {
		return false, ErrInvalidInput
	}
	root, local, peer = bytes.Clone(root), bytes.Clone(local), bytes.Clone(peer)
	var denied bool
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		peers := try.To1(readDenied(tx, root, local))
		_, denied = slices.BinarySearchFunc(
			peers.Peers,
			peer,
			func(a, b key.Public) int { return bytes.Compare(a, b) },
		)
		return nil
	}))
	return denied, nil
}

// IsDeniedInTx borrows the caller's active transaction and copies key inputs.
// It retains neither transaction nor input buffers, does not finish the
// transaction, and must not be used concurrently or after its callback exits.
// It performs the same whole-record validation as IsDenied, with no writes,
// signer calls, expiry, repair, or nested Vault transaction. A future CreatePW
// final guard must use this inside its atomic commit along with Known and other
// required guards; never nest Vault.View inside Vault.Update. Errors deny use.
func IsDeniedInTx(tx storage.ReadTx, root, local, peer key.Public) (
	_ bool, err error,
) {
	defer err2.Handle(&err, nil)

	if tx == nil || !validInputs(root, local, peer) {
		return false, ErrInvalidInput
	}
	root, local, peer = bytes.Clone(root), bytes.Clone(local), bytes.Clone(peer)
	peers := try.To1(readDenied(tx, root, local))
	_, denied := slices.BinarySearchFunc(
		peers.Peers,
		peer,
		func(a, b key.Public) int { return bytes.Compare(a, b) },
	)
	return denied, nil
}

// Inputs have been validated and copied before entering the transaction.
func changeDenied(tx storage.WriteTx, root, local, peer key.Public,
	deny bool,
) (err error) {
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()

	peers := try.To1(readDenied(tx, root, local))
	i, found := slices.BinarySearchFunc(
		peers.Peers,
		peer,
		func(a, b key.Public) int { return bytes.Compare(a, b) },
	)
	if found == deny {
		return errUnchanged // Roll back backend bookkeeping as well.
	}
	if deny {
		assert.That(len(peers.Peers) < maxDeniedPeers, ErrFull)
		peers.Peers = slices.Insert(peers.Peers, i, peer)
	} else {
		peers.Peers = slices.Delete(peers.Peers, i, i+1)
	}
	return tx.Put([]byte(deniedKey), try.To1(wire.Marshal(peers)))
}

func readDenied(tx storage.ReadTx, root, local key.Public) (
	_ deniedPeers, err error,
) {
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()

	raw, found := try.To2(tx.Get([]byte(deniedKey)))
	if !found {
		return deniedPeers{
			Version: 1, Root: root, Local: local, Peers: []key.Public{},
		}, nil
	}
	assert.That(len(raw) > 0 && len(raw) <= maxDeniedBytes, ErrInvalidRecord)
	var peers deniedPeers
	// Decode without tracing raw CBOR diagnostics or attacker-controlled keys.
	assert.That(wire.DecMode.Unmarshal(raw, &peers) == nil, ErrInvalidRecord)
	canonical, encodeErr := wire.EncMode.Marshal(peers)
	assert.That(
		encodeErr == nil && bytes.Equal(raw, canonical),
		ErrInvalidRecord,
	)
	assert.That(peers.Version == 1 && bytes.Equal(peers.Root, root) &&
		bytes.Equal(peers.Local, local) && peers.Peers != nil &&
		len(peers.Peers) <= maxDeniedPeers, ErrInvalidRecord)
	for i, peer := range peers.Peers {
		assert.That(
			validPublic(peer) && !bytes.Equal(peer, local),
			ErrInvalidRecord,
		)
		assert.That(i == 0 || bytes.Compare(peers.Peers[i-1], peer) < 0,
			ErrInvalidRecord)
	}
	return peers, nil
}

func validInputs(root, local, peer key.Public) bool {
	return validPublic(root) && validPublic(local) && validPublic(peer) &&
		!bytes.Equal(local, peer)
}

// Match pw/ads' canonical ES256/P-256 profile, including shortened coordinates
// from the installed software signer. Decoder errors stay out of err2 tracing.
func validPublic(public key.Public) bool {
	if len(public) == 0 || len(public) > maxPublicBytes {
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
