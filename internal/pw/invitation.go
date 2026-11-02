package pw

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const (
	// InvitationTTL is server policy, independent of ad TTL and TLC's clock.
	InvitationTTL      = 15 * time.Minute
	invitationKey      = "local-pw-invitation-v1"
	maxInvitationBytes = 512

	InvitationActive   = "Active"
	InvitationRevoked  = "Revoked"
	InvitationConsumed = "Consumed"
	InvitationAny      = "Any"
	InvitationDirected = "Directed"
)

var (
	ErrInvitationInput = errors.New("invalid invitation input")
	ErrInvitationState = errors.New(
		"invalid or unavailable invitation state",
	)
	ErrInvitationIssued    = errors.New("invitation already issued")
	errInvitationUnchanged = errors.New("invitation unchanged")
)

// Invitation is the bounded v1 canonical CBOR array in declaration order,
// stored only inside the encrypted Vault. ID is a fresh 32-byte local lookup
// secret, not an authenticated invitation wire protocol. ExpiresUnixNano is a
// UTC instant in nonnegative int64 nanoseconds. Any has a nil Recipient;
// Directed retains the exact canonical public key, without asserting Known.
// There is no requester, attempt, acceptance, PWHeld, or Trust in this row.
// Consumed is reserved for the revocation no-op boundary; this increment has
// no production transition into it and defines no acceptance record format.
type Invitation struct {
	_               struct{} `cbor:",toarray"`
	Version         uint8
	ID              []byte
	Root            key.Public
	Target          key.Public
	Audience        string
	Recipient       key.Public
	ExpiresUnixNano int64
	State           string
}

// IssueInvitation implements only IssueInvitation's Bob-local activation.
// The caller must obtain explicit owner authorization and borrow an open Vault
// independently bound to the pinned Root/target (e.g. nodevault.OpenForNode).
// A Vault pointer alone does not establish that binding. Never call this from
// startup, discovery, publication, or a peer request. Recipient nil means Any;
// otherwise it must be an exact canonical ES256/P-256 key distinct from target.
// No introduction eligibility is inferred or promoted.
//
// At most one row may ever be issued in this bounded v1 Vault. An existing row,
// including expired/revoked/consumed, is validated and never replaced. Only a
// committed row is returned. There is no signing or network I/O, and random
// generation precedes the sole Update. The server samples its own wall clock;
// clock rollback and restored/deleted Vault files are not protected here.
func IssueInvitation(vault *storage.Vault, root, target, recipient key.Public,
) (Invitation, error) {
	return issueInvitation(vault, root, target, recipient, time.Now())
}

// Package-local time input keeps the HTTP surface independent of client time.
func issueInvitation(vault *storage.Vault, root, target, recipient key.Public,
	now time.Time,
) (_ Invitation, err error) {
	defer err2.Handle(&err, nil)

	if !validInvitationBinding(vault, root, target) ||
		!validInvitationTime(now) ||
		!validInvitationTime(now.Add(InvitationTTL)) ||
		(recipient != nil && (!validPublic(recipient) ||
			bytes.Equal(recipient, target))) {
		return Invitation{}, ErrInvitationInput
	}
	row := Invitation{
		Version: 1, ID: make([]byte, 32), Root: bytes.Clone(root),
		Target: bytes.Clone(target), Audience: InvitationAny,
		Recipient:       bytes.Clone(recipient),
		ExpiresUnixNano: now.Add(InvitationTTL).UTC().UnixNano(),
		State:           InvitationActive,
	}
	if recipient != nil {
		row.Audience = InvitationDirected
	}
	if _, err := rand.Read(row.ID); err != nil {
		return Invitation{}, ErrInvitationState
	}
	raw, err := wire.Marshal(row)
	if err != nil {
		return Invitation{}, ErrInvitationState
	}
	err = vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		_, found := try.To2(readInvitation(tx, row.Root, row.Target))
		if found {
			return ErrInvitationIssued // Abort without a seal or bookkeeping.
		}
		return tx.Put([]byte(invitationKey), raw)
	})
	if err == ErrInvitationIssued {
		return Invitation{}, err
	}
	if err != nil {
		return Invitation{}, ErrInvitationState
	}
	return row, nil
}

// ReadInvitation validates the complete stored row and independent binding.
// It returns caller-owned bytes, including expired/revoked rows, without writes
// or repair. Absence returns zero, false, nil; errors return zero, false, err.
// Neither presence nor a time predicate is authorization to redeem anything.
func ReadInvitation(vault *storage.Vault, root, target key.Public,
) (Invitation, bool, error) {
	if !validInvitationBinding(vault, root, target) {
		return Invitation{}, false, ErrInvitationInput
	}
	root, target = bytes.Clone(root), bytes.Clone(target)
	var row Invitation
	var found bool
	err := vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		row, found = try.To2(readInvitation(tx, root, target))
		return nil
	})
	if err != nil {
		return Invitation{}, false, ErrInvitationState
	}
	return row, found, nil
}

// RevokeInvitation implements RevokeInvitation under IssueInvitation's owner
// authorization and pinned-Vault contract. The exact ID, full binding and
// current Active state are checked in the same sole Update as revocation.
// Expiry does not prevent revocation. True means Active -> Revoked committed;
// absent, wrong-ID, Revoked and Consumed return false without any durable write
// or encryption spending. No acceptance history or PW/policy state is touched.
func RevokeInvitation(vault *storage.Vault, root, target key.Public, id []byte,
) (bool, error) {
	if !validInvitationBinding(vault, root, target) || len(id) != 32 {
		return false, ErrInvitationInput
	}
	root, target, id = bytes.Clone(root), bytes.Clone(target), bytes.Clone(id)
	err := vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		row, found := try.To2(readInvitation(tx, root, target))
		if !found || !bytes.Equal(row.ID, id) || row.State != InvitationActive {
			return errInvitationUnchanged
		}
		row.State = InvitationRevoked
		return tx.Put([]byte(invitationKey), try.To1(wire.Marshal(row)))
	})
	if err == errInvitationUnchanged {
		return false, nil
	}
	if err != nil {
		return false, ErrInvitationState
	}
	return true, nil
}

func readInvitation(tx storage.ReadTx, root, target key.Public,
) (_ Invitation, _ bool, err error) {
	defer err2.Handle(&err, nil)

	raw, found := try.To2(tx.Get([]byte(invitationKey)))
	if !found {
		return Invitation{}, false, nil
	}
	if len(raw) == 0 || len(raw) > maxInvitationBytes {
		return Invitation{}, false, ErrInvitationState
	}
	var row Invitation
	// Avoid tracing decoder diagnostics containing stored bytes or secrets.
	if wire.DecMode.Unmarshal(raw, &row) != nil {
		return Invitation{}, false, ErrInvitationState
	}
	canonical, encodeErr := wire.EncMode.Marshal(row)
	if encodeErr != nil || !bytes.Equal(raw, canonical) || row.Version != 1 ||
		len(row.ID) != 32 || !bytes.Equal(row.Root, root) ||
		!bytes.Equal(row.Target, target) ||
		row.ExpiresUnixNano < int64(InvitationTTL) {
		return Invitation{}, false, ErrInvitationState
	}
	if row.State != InvitationActive && row.State != InvitationRevoked &&
		row.State != InvitationConsumed {
		return Invitation{}, false, ErrInvitationState
	}
	audienceOK := (row.Audience == InvitationAny && row.Recipient == nil) ||
		(row.Audience == InvitationDirected && validPublic(row.Recipient) &&
			!bytes.Equal(row.Recipient, target))
	if !audienceOK {
		return Invitation{}, false, ErrInvitationState
	}
	return row, true, nil
}

func validInvitationBinding(
	vault *storage.Vault,
	root, target key.Public,
) bool {
	return vault != nil && validPublic(root) && validPublic(target)
}

func validInvitationTime(now time.Time) bool {
	return !now.IsZero() && !now.Before(time.Unix(0, 0)) &&
		!now.After(time.Unix(0, math.MaxInt64))
}

// Time predicate only, on a validated row. This deliberately confers no
// eligibility beyond time: no Active, Known, device, policy or binding guard.
func invitationBeforeExpiry(row Invitation, now time.Time) bool {
	return validInvitationTime(now) &&
		now.Before(time.Unix(0, row.ExpiresUnixNano).UTC())
}
