package pw

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestBobAcceptCompetition(t *testing.T) {
	defer assert.PushTester(t)()
	f := newEstablishment(t, false)
	carol := newSigner(t)
	base := intro.New(key.Info{Public: f.root.public})
	savePath(t, f.f.vault, f.root.public,
		base.Introduce(f.root.handle, key.Info{Public: carol.public}), carol)
	try.To1(onboarding.VerifyReceived(f.f.vault, f.root.public))
	request := f.request
	request.Payload.Requester, request.Payload.Device = carol.public, carol.public
	request.Payload.AttemptID = bytes.Repeat([]byte{43}, 32)
	carolRaw := signEstablishment(t, request, carol.handle)
	start := make(chan struct{})
	results := make(chan error, 2)
	var service sync.Mutex
	for _, raw := range [][]byte{f.raw, carolRaw} {
		go func() {
			<-start
			service.Lock()
			defer service.Unlock()
			results <- f.accept(raw, f.local.handle)
		}()
	}
	close(start)
	first, second := <-results, <-results
	assert.That((first == nil && second == ErrEstablishment) ||
		(first == ErrEstablishment && second == nil))
	row, history, holding := f.records(t)
	assert.Equal(row.State, InvitationConsumed)
	assert.SNotEmpty(holding)
	var record acceptedRecord
	try.To(wire.UnmarshalCanonical(&record, history))
	assert.That(
		bytes.Equal(record.Request, f.raw) ||
			bytes.Equal(record.Request, carolRaw),
	)
}

func TestBobAcceptRevokeOrders(t *testing.T) {
	for _, revokeFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(revokeFirst), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newEstablishment(t, false)
			if revokeFirst {
				assert.That(try.To1(RevokeInvitation(f.f.vault,
					f.root.public, f.local.public, f.invitation.ID)))
				f.invitation.State = InvitationRevoked
				assert.Equal(f.accept(f.raw, f.local.handle), ErrEstablishment)
				f.unconsumed(t)
				return
			}
			try.To(f.accept(f.raw, f.local.handle))
			row, history, held := f.records(t)
			f.f.unchanged(t, func() {
				assert.ThatNot(try.To1(RevokeInvitation(f.f.vault,
					f.root.public, f.local.public, f.invitation.ID)))
			})
			gotRow, gotHistory, gotHeld := f.records(t)
			assert.DeepEqual(gotRow, row)
			assert.DeepEqual(gotHistory, history)
			assert.DeepEqual(gotHeld, held)
		})
	}
}

func TestBobAcceptEncryptionFailure(t *testing.T) {
	for allowance := range int64(3) {
		t.Run(fmt.Sprint(allowance), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newEstablishment(t, false)
			f.f.lease.remaining.Store(allowance)
			assert.Equal(f.accept(f.raw, f.local.handle), ErrEstablishment)
			assert.Equal(f.f.lease.remaining.Load(), 0)
			f.unconsumed(t)
			f.f.reopen(t)
			f.unconsumed(t)
		})
	}
}

type failingAcceptanceTx struct {
	storage.WriteTx
	failAfter int
	writes    int
	cause     error
}

func (tx *failingAcceptanceTx) Put(k, v []byte) error {
	if err := tx.WriteTx.Put(k, v); err != nil {
		return err
	}
	tx.writes++
	if tx.writes == tx.failAfter {
		return tx.cause
	}
	return nil
}

func TestBobAcceptCallbackRollback(t *testing.T) {
	for index := range 3 {
		boundary := index + 1
		t.Run(fmt.Sprint(boundary), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newEstablishment(t, false)
			payload := acceptedPayload(f.request.Payload, f.raw)
			digest := key.HashTagged(
				AcceptedPurpose,
				try.To1(wire.Marshal(payload)),
			)
			response := try.To1(wire.Marshal(SignedAccepted{Payload: payload,
				Signature: try.To1(f.local.handle.Sign(digest[:]))}))
			cause := errors.New("callback failure after acceptance write")
			err := f.f.vault.Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				return commitAcceptance(
					&failingAcceptanceTx{WriteTx: tx,
						failAfter: boundary, cause: cause},
					f.root.public,
					f.local.public,
					establishmentEndpoint,
					f.raw,
					response,
					func() time.Time { return f.now },
				)
			})
			assert.ErrorIs(err, cause)
			f.unconsumed(t)
			f.f.reopen(t)
			f.unconsumed(t)
		})
	}
}

func TestBobAcceptConflictingState(t *testing.T) {
	for _, name := range []string{acceptedKey, heldKey, invitationKey} {
		for _, namespace := range []bool{false, true} {
			t.Run(fmt.Sprint(name, namespace), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newEstablishment(t, false)
				try.To(f.f.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					if namespace {
						try.To(tx.Delete([]byte(name)))
						try.To1(tx.EnsureChild([]byte(name)))
						return nil
					}
					return tx.Put([]byte(name), []byte{0xff})
				}))
				f.f.unchanged(t, func() {
					assert.Equal(
						f.accept(f.raw, f.local.handle),
						ErrEstablishment,
					)
				})
			})
		}
	}
}
