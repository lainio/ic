package pw

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/storage"
)

func TestIncomingAtomicFailure(t *testing.T) {
	for _, receiver := range []int{0, 1} {
		for _, mode := range []string{"write", "callback", "seal"} {
			t.Run(fmt.Sprint(receiver, "/", mode), func(t *testing.T) {
				defer assert.PushTester(t)()
				f, n, raw := incomingTest(t, receiver, "atomic inbox")
				before := outgoingTestState(t, n.own.vault)
				disk := try.To1(os.ReadFile(n.own.path))
				n.other.unchanged(t, func() {
					if mode == "seal" {
						n.own.lease.remaining.Store(0)
						signer := &probeSigner{Handle: n.signer}
						refuseIncoming(t, f, n, signer, raw)
						assert.Equal(signer.signCalls.Load(), 1)
						return
					}
					cause := errors.New("failure after pending inbox put")
					err := n.own.vault.Update(
						func(tx storage.WriteTx) (err error) {
							defer err2.Handle(&err, nil)
							if mode == "write" {
								return commitIncoming(&failingAcceptanceTx{
									WriteTx: tx, failAfter: 1, cause: cause,
								}, f.root.public, n.local, raw)
							}
							try.To(
								commitIncoming(tx, f.root.public, n.local, raw),
							)
							return cause
						},
					)
					assert.ErrorIs(err, cause)
				})
				assert.DeepEqual(try.To1(os.ReadFile(n.own.path)), disk)
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				n.own.reopen(t)
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
			})
		}
	}
}

func TestIncomingSlotChangesDuringProbe(t *testing.T) {
	for _, mode := range []string{"identical", "conflict", "corrupt", "lost result"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f, n, raw := incomingTest(t, 0, "explicit admission")
			signer := &probeSigner{Handle: n.signer}
			var committed map[string]map[string][]byte
			var disk []byte
			signer.sign = func(d []byte) (_ []byte, err error) {
				defer err2.Handle(&err, nil)
				other := raw
				if mode == "conflict" {
					var envelope messageEnvelope
					try.To(wire.UnmarshalCanonical(&envelope, raw))
					other = signMessageEnvelope(
						t,
						envelope.Message,
						f.peer.handle,
					)
					assert.ThatNot(bytes.Equal(other, raw))
				}
				// Fault injection bypasses the normal owner ordering to exercise
				// the final slot check. Discard the competing call's result.
				try.To1(admitIncomingEnvelope(n.own.vault, f.root.public,
					n.local, n.signer, other))
				if mode == "corrupt" {
					try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
						return tx.Put([]byte(inboxKey), []byte{0xff})
					}))
				}
				committed = outgoingTestState(t, n.own.vault)
				disk = try.To1(os.ReadFile(n.own.path))
				n.own.lease.remaining.Store(0)
				if mode == "lost result" {
					return nil, errors.New(
						"caller cannot observe committed result",
					)
				}
				return n.signer.Sign(d)
			}
			n.other.unchanged(t, func() {
				saved, err := admitIncomingEnvelope(n.own.vault, f.root.public,
					n.local, signer, raw)
				assert.ThatNot(saved)
				if mode == "identical" {
					try.To(err)
				} else {
					assert.Equal(err, errIncoming)
				}
			})
			assert.Equal(signer.signCalls.Load(), 1)
			assert.DeepEqual(outgoingTestState(t, n.own.vault), committed)
			assert.DeepEqual(try.To1(os.ReadFile(n.own.path)), disk)
			n.own.reopen(t)
			n.own.unchanged(t, func() {
				saved, err := admitIncomingEnvelope(n.own.vault, f.root.public,
					n.local, n.signer, raw)
				assert.ThatNot(saved)
				if mode == "identical" || mode == "lost result" {
					try.To(err)
				} else {
					assert.Equal(err, errIncoming)
				}
			})
		})
	}
}

func TestIncomingOwnsInputBeforeProbe(t *testing.T) {
	defer assert.PushTester(t)()
	f, n, raw := incomingTest(t, 1, "owned bytes")
	original := bytes.Clone(raw)
	root, local := bytes.Clone(f.root.public), bytes.Clone(n.local)
	signer := &probeSigner{Handle: n.signer}
	signer.sign = func(d []byte) ([]byte, error) {
		clear(root)
		clear(local)
		clear(raw)
		return n.signer.Sign(d)
	}
	n.other.unchanged(t, func() {
		assert.That(try.To1(admitIncomingEnvelope(n.own.vault,
			root, local, signer, raw)))
	})
	var record inboxMessage
	try.To(wire.UnmarshalCanonical(&record,
		outgoingTestState(t, n.own.vault)["root"][inboxKey]))
	assert.DeepEqual(record.Envelope, original)
}
