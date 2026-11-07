package pw

import (
	"fmt"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/storage"
)

func (f *requesterFixture) usableContactV2(alice bool, runtime ContactRuntimeV2,
) (string, error) {
	if alice {
		return usableContactV2(f.alice.vault, f.root.public, f.peer.public,
			f.signer, runtime, true, func() time.Time { return f.now })
	}
	return usableContactV2(f.f.vault, f.root.public, f.local.public,
		f.local.handle, runtime, false, func() time.Time { return f.now })
}

func TestContactV2DeleteBothRoles(t *testing.T) {
	for _, alice := range []bool{false, true} {
		t.Run(fmt.Sprint(alice), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			response := f.responseV2(t)
			assert.That(try.To1(f.receiveV2(response)))
			node, local, peer, origin, want := &f.f, f.local.public,
				f.peer.public, "http://127.0.0.1:12345", aliceServiceOrigin
			read := BobContactV2
			if alice {
				node, local, peer, origin, want = &f.alice, peer, local,
					want, origin
				read = RequesterContactV2
			}
			history := requesterRecords(t, node.vault)
			try.To1(policy.DenyLocal(node.vault, f.root.public, local, peer))
			assert.DeepEqual(requesterRecords(t, node.vault), history)
			assert.Equal(try.To1(read(node.vault, f.root.public, local)), want)
			assert.Equal(try.To1(f.usableContactV2(alice,
				ContactRuntimeV2{true, origin})), "")
			node.lease.remaining.Store(0)
			before := heldTestState(t, node.vault)
			assert.That(try.To1(DeleteHeldLocal(node.vault, f.root.public, local)))
			delete(before["root"], heldKey)
			assert.DeepEqual(heldTestState(t, node.vault), before)
			node.reopen(t)
			node.unchanged(t, func() {
				assert.Equal(try.To1(read(node.vault, f.root.public, local)), want)
				assert.ThatNot(try.To1(DeleteHeldLocal(node.vault,
					f.root.public, local)))
				assert.Equal(try.To1(f.usableContactV2(alice,
					ContactRuntimeV2{true, origin})), "")
			})
		})
	}
}

func TestContactV2UnexpectedFirstUseFailsClosed(t *testing.T) {
	for _, alice := range []bool{false, true} {
		for _, name := range []string{firstUseKey, useSeenKey} {
			t.Run(fmt.Sprint(alice, name), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRequester(t, false)
				response := f.responseV2(t)
				assert.That(try.To1(f.receiveV2(response)))
				node, local, read := &f.f, f.local.public, BobContactV2
				if alice {
					node, local, read = &f.alice, f.peer.public, RequesterContactV2
				}
				try.To(node.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					return tx.Put([]byte(name), []byte{0xff})
				}))
				node.unchanged(t, func() {
					contact, err := read(node.vault, f.root.public, local)
					assert.Equal(err, ErrEstablishment)
					assert.Equal(contact, "")
					deleted, err := DeleteHeldLocal(node.vault, f.root.public, local)
					assert.Equal(err, ErrDeleteHeld)
					assert.ThatNot(deleted)
				})
			})
		}
	}
}

func TestContactV2BobRefusesUnexpectedFirstUse(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		for _, name := range []string{firstUseKey, useSeenKey} {
			t.Run(fmt.Sprint(accepted, name), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRequester(t, false)
				saved := try.To1(f.saveV2(aliceServiceOrigin))
				if accepted {
					try.To(f.acceptV2(saved.request, f.local.handle))
				}
				try.To(f.f.vault.Update(func(tx storage.WriteTx) error {
					return tx.Put([]byte(name), []byte{0xff})
				}))
				f.f.unchanged(t, func() {
					if accepted {
						response, err := f.replyV2(saved.request, f.local.handle)
						assert.Equal(err, ErrEstablishment)
						assert.SNil(response)
					} else {
						assert.Equal(f.acceptV2(saved.request, f.local.handle),
							ErrEstablishment)
					}
				})
			})
		}
	}
}
