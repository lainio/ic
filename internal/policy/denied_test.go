package policy

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestIndependentlyBoundLocalTransitionsAndReopen(t *testing.T) {
	defer assert.PushTester(t)()
	root, local, peer := newPublic(t), newPublic(t), newPublic(t)
	dir, otherDir := filepath.Join(
		t.TempDir(),
		"node",
	), filepath.Join(
		t.TempDir(),
		"node",
	)
	try.To(os.Mkdir(dir, 0700))
	try.To(os.Mkdir(otherDir, 0700))
	keyFile, otherKey := filepath.Join(
		t.TempDir(),
		"key",
	), filepath.Join(
		t.TempDir(),
		"key",
	)
	store := try.To1(
		nodevault.CreateForNode(t.Context(), dir, keyFile, root, local),
	)
	t.Cleanup(func() { assert.NoError(store.Close()) })
	other := try.To1(
		nodevault.CreateForNode(t.Context(), otherDir, otherKey, root, peer),
	)
	t.Cleanup(func() { assert.NoError(other.Close()) })
	otherBefore := try.To1(
		os.ReadFile(filepath.Join(otherDir, "state", "vault.db")),
	)

	assert.ThatNot(try.To1(IsDenied(store.Vault(), root, local, peer)))
	assert.That(try.To1(DenyLocal(store.Vault(), root, local, peer)))
	assert.That(try.To1(IsDenied(store.Vault(), root, local, peer)))
	assert.SLen(
		try.To1(onboarding.ListKnownIntroductions(store.Vault(), root)),
		0,
	)
	assert.ThatNot(try.To1(IsDenied(other.Vault(), root, peer, local)))
	assert.DeepEqual(
		try.To1(os.ReadFile(filepath.Join(otherDir, "state", "vault.db"))),
		otherBefore,
	)
	try.To(store.Close())

	for _, binding := range [][2]key.Public{{peer, local}, {root, peer}} {
		rejected, err := nodevault.OpenForNode(
			t.Context(),
			dir,
			keyFile,
			binding[0],
			binding[1],
		)
		assert.Error(err)
		assert.Nil(rejected)
	}
	store = try.To1(
		nodevault.OpenForNode(t.Context(), dir, keyFile, root, local),
	)
	assert.That(try.To1(IsDenied(store.Vault(), root, local, peer)))
	for _, deny := range []bool{true, false, false} {
		statePath, usagePath := filepath.Join(
			dir,
			"state",
			"vault.db",
		), filepath.Join(
			dir,
			"state",
			"usage.db",
		)
		state, usage := try.To1(
			os.ReadFile(statePath),
		), try.To1(
			os.ReadFile(usagePath),
		)
		wasDenied := try.To1(IsDenied(store.Vault(), root, local, peer))
		changed := try.To1(changeLocal(store.Vault(), root, local, peer, deny))
		assert.Equal(changed, wasDenied != deny)
		if !changed {
			assert.DeepEqual(try.To1(os.ReadFile(statePath)), state)
			assert.DeepEqual(try.To1(os.ReadFile(usagePath)), usage)
		}
	}
	try.To(store.Close())
	store = try.To1(
		nodevault.OpenForNode(t.Context(), dir, keyFile, root, local),
	)
	assert.ThatNot(try.To1(IsDenied(store.Vault(), root, local, peer)))
	assert.DeepEqual(
		try.To1(os.ReadFile(filepath.Join(otherDir, "state", "vault.db"))),
		otherBefore,
	)
}

func TestCapacityOrderRetriesAndInputOwnership(t *testing.T) {
	defer assert.PushTester(t)()
	f := newVault(t)
	root, local := newPublic(t), newPublic(t)
	peers := make([]key.Public, maxDeniedPeers)
	for i := range peers {
		peers[i] = newPublic(t)
		r, l, p := bytes.Clone(root), bytes.Clone(local), bytes.Clone(peers[i])
		f.lease.onCheck = func() { clear(r); clear(l); clear(p) }
		assert.That(try.To1(DenyLocal(f.vault, r, l, p)))
		f.lease.onCheck = nil
	}
	slices.SortFunc(
		peers,
		func(a, b key.Public) int { return bytes.Compare(a, b) },
	)
	assert.DeepEqual(rawPolicy(t, f.vault), try.To1(wire.Marshal(deniedPeers{
		Version: 1, Root: root, Local: local, Peers: peers,
	})))
	extra := newPublic(t)
	f.lease.remaining.Store(0)
	f.unchanged(t, func() {
		for _, peer := range peers {
			assert.That(try.To1(IsDenied(f.vault, root, local, peer)))
			assert.ThatNot(try.To1(DenyLocal(f.vault, root, local, peer)))
		}
		assert.ThatNot(try.To1(AllowLocal(f.vault, root, local, extra)))
		changed, err := DenyLocal(f.vault, root, local, extra)
		assert.ThatNot(changed)
		assert.ErrorIs(err, ErrFull)
	})
	f.lease.remaining.Store(2)
	assert.That(try.To1(AllowLocal(f.vault, root, local, peers[0])))
	assert.That(try.To1(DenyLocal(f.vault, root, local, extra)))
	assert.ThatNot(try.To1(IsDenied(f.vault, root, local, peers[0])))
	assert.That(try.To1(IsDenied(f.vault, root, local, extra)))
	f.reopen(t)
	assert.That(try.To1(IsDenied(f.vault, root, local, extra)))
}

func TestReadOwnershipBorrowedTransactionAndEmptyRetries(t *testing.T) {
	defer assert.PushTester(t)()
	f := newVault(t)
	root, local, peer := newPublic(t), newPublic(t), newPublic(t)
	f.unchanged(t, func() {
		assert.ThatNot(try.To1(AllowLocal(f.vault, root, local, peer)))
		assert.ThatNot(try.To1(IsDenied(f.vault, root, local, peer)))
	})
	assert.That(try.To1(DenyLocal(f.vault, root, local, peer)))
	r, l, p := bytes.Clone(root), bytes.Clone(local), bytes.Clone(peer)
	f.lease.onCheck = func() { clear(r); clear(l); clear(p) }
	assert.That(try.To1(IsDenied(f.vault, r, l, p)))
	f.lease.onCheck = nil
	var expired storage.ReadTx
	f.unchanged(t, func() {
		try.To(f.vault.View(func(tx storage.ReadTx) (err error) {
			defer err2.Handle(&err, nil)
			expired = tx
			assert.That(try.To1(IsDeniedInTx(tx, root, local, peer)))
			return nil
		}))
		denied, err := IsDeniedInTx(expired, root, local, peer)
		assert.ThatNot(denied)
		assert.ErrorIs(err, storage.ErrTxClosed)
	})
	// Observe pending state and roll back in one caller-owned Update. This
	// would deadlock if IsDeniedInTx tried to open another Vault transaction.
	err := f.vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		try.To(changeDenied(tx, root, local, peer, false))
		assert.ThatNot(try.To1(IsDeniedInTx(tx, root, local, peer)))
		return errUnchanged
	})
	assert.ErrorIs(err, errUnchanged)
	assert.That(try.To1(IsDenied(f.vault, root, local, peer)))
	assert.That(try.To1(AllowLocal(f.vault, root, local, peer)))
	f.reopen(t)
	f.lease.remaining.Store(0)
	f.unchanged(t, func() {
		assert.ThatNot(try.To1(IsDenied(f.vault, root, local, peer)))
		assert.ThatNot(try.To1(AllowLocal(f.vault, root, local, peer)))
	})
}

func TestConcurrentDenyAllowRemainTransactional(t *testing.T) {
	defer assert.PushTester(t)()
	f := newVault(t)
	root, local := newPublic(t), newPublic(t)
	peers := []key.Public{
		newPublic(t),
		newPublic(t),
		newPublic(t),
		newPublic(t),
	}
	type result struct {
		changed bool
		err     error
	}
	for _, deny := range []bool{true, false} {
		results := make(chan result, len(peers)*4)
		for _, peer := range peers {
			for range 4 {
				go func() {
					changed, err := changeLocal(
						f.vault,
						root,
						local,
						peer,
						deny,
					)
					results <- result{changed, err}
				}()
			}
		}
		changed := 0
		for range len(peers) * 4 {
			r := <-results
			assert.NoError(r.err)
			if r.changed {
				changed++
			}
		}
		assert.Equal(changed, len(peers))
		for _, peer := range peers {
			assert.Equal(try.To1(IsDenied(f.vault, root, local, peer)), deny)
		}
	}
	// Mixed requests may serialize in either order. Successful insertions minus
	// removals must exactly match the final set, with no lost update.
	type mixedResult struct {
		delta int
		err   error
	}
	results := make(chan mixedResult, 32)
	for i := range 32 {
		go func() {
			changed, err := changeLocal(
				f.vault,
				root,
				local,
				peers[0],
				i%2 == 0,
			)
			delta := 0
			if changed {
				delta = 1 - 2*(i%2)
			}
			results <- mixedResult{delta, err}
		}()
	}
	balance := 0
	for range 32 {
		r := <-results
		assert.NoError(r.err)
		balance += r.delta
	}
	assert.That(balance == 0 || balance == 1)
	assert.Equal(
		try.To1(IsDenied(f.vault, root, local, peers[0])),
		balance == 1,
	)
}
