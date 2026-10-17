package main

import (
	"context"
	"sync"

	"github.com/lainio/ic/storage"
)

// demoEncryptionBudget counts permitted encryptions for one session's binding.
// This finite test/demo policy matches the examples, not durable lifetime
// accounting across process restarts, copies, or restores.
const demoEncryptionBudget uint32 = 1 << 24

// Adapted from the storage examples' private consumerProvider fixture.
// The secret and binding stay fixed until all databases have been closed.
type demoProvider struct {
	mu                   sync.Mutex
	secret               []byte
	vault                storage.VaultID
	id                   storage.KeyID
	remainingEncryptions uint32
}

func newDemoProvider() *demoProvider {
	return &demoProvider{
		secret: make([]byte, 32), vault: storage.VaultID{1}, id: storage.KeyID{7},
		remainingEncryptions: demoEncryptionBudget,
	}
}

func (p *demoProvider) Acquire(ctx context.Context, vault storage.VaultID,
	id storage.KeyID) (storage.Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if vault != p.vault || id != p.id {
		return nil, storage.ErrProvider
	}
	return &demoLease{p}, nil
}

type demoLease struct{ p *demoProvider }

// These simplified methods provide no production revocation or key custody.
// The session owns the borrowed secret and clears it after database cleanup.
func (l *demoLease) Secret() []byte { return l.p.secret }
func (l *demoLease) Check() error   { return nil }
func (l *demoLease) Release() error { return nil }

// Only the storage codec calls this during use; it performs no I/O or reentry.
// All leases share the same counter. Acquiring/releasing never resets it.
func (l *demoLease) ConsumeEncryption() error {
	p := l.p
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.remainingEncryptions == 0 {
		return storage.ErrKeyUsageExhausted
	}
	p.remainingEncryptions--
	return nil
}
