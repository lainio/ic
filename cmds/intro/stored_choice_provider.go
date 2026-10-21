package intro

import (
	"context"
	"sync"

	"github.com/lainio/ic/storage"
)

// This finite development policy is independent of the two-request workload.
// It is not durable lifetime accounting across process restarts or restores.
const storedChoiceEncryptionBudget uint32 = 1 << 24

// Adapted from cmd/vault-playground's private demoProvider. One binding, secret,
// and shared counter stay alive across reopening until all database use ends.
type storedChoiceProvider struct {
	mu                   sync.Mutex
	secret               []byte
	vault                storage.VaultID
	id                   storage.KeyID
	remainingEncryptions uint32
}

func newStoredChoiceProvider() *storedChoiceProvider {
	return &storedChoiceProvider{
		secret:               make([]byte, 32),
		vault:                storage.VaultID{1},
		id:                   storage.KeyID{7},
		remainingEncryptions: storedChoiceEncryptionBudget,
	}
}

func (p *storedChoiceProvider) Acquire(
	ctx context.Context, vault storage.VaultID, id storage.KeyID,
) (storage.Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if vault != p.vault || id != p.id {
		return nil, storage.ErrProvider
	}
	return &storedChoiceLease{p}, nil
}

type storedChoiceLease struct{ p *storedChoiceProvider }

// These demo methods provide no production revocation or key custody.
// The runner clears the borrowed secret only after all database use ends.
func (l *storedChoiceLease) Secret() []byte { return l.p.secret }
func (l *storedChoiceLease) Check() error   { return nil }
func (l *storedChoiceLease) Release() error { return nil }

// All leases share the same counter; acquiring and reopening never reset it.
// Only the storage codec calls this during use, without I/O or reentry.
func (l *storedChoiceLease) ConsumeEncryption() error {
	p := l.p
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.remainingEncryptions == 0 {
		return storage.ErrKeyUsageExhausted
	}
	p.remainingEncryptions--
	return nil
}
