package storage

import "context"

// VaultID identifies a vault. It is not authority to access it.
type VaultID [16]byte

// KeyID identifies an immutable, externally provisioned key generation.
type KeyID [16]byte

// KeyProvider authorizes access to the caller's expected identities, never IDs
// selected from stored bytes. Provision independent random 32-byte secrets.
// Acquire returns no lease on failure and a nonnil owned lease on success.
// Methods must terminate and must not reenter storage.
type KeyProvider interface {
	Acquire(context.Context, VaultID, KeyID) (Lease, error)
}

// Lease supplies authorization and borrowed secret bytes until Release.
// Storage calls Release exactly once for each successfully acquired lease.
// Methods must terminate and must not reenter storage. Acquire, Reserve and
// Release run outside storage admission gates and engine transactions; Check
// may run under the admission gate, but never under an engine lock.
type Lease interface {
	Secret() []byte
	// Check synchronizes authorization and availability checks. Revocation is
	// observed at admission; already admitted work is allowed to finish.
	Check() error
	// Reserve irrevocably precharges n seals and returns a nonnil concurrency-
	// safe LOCAL spending gate that performs no provider I/O or authorization
	// rechecks. Reserve(0) must succeed with a rejecting gate even when the
	// encryption budget is exhausted. Failed/unused reservations are not refunded.
	// One request is bounded by 2^24. Global lifetime accounting across leases,
	// files, reopens and restores is the provider's responsibility; this partial
	// integration establishes no production accounting guarantee.
	Reserve(n uint32) (spend func() error, err error)
	Release() error
}
