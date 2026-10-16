package storage

import "context"

// VaultID identifies a vault. It is not authority to access it.
type VaultID [16]byte

// KeyID identifies an immutable, externally provisioned key version.
// It is neither the secret nor a cipher selector.
type KeyID [16]byte

// KeyProvider decides whether access to a vault and key version is allowed and
// supplies its secret through a Lease. The application supplies the expected
// VaultID and KeyID; storage never selects these identities from stored bytes.
// Provision independent random 32-byte secrets; storage derives keys from them.
//
// Acquire returns no lease on failure and a nonnil owned lease on success.
// Methods must terminate and must not reenter storage.
type KeyProvider interface {
	Acquire(context.Context, VaultID, KeyID) (Lease, error)
}

// Lease supplies authorization and borrowed secret bytes until Release.
// Storage calls Release exactly once for each successfully acquired lease.
//
// Methods must terminate and must not reenter storage. Acquire, Reserve and
// Release run outside storage admission gates and engine transactions; Check
// may run under the admission gate, but never under an engine lock.
type Lease interface {
	// Secret returns the borrowed 32-byte secret for deriving storage keys.
	Secret() []byte
	// Check synchronizes authorization and availability checks. Revocation is
	// observed at admission; already admitted work is allowed to finish.
	Check() error
	// Reserve allocates n encryptions, not storage space or reads. It returns a
	// nonnil concurrency-safe local spending gate; each encryption spends one.
	// The gate performs no provider I/O or authorization rechecks. Reservations
	// are irrevocable: failed/unused reservations are not refunded.
	//
	// Reserve(0) must succeed with a rejecting gate even when the encryption
	// budget is exhausted. Zero reserves no new encryptions; reading, authorized
	// deletion, and namespace creation do not require them.
	//
	// One request is bounded by 2^24. Global lifetime accounting across leases,
	// files, reopens and restores is the provider's responsibility; this partial
	// integration establishes no production accounting guarantee.
	Reserve(n uint32) (spend func() error, err error)
	Release() error
}
