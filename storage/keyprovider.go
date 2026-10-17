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
// Methods must terminate and must not reenter storage. Acquire, Secret and
// Release run outside storage admission gates and engine transactions; Check
// may run under the admission gate, but never under an engine lock.
// ConsumeEncryption is the narrowly allowed local accounting call inside an
// engine transaction, immediately before sealing.
type Lease interface {
	// Secret returns the borrowed 32-byte secret for deriving storage keys.
	Secret() []byte
	// Check synchronizes authorization and availability checks. Revocation is
	// observed at admission; already admitted work is allowed to finish.
	Check() error
	// ConsumeEncryption atomically debits one permitted encryption for the actual
	// derived key, returning nil only after success. All leases using that key,
	// including across Database instances, must share accounting. Acquire,
	// OpenVault, Close and Release must neither allocate nor reset the counter.
	//
	// This call performs only short, synchronized in-process accounting while an
	// engine transaction is active: no disk/network I/O, replenishment, storage
	// reentry, or authorization recheck. Already admitted work may finish.
	// Successful consumption is never refunded after failed encryption, rollback,
	// write failure, or Close. Opening and reading consume nothing; exhaustion
	// does not deny authorized reads, deletes, or namespace creation.
	//
	// Sound actual-key accounting is the provider's responsibility. This package
	// supplies no production durable accounting across restarts, copies or
	// restores.
	// See docs/architecture/managed-storage-current-system.md,
	// "Core concepts" and "Encryption usage walkthrough".
	ConsumeEncryption() error
	Release() error
}
