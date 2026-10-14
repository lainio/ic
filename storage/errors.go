package storage

import "errors"

var (
	ErrClosed = errors.New("storage: database closed")
	ErrLocked = errors.New("storage: vault locked")
	// ErrProvider indicates a missing provider or a nil successful lease.
	ErrProvider = errors.New("storage: invalid key provider")
	// ErrAllowance indicates an oversized reservation or a missing spending gate.
	// Providers may also return it for exhausted allowances, preserving causes.
	ErrAllowance = errors.New("storage: invalid or exhausted allowance")

	// Manifest classifications preserve the accepted helpers' sentinel identity.
	ErrVaultExists   = errVaultExists
	ErrVaultNotFound = errVaultNotFound
	ErrVaultManifest = errVaultManifest
)
