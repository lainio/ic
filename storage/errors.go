package storage

import (
	"errors"

	"github.com/lainio/ic/storage/internal/engine"
)

var (
	ErrClosed = errors.New("storage: database closed")
	// ErrVaultClosed indicates that this Vault handle no longer accepts operations.
	ErrVaultClosed = errors.New("storage: vault handle closed")
	// ErrTxClosed indicates that the transaction callback has ended.
	ErrTxClosed = engine.ErrTxClosed
	// Namespace classifications preserve the engine's sentinel identity.
	ErrEmptyName         = engine.ErrEmptyName
	ErrNamespaceNotFound = engine.ErrNamespaceNotFound
	ErrConflict          = engine.ErrConflict
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
