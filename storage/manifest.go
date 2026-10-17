package storage

import (
	"errors"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/storage/internal/engine"
	"github.com/lainio/ic/storage/internal/record"
)

var (
	errVaultExists   = errors.New("storage: vault already exists")
	errVaultNotFound = errors.New("storage: vault not found")
	errVaultManifest = errors.New("storage: invalid vault manifest")
)

const (
	vaultCollection = "vaults"
	vaultMetadata   = "\x03"
	manifestKey     = "manifest"
	manifestVersion = 1
	manifestSize    = 1 + 16 + 16
)

// createVaultState requires a database-root Update and a live Scope derived for
// the SAME externally expected vault/id, with shared local encryption accounting
// (no provider I/O). The trusted caller establishes this pairing; these
// helpers neither discover nor authorize keys. CreateVault and OpenVault pair
// them from authorized external inputs.
//
// The caller owns Scope and must drain its work before Clear. Neither helper
// acquires, releases, or clears it. Callers MUST propagate helper errors into the
// engine callback. This private composition is not a public abort-only Vault API.
// A successful debit remains consumed, including on transaction rollback.
func createVaultState(root engine.WriteTx, scope *record.Scope,
	vault, id [16]byte) (err error) {
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()

	var collection engine.WriteNS
	if try.To1(root.HasChild([]byte(vaultCollection))) {
		collection = try.To1(root.ChildForUpdate([]byte(vaultCollection)))
	} else {
		collection = try.To1(root.EnsureChild([]byte(vaultCollection)))
	}
	assert.ThatNot(try.To1(collection.HasChild(vault[:])), errVaultExists)
	state := try.To1(collection.EnsureChild(vault[:]))
	metadata := try.To1(state.EnsureChild([]byte(vaultMetadata)))
	path, key := [][]byte{[]byte(vaultMetadata)}, []byte(manifestKey)
	token := try.To1(scope.Token(path, key))
	var value [manifestSize]byte
	value[0] = manifestVersion
	copy(value[1:17], vault[:])
	copy(value[17:], id[:])
	envelope := try.To1(scope.Seal(path, key, value[:]))
	return metadata.Put(token[:], envelope)
}

// verifyVaultState requires a database-root transaction and the same trusted
// Scope/expected-ID pairing and ownership as createVaultState. It only reads;
// missing or invalid state is never created, repaired, or adopted. Verification
// spends nothing, including when the shared key budget is exhausted.
func verifyVaultState(root engine.ReadTx, scope *record.Scope,
	vault, id [16]byte) (err error) {
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()

	assert.That(try.To1(root.HasChild([]byte(vaultCollection))), errVaultNotFound)
	collection := try.To1(root.Child([]byte(vaultCollection)))
	assert.That(try.To1(collection.HasChild(vault[:])), errVaultNotFound)
	state := try.To1(collection.Child(vault[:]))
	assert.That(try.To1(state.HasChild([]byte(vaultMetadata))), errVaultManifest)
	metadata := try.To1(state.Child([]byte(vaultMetadata)))
	path, key := [][]byte{[]byte(vaultMetadata)}, []byte(manifestKey)
	token := try.To1(scope.Token(path, key))
	envelope, found := try.To2(metadata.Get(token[:]))
	assert.That(found, errVaultManifest)

	// Only full record verification and payload validation are translated below.
	// Engine errors and operational failures above retain their classifications.
	defer err2.Handle(&err, func(cause error) error {
		if cause == errVaultManifest {
			return cause
		}
		return errors.Join(errVaultManifest, cause)
	})
	_, value := try.To2(scope.Open(path, token, key, envelope))
	assert.SLen(value, manifestSize, errVaultManifest)
	assert.Equal(value[0], byte(manifestVersion), errVaultManifest)
	assert.Equal([16]byte(value[1:17]), vault, errVaultManifest)
	assert.Equal([16]byte(value[17:]), id, errVaultManifest)
	return nil
}
