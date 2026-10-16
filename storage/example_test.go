package storage_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/storage"
)

func ExampleVault() {
	defer err2.Catch(err2.Stdout)

	dir := try.To1(os.MkdirTemp("", "vault-example-"))
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "vault.db")

	// consumerProvider in vault_consumer_test.go serves one vault ID and key
	// version. These IDs are not secrets, and the key ID is not a cipher selector.
	// Its finite accounting is a test fixture, not a production guarantee;
	// Check and Release provide no revocation service or production key custody.
	p := &consumerProvider{
		vault:     storage.VaultID{1}, // ID of the vault this provider serves.
		id:        storage.KeyID{7},   // ID of the key version.
		secret:    make([]byte, 32),   // Filled with random bytes below.
		remaining: 2,                  // Encryptions not yet allocated.
	}
	defer clear(p.secret) // Runs after database cleanup, including on failure.
	// Storage derives its keys from these 32 random bytes. Keep this secret
	// alive across file reopening below; the file does not supply it.
	try.To1(rand.Read(p.secret))

	ctx := context.Background()
	db := try.To1(storage.OpenBolt(path))
	defer func() { _ = db.Close() }()
	// Two encryptions: one for the encrypted identity record (manifest),
	// and one for the greeting. CreateVault reserves and spends the first.
	try.To(db.CreateVault(ctx, p.vault, p.id, p))
	// OpenVault reserves the other; Put below spends it.
	vault := try.To1(db.OpenVault(ctx, p.vault, p.id, p, 1))

	try.To(vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, "writing greeting")
		notes := try.To1(tx.EnsureChild([]byte("notes")))
		return notes.Put([]byte("greeting"), []byte("hello"))
	}))
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, "reading greeting")
		notes := try.To1(tx.Child([]byte("notes")))
		value, found := try.To2(notes.Get([]byte("greeting")))
		assert.That(found, "greeting missing before close")
		try.To1(fmt.Printf("before close: %s\n", value))
		return nil
	}))

	try.To(vault.Close()) // End this handle's access; keep the stored records.
	try.To(db.Close())

	// Reopen the same file within this process, keeping the provider and secret.
	// OpenVault with 0 reserves no new encryptions and still permits reading.
	// Authorized deletion and namespace creation also need no new encryption.
	reopened := try.To1(storage.OpenBolt(path))
	defer func() { _ = reopened.Close() }()
	reopenedVault := try.To1(reopened.OpenVault(ctx, p.vault, p.id, p, 0))
	try.To(reopenedVault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, "reading greeting")
		notes := try.To1(tx.Child([]byte("notes")))
		value, found := try.To2(notes.Get([]byte("greeting")))
		assert.That(found, "greeting missing after reopen")
		try.To1(fmt.Printf("after reopen: %s\n", value))
		return nil
	}))
	try.To(reopenedVault.Close())
	try.To(reopened.Close())

	// Output:
	// before close: hello
	// after reopen: hello
}
