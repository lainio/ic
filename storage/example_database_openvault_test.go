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

func ExampleDatabase_OpenVault() {
	defer err2.Catch(err2.Stdout)

	dir := try.To1(os.MkdirTemp("", "vault-example-"))
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "vault.db")

	// consumerProvider in vault_consumer_test.go serves one vault ID and key
	// version. These IDs are not secrets, and the key ID is not a cipher selector.
	// Its finite accounting is a test fixture, not a production guarantee;
	// Check and Release provide no revocation service or production key custody.
	// See docs/architecture/managed-storage-current-system.md,
	// "Core concepts" and "Encryption usage walkthrough".
	const writeCount = 3 // Playground: change the workload here.
	p := newConsumerProvider(
		storage.VaultID{1}, // ID of the vault this provider serves.
		storage.KeyID{7},   // ID of the key version.
		make([]byte, 32),   // Filled with random bytes below.
	)
	defer clear(p.secret) // Runs after database cleanup, including on failure.
	// Storage derives its keys from these 32 random bytes. Keep this secret
	// alive across file reopening below; the file does not supply it.
	try.To1(rand.Read(p.secret))

	ctx := context.Background()
	db := try.To1(storage.OpenBolt(path))
	defer func() { _ = db.Close() }()
	// Creating the encrypted identity record consumes one encryption.
	try.To(db.CreateVault(ctx, p.vault, p.id, p))
	// Opening consumes nothing; each Put consumes one shared encryption.
	vault := try.To1(db.OpenVault(ctx, p.vault, p.id, p))

	for range writeCount { // Each iteration changes workload only.
		try.To(vault.Update(func(tx storage.WriteTx) (err error) {
			defer err2.Handle(&err, "writing greeting")
			notes := try.To1(tx.EnsureChild([]byte("notes")))
			return notes.Put([]byte("greeting"), []byte("hello"))
		}))
	}
	for i := range 4 { // Playground: adjust the read workload.
		try.To(vault.View(func(tx storage.ReadTx) (err error) {
			defer err2.Handle(&err, "reading greeting")
			notes := try.To1(tx.Child([]byte("notes")))
			value, found := try.To2(notes.Get([]byte("greeting")))
			assert.That(found, "greeting missing before close")
			if i == 0 {
				try.To1(fmt.Printf("before close: %s\n", value))
			}
			return nil
		}))
	}

	try.To(vault.Close()) // End this handle's access; keep the stored records.
	try.To(db.Close())

	// Reopen the same file within this process, keeping the provider and secret.
	// Opening and reading leave the shared encryption counter unchanged.
	// Authorized deletion and namespace creation also need no new encryption.
	reopened := try.To1(storage.OpenBolt(path))
	defer func() { _ = reopened.Close() }()
	reopenedVault := try.T1(reopened.OpenVault(ctx, p.vault, p.id, p))("reopening vault")
	for i := range 4 { // Playground: adjust the read workload.
		try.T(reopenedVault.View(func(tx storage.ReadTx) (err error) {
			defer err2.Handle(&err, "reading greeting")
			notes := try.To1(tx.Child([]byte("notes")))
			value, found := try.To2(notes.Get([]byte("greeting")))
			assert.That(found, "greeting missing after reopen")
			if i == 0 {
				try.To1(fmt.Printf("after reopen: %s\n", value))
			}
			return nil
		}))("weird if fails")
	}
	try.To(reopenedVault.Close())
	try.To(reopened.Close())

	// Output:
	// before close: hello
	// after reopen: hello
}
