package storage_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/storage"
)

func ExampleVault() {
	dir := try.To1(os.MkdirTemp("", "vault-example-"))
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "vault.db")

	// `consumerProvider` in `vault_consumer_test.go` is a finite, test-only
	// fixture. Its `Check` and `Release` are simplified: no durable accounting,
	// revocation service, or production key custody is provided.
	p := &consumerProvider{
		vault:     storage.VaultID{1},
		id:        storage.KeyID{7},
		secret:    make([]byte, 32),
		remaining: 2, // One seal for the manifest and one for the data record.
	}
	defer clear(p.secret) // Runs after database cleanup, including on failure.
	try.To1(rand.Read(p.secret))

	ctx := context.Background()
	db := try.To1(storage.OpenBolt(path))
	defer func() { _ = db.Close() }()
	try.To(db.CreateVault(ctx, p.vault, p.id, p))
	vault := try.To1(db.UnlockVault(ctx, p.vault, p.id, p, 1))

	try.To(vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		notes := try.To1(tx.EnsureChild([]byte("notes")))
		return notes.Put([]byte("greeting"), []byte("hello"))
	}))
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		defer assert.PushAsserter(assert.Plain)()
		notes := try.To1(tx.Child([]byte("notes")))
		value, found := try.To2(notes.Get([]byte("greeting")))
		assert.That(found, errors.New("greeting missing before close"))
		try.To1(fmt.Printf("before close: %s\n", value))
		return nil
	}))

	try.To(vault.Lock())
	try.To(db.Close())

	// Reopen the same file within this process, keeping the provider and secret.
	// Reading needs no new seals, even though the allowance is exhausted.
	reopened := try.To1(storage.OpenBolt(path))
	defer func() { _ = reopened.Close() }()
	reopenedVault := try.To1(reopened.UnlockVault(ctx, p.vault, p.id, p, 0))
	try.To(reopenedVault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		defer assert.PushAsserter(assert.Plain)()
		notes := try.To1(tx.Child([]byte("notes")))
		value, found := try.To2(notes.Get([]byte("greeting")))
		assert.That(found, errors.New("greeting missing after reopen"))
		try.To1(fmt.Printf("after reopen: %s\n", value))
		return nil
	}))
	try.To(reopenedVault.Lock())
	try.To(reopened.Close())

	// Output:
	// before close: hello
	// after reopen: hello
}
