package storage_test

import (
	"bytes"
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/storage"
)

func init() {
	// Suppress all the panic and error-handling logging noiee from this
	// package we don't want them especially with the benchmar.
	err2.SetTracers(nil)
}

// One operation opens a bbolt-backed Vault read transaction, finds a child
// namespace, authenticates/decrypts one 1 KiB value and checks its contents.
// The already-open Vault and OS pages are warm. File/key/manifest creation,
// the initial write and cleanup are excluded; each iteration performs Get.
func BenchmarkVaultRead1KiB(b *testing.B) {
	defer assert.PushTester(b)()
	p := newConsumerProvider(
		storage.VaultID{1}, storage.KeyID{7}, make([]byte, 32),
	)
	defer clear(p.secret)
	try.To1(rand.Read(p.secret))
	db := try.To1(storage.OpenBolt(filepath.Join(b.TempDir(), "vault.db")))
	defer func() { assert.NoError(db.Close()) }()
	try.To(db.CreateVault(b.Context(), p.vault, p.id, p))
	vault := try.To1(db.OpenVault(b.Context(), p.vault, p.id, p))
	name, recordKey := []byte("benchmark-records"), []byte("evidence")
	want := bytes.Repeat([]byte{0x5a}, 1024)
	try.To(vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		ns := try.To1(tx.EnsureChild(name))
		return ns.Put(recordKey, want)
	}))
	read := func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		ns := try.To1(tx.Child(name))
		got, found := try.To2(ns.Get(recordKey))
		assert.That(found)
		assert.That(bytes.Equal(got, want))
		return nil
	}
	try.To(vault.View(read))
	remaining := p.remainingEncryptions

	b.ReportAllocs()
	b.SetBytes(int64(len(want)))

	for b.Loop() {
		try.To(vault.View(read))
	}
	b.StopTimer()
	assert.Equal(p.remainingEncryptions, remaining)
}
