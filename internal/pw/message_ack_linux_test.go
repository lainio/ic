package pw

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestMessageACKBackendCommitFailure(t *testing.T) {
	defer assert.PushTester(t)()
	for sender := range 2 {
		f, n, _, receipt := ackTest(t, sender)
		before := outgoingTestState(t, n.own.vault)
		disk := try.To1(os.ReadFile(n.own.path))
		remaining := n.own.lease.remaining.Load()
		n.other.unchanged(t, func() {
			restore := readOnlyVaultDescriptor(t, n.own.path)
			saved, err := observeMessageReceipt(n.own.vault, f.root.public,
				n.local, receipt)
			restore()
			assert.Equal(err, errMessageACK)
			assert.ThatNot(saved)
		})
		assert.Equal(n.own.lease.remaining.Load(), remaining-1) // No retry.
		assert.DeepEqual(try.To1(os.ReadFile(n.own.path)), disk)
		assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
		n.own.reopen(t)
		assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
	}
}

func TestMessageACKRepeatReadOnlyBackend(t *testing.T) {
	defer assert.PushTester(t)()
	for sender := range 2 {
		f, n, envelope, receipt := ackTest(t, sender)
		receiver := outgoingTestNodes(f)[1-sender]
		second := try.To1(issueMessageReceipt(n.other.vault, f.root.public,
			n.peer, receiver.signer, envelope))
		assert.ThatNot(bytes.Equal(receipt, second))
		assert.That(try.To1(observeMessageReceipt(n.own.vault, f.root.public,
			n.local, receipt)))
		before := outgoingTestState(t, n.own.vault)
		n.own.lease.remaining.Store(0)
		restore := readOnlyVaultDescriptor(t, n.own.path)
		n.other.unchanged(t, func() {
			n.own.unchanged(t, func() {
				for _, raw := range [][]byte{receipt, second} {
					assert.ThatNot(try.To1(observeMessageReceipt(n.own.vault,
						f.root.public, n.local, raw)))
				}
			})
		})
		restore()
		assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
	}
}

// Test-only metadata in a temporary 0600 file. Reopening observation needs no
// signer directory, unlock credential or peer Vault location.
type ackReopenFixture struct {
	_           struct{} `cbor:",toarray"`
	Path        string
	Secret      []byte
	Root, Local key.Public
	Receipt     []byte
}

func TestMessageACKProcessReopen(t *testing.T) {
	defer assert.PushTester(t)()
	const fixtureEnv = "PW_ACK_REOPEN_FIXTURE"
	if path := os.Getenv(fixtureEnv); path != "" {
		var saved ackReopenFixture
		try.To(wire.UnmarshalCanonical(&saved, try.To1(os.ReadFile(path))))
		defer clear(saved.Secret)
		lease := &testLease{secret: saved.Secret} // Zero seal allowance.
		db := try.To1(storage.OpenBolt(saved.Path))
		defer func() { assert.NoError(db.Close()) }()
		vault := try.To1(db.OpenVault(t.Context(), storage.VaultID{1},
			storage.KeyID{7}, lease))
		fixture := vaultFixture{vault: vault, db: db, lease: lease,
			path: saved.Path}
		before := outgoingTestState(t, vault)
		fixture.unchanged(t, func() {
			assert.ThatNot(try.To1(observeMessageReceipt(vault, saved.Root,
				saved.Local, saved.Receipt)))
		})
		assert.DeepEqual(outgoingTestState(t, vault), before)
		return
	}
	for sender := range 2 {
		f, n, _, receipt := ackTest(t, sender)
		guard := "deny"
		if sender == 1 {
			guard = "delete"
		}
		try.To(mutateEnvelopeGuard(n, f.root.public, guard))
		// Discard the original result. Only a later explicit observation in a
		// new process can establish that the historical ACK was committed.
		try.To1(observeMessageReceipt(n.own.vault, f.root.public,
			n.local, receipt))
		before, other := outgoingTestState(t, n.own.vault),
			outgoingTestState(t, n.other.vault)
		metadata := try.To1(wire.Marshal(ackReopenFixture{
			Path: n.own.path, Secret: bytes.Clone(n.own.lease.secret),
			Root: f.root.public, Local: n.local, Receipt: receipt,
		}))
		path := filepath.Join(t.TempDir(), "reopen.cbor")
		try.To(os.WriteFile(path, metadata, 0600))
		clear(metadata)
		try.To(n.own.db.Close())
		n.other.unchanged(t, func() {
			// OpenBolt initializes buckets with its existing Update. The child
			// checks disk identity after opening; snapshots span the restart.
			cmd := exec.CommandContext(t.Context(), try.To1(os.Executable()),
				"-test.run=^TestMessageACKProcessReopen$", "-test.count=1",
				"-test.timeout=30s")
			cmd.Env = append(os.Environ(), fixtureEnv+"="+path)
			assert.NoError(cmd.Run(), "ACK reopen subprocess failed")
		})
		n.own.reopen(t)
		assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
		assert.DeepEqual(outgoingTestState(t, n.other.vault), other)
	}
}
