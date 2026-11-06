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
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/storage"
)

func TestMessageReceiptReadOnlyBackend(t *testing.T) {
	defer assert.PushTester(t)()
	for _, receiver := range []int{0, 1} {
		f, n, raw, expected := receiptTest(t, receiver)
		before, other := outgoingTestState(t, n.own.vault),
			outgoingTestState(t, n.other.vault)
		n.own.lease.remaining.Store(0)
		restore := readOnlyVaultDescriptor(t, n.own.path)
		n.other.unchanged(t, func() {
			n.own.unchanged(t, func() {
				got := try.To1(issueMessageReceipt(n.own.vault, f.root.public,
					n.local, n.signer, raw))
				try.To1(decodeMessageReceipt(got, raw, expected))
			})
		})
		restore()
		assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
		assert.DeepEqual(outgoingTestState(t, n.other.vault), other)
	}
}

// Test-only metadata in a temporary 0600 file, never command-line secrets.
type messageReceiptReopenFixture struct {
	_        struct{} `cbor:",toarray"`
	Incoming incomingReopenFixture
	Expected outgoingBinding
	Prior    []byte
}

func TestMessageReceiptProcessReopen(t *testing.T) {
	defer assert.PushTester(t)()
	const fixtureEnv = "PW_RECEIPT_REOPEN_FIXTURE"
	if path := os.Getenv(fixtureEnv); path != "" {
		var saved messageReceiptReopenFixture
		try.To(wire.UnmarshalCanonical(&saved, try.To1(os.ReadFile(path))))
		input := saved.Incoming
		defer clear(input.Secret)
		lease := &testLease{secret: input.Secret} // Zero seal allowance.
		db := try.To1(storage.OpenBolt(input.Path))
		defer func() { assert.NoError(db.Close()) }()
		vault := try.To1(db.OpenVault(t.Context(), storage.VaultID{1},
			storage.KeyID{7}, lease))
		signer := try.To1(nodeidentity.OpenDirectory(input.Dir, input.Unlock))
		fixture := vaultFixture{
			vault: vault,
			db:    db,
			lease: lease,
			path:  input.Path,
		}
		before := outgoingTestState(t, vault)
		fixture.unchanged(t, func() {
			got := try.To1(issueMessageReceipt(vault, input.Root, input.Local,
				signer, input.Envelope))
			a := try.To1(
				decodeMessageReceipt(got, input.Envelope, saved.Expected),
			)
			b := try.To1(
				decodeMessageReceipt(
					saved.Prior,
					input.Envelope,
					saved.Expected,
				),
			)
			assert.DeepEqual(a.Payload, b.Payload)
		})
		assert.DeepEqual(outgoingTestState(t, vault), before)
		return
	}
	for _, receiver := range []int{0, 1} {
		f, n, raw, expected := receiptTest(t, receiver)
		prior := try.To1(issueMessageReceipt(n.own.vault, f.root.public,
			n.local, n.signer, raw))
		before, other := outgoingTestState(t, n.own.vault),
			outgoingTestState(t, n.other.vault)
		identity := f.local
		if n.name == "Alice" {
			identity = f.peer
		}
		metadata := try.To1(wire.Marshal(messageReceiptReopenFixture{
			Incoming: incomingReopenFixture{
				Path: n.own.path, Dir: identity.dir, Unlock: identity.unlock,
				Secret: bytes.Clone(n.own.lease.secret), Root: f.root.public,
				Local: n.local, Envelope: raw,
			}, Expected: expected, Prior: prior,
		}))
		path := filepath.Join(t.TempDir(), "reopen.cbor")
		try.To(os.WriteFile(path, metadata, 0600))
		clear(metadata)
		try.To(n.own.db.Close())
		n.other.unchanged(t, func() {
			// OpenBolt initializes buckets with its existing Update. The child
			// checks disk identity AFTER reopening; snapshots cover all records
			// across the process boundary. Receipt issuance itself only reads.
			cmd := exec.CommandContext(t.Context(), try.To1(os.Executable()),
				"-test.run=^TestMessageReceiptProcessReopen$", "-test.count=1",
				"-test.timeout=30s")
			cmd.Env = append(os.Environ(), fixtureEnv+"="+path)
			assert.NoError(cmd.Run(), "receipt reopen subprocess failed")
		})
		n.own.reopen(t)
		assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
		assert.DeepEqual(outgoingTestState(t, n.other.vault), other)
	}
}
