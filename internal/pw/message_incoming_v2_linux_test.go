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
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestIncomingBackendCommitFailureV2(t *testing.T) {
	defer assert.PushTester(t)()
	for _, receiver := range []int{0, 1} {
		f, n, raw := incomingTestV2(t, receiver, "backend failure")
		before := outgoingTestState(t, n.own.vault)
		disk := try.To1(os.ReadFile(n.own.path))
		signer := &probeSigner{Handle: n.signer}
		remaining := n.own.lease.remaining.Load()
		n.other.unchanged(t, func() {
			restore := readOnlyVaultDescriptor(t, n.own.path)
			saved, err := AdmitIncomingEnvelopeV2(n.own.vault, f.root.public,
				n.local, signer, f.messageRuntime(n), raw)
			restore()
			assert.Equal(err, errIncoming)
			assert.ThatNot(saved)
		})
		assert.Equal(signer.signCalls.Load(), 1) // No automatic retry.
		assert.Equal(n.own.lease.remaining.Load(), remaining-1)
		assert.DeepEqual(try.To1(os.ReadFile(n.own.path)), disk)
		assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
		n.own.reopen(t)
		assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
		refuseMessageReceiptV2(t, f, n, n.signer, raw)
	}
}

// Test-only data in a 0600 temporary file, never command-line secrets or logs.
type incomingReopenFixtureV2 struct {
	_                         struct{} `cbor:",toarray"`
	Path, Dir, Unlock, Origin string
	Secret                    []byte
	Root, Local               key.Public
	Envelope                  []byte
}

func TestIncomingProcessReopenV2(t *testing.T) {
	defer assert.PushTester(t)()
	const fixtureEnv = "PW_INCOMING_V2_REOPEN_FIXTURE"
	if path := os.Getenv(fixtureEnv); path != "" {
		var saved incomingReopenFixtureV2
		try.To(wire.UnmarshalCanonical(&saved, try.To1(os.ReadFile(path))))
		defer clear(saved.Secret)
		lease := &testLease{secret: saved.Secret} // Zero seal allowance.
		db := try.To1(storage.OpenBolt(saved.Path))
		defer func() { assert.NoError(db.Close()) }()
		vault := try.To1(db.OpenVault(t.Context(), storage.VaultID{1},
			storage.KeyID{7}, lease))
		signer := try.To1(nodeidentity.OpenDirectory(saved.Dir, saved.Unlock))
		fixture := vaultFixture{
			vault: vault,
			db:    db,
			lease: lease,
			path:  saved.Path,
		}
		fixture.unchanged(t, func() {
			assert.ThatNot(try.To1(AdmitIncomingEnvelopeV2(
				vault,
				saved.Root,
				saved.Local,
				signer,
				ContactRuntimeV2{true, saved.Origin},
				saved.Envelope,
			)))
		})
		return
	}
	for _, receiver := range []int{0, 1} {
		f, n, raw := incomingTestV2(t, receiver, "retained across processes")
		// Drop the local outcome, then let a new process explicitly repeat.
		try.To1(AdmitIncomingEnvelopeV2(n.own.vault, f.root.public,
			n.local, n.signer, f.messageRuntime(n), raw))
		before := outgoingTestState(t, n.own.vault)
		identity := f.local
		if n.name == "Alice" {
			identity = f.peer
		}
		metadata := try.To1(wire.Marshal(incomingReopenFixtureV2{
			Path: n.own.path, Dir: identity.dir, Unlock: identity.unlock,
			Secret: bytes.Clone(n.own.lease.secret), Root: f.root.public,
			Local: n.local, Envelope: raw, Origin: f.messageRuntime(n).BoundOrigin,
		}))
		path := filepath.Join(t.TempDir(), "reopen.cbor")
		try.To(os.WriteFile(path, metadata, 0600))
		clear(metadata)
		try.To(n.own.db.Close())
		n.other.unchanged(t, func() {
			// OpenBolt performs its existing bucket-initialization Update.
			// The child checks disk identity around admission AFTER reopening;
			// the parent checks all logical records across the process boundary.
			cmd := exec.CommandContext(t.Context(), try.To1(os.Executable()),
				"-test.run=^TestIncomingProcessReopenV2$", "-test.count=1",
				"-test.timeout=30s")
			cmd.Env = append(os.Environ(), fixtureEnv+"="+path)
			assert.NoError(cmd.Run(), "reopen subprocess failed")
		})
		n.own.reopen(t)
		assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
	}
}
