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

func TestMessageACKBackendFailureAndExplicitRetryV2(t *testing.T) {
	defer assert.PushTester(t)()
	for sender := range 2 {
		f, n, _, receipt := ackTestV2(t, sender)
		before := outgoingTestState(t, n.own.vault)
		disk := try.To1(os.ReadFile(n.own.path))
		remaining := n.own.lease.remaining.Load()
		n.other.unchanged(t, func() {
			restore := readOnlyVaultDescriptor(t, n.own.path)
			saved, err := ObserveMessageReceiptV2(n.own.vault, f.root.public,
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
		n.own.lease.remaining.Store(1)
		n.other.unchanged(t, func() {
			assert.That(try.To1(ObserveMessageReceiptV2(n.own.vault,
				f.root.public, n.local, receipt)))
		})
		assert.Equal(n.own.lease.remaining.Load(), 0)
		before["root"][messageACKKey] = try.To1(wire.Marshal(messageACK{
			Version: 2, Receipt: receipt,
		}))
		assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
	}
}

func TestMessageACKAndInboxReadOnlyBackendV2(t *testing.T) {
	defer assert.PushTester(t)()
	for sender := range 2 {
		f, n, envelope, receipt := ackTestV2(t, sender)
		receiver := outgoingTestNodes(f.requesterFixture)[1-sender]
		second := try.To1(IssueMessageReceiptV2(n.other.vault, f.root.public,
			n.peer, receiver.signer, f.messageRuntime(receiver), envelope))
		assert.ThatNot(bytes.Equal(receipt, second))
		assert.That(try.To1(ObserveMessageReceiptV2(n.own.vault, f.root.public,
			n.local, receipt)))
		want := try.To1(
			ReadMessageInboxV2(n.other.vault, f.root.public, n.peer),
		)
		n.own.lease.remaining.Store(0)
		n.other.lease.remaining.Store(0)
		restoreSender := readOnlyVaultDescriptor(t, n.own.path)
		restoreReceiver := readOnlyVaultDescriptor(t, n.other.path)
		n.other.unchanged(t, func() {
			n.own.unchanged(t, func() {
				for _, raw := range [][]byte{receipt, second} {
					assert.ThatNot(try.To1(ObserveMessageReceiptV2(n.own.vault,
						f.root.public, n.local, raw)))
				}
				assert.DeepEqual(try.To1(ReadMessageInboxV2(n.other.vault,
					f.root.public, n.peer)), want)
			})
		})
		restoreReceiver()
		restoreSender()
	}
}

// Only this node's encrypted Vault and test lease cross the process boundary.
// No signer directory, runtime, listener, remote Vault or unlock path is passed.
type projectionReopenFixtureV2 struct {
	_           struct{} `cbor:",toarray"`
	Path        string
	Secret      []byte
	Root, Local key.Public
	Receipt     []byte
	Inbox       MessageInbox
}

func TestMessageProjectionProcessReopenV2(t *testing.T) {
	defer assert.PushTester(t)()
	const fixtureEnv = "PW_PROJECTION_V2_REOPEN_FIXTURE"
	if path := os.Getenv(fixtureEnv); path != "" {
		var saved projectionReopenFixtureV2
		try.To(wire.UnmarshalCanonical(&saved, try.To1(os.ReadFile(path))))
		defer clear(saved.Secret)
		lease := &testLease{secret: saved.Secret}
		db := try.To1(storage.OpenBolt(saved.Path))
		defer func() { assert.NoError(db.Close()) }()
		vault := try.To1(db.OpenVault(t.Context(), storage.VaultID{1},
			storage.KeyID{7}, lease))
		fixture := vaultFixture{vault: vault, db: db, lease: lease,
			path: saved.Path}
		fixture.unchanged(t, func() {
			assert.ThatNot(try.To1(ObserveMessageReceiptV2(vault, saved.Root,
				saved.Local, saved.Receipt)))
			assert.DeepEqual(try.To1(ReadMessageInboxV2(vault, saved.Root,
				saved.Local)), saved.Inbox)
		})
		return
	}
	for sender := range 2 {
		for _, guard := range []string{"deny", "delete"} {
			f, n, _, receipt := ackTestV2(t, sender)
			peer := outgoingTestNodes(f.requesterFixture)[1-sender]
			try.To1(CreateOutgoingV2(peer.own.vault, f.root.public, peer.local,
				peer.signer, f.messageRuntime(peer), "process retained text"))
			reverse := try.To1(PrepareOutgoingEnvelopeV2(peer.own.vault,
				f.root.public, peer.local, peer.signer, f.messageRuntime(peer)))
			try.To1(AcceptMessageAndReceiptV2(n.own.vault, f.root.public,
				n.local, n.signer, f.messageRuntime(n), reverse))
			try.To(mutateEnvelopeGuard(n, f.root.public, guard))
			// Drop the first outcome; the child explicitly observes committed
			// history with a zero-seal lease after process restart.
			try.To1(ObserveMessageReceiptV2(n.own.vault, f.root.public,
				n.local, receipt))
			want := try.To1(
				ReadMessageInboxV2(n.own.vault, f.root.public, n.local),
			)
			before := outgoingTestState(t, n.own.vault)
			other := outgoingTestState(t, n.other.vault)
			metadata := try.To1(wire.Marshal(projectionReopenFixtureV2{
				Path: n.own.path, Secret: bytes.Clone(n.own.lease.secret),
				Root: f.root.public, Local: n.local, Receipt: receipt, Inbox: want,
			}))
			path := filepath.Join(t.TempDir(), "reopen.cbor")
			try.To(os.WriteFile(path, metadata, 0600))
			clear(metadata)
			try.To(n.own.db.Close())
			try.To(n.other.db.Close())
			n.other.unchanged(t, func() {
				// OpenBolt performs its existing initialization Update. The child
				// compares disk bytes after opening; snapshots span the restart.
				cmd := exec.CommandContext(
					t.Context(),
					try.To1(os.Executable()),
					"-test.run=^TestMessageProjectionProcessReopenV2$",
					"-test.count=1",
					"-test.timeout=30s",
				)
				cmd.Env = append(os.Environ(), fixtureEnv+"="+path)
				assert.NoError(cmd.Run(), "projection reopen subprocess failed")
			})
			n.own.reopen(t)
			n.other.reopen(t)
			assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
			assert.DeepEqual(outgoingTestState(t, n.other.vault), other)
		}
	}
}
