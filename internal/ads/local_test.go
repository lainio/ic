package ads

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestPublishAndReopen(t *testing.T) {
	for _, isRoot := range []bool{false, true} {
		name := "non-Root"
		if isRoot {
			name = "Root"
		}
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			local, root := newSigner(t), newSigner(t)
			if isRoot {
				root = local
			}
			r, owner := root.public, local.public
			keyFile := filepath.Join(t.TempDir(), "storage-key")
			store := try.To1(nodevault.CreateForNode(
				t.Context(), local.dir, keyFile, r, owner))
			t.Cleanup(func() { assert.NoError(store.Close()) })
			if !isRoot {
				try.To(ownEvidence(store.Vault(), root, local, "known"))
			}
			try.To1(
				device.BootstrapLocal(store.Vault(), r, owner, local.handle),
			)
			probe := &observedSigner{Handle: local.handle}
			published := try.To1(PublishLocal(store.Vault(), r, owner,
				probe, "http://localhost:08080/peer/introduction", fixedNow))
			assert.Equal(probe.calls, 2)
			ad := published.Payload
			assert.Equal(ad.Version, uint8(1))
			assert.DeepEqual(ad.Root, r)
			assert.DeepEqual(ad.Node, owner)
			assert.DeepEqual(ad.Device, owner)
			assert.Equal(ad.Slot, uint64(1))
			assert.Equal(ad.Epoch, uint64(0))
			assert.SLen(ad.Token, 32)
			assert.Equal(ad.ExpiresUnixNano, fixedNow.Add(TTL).UnixNano())
			assert.Equal(ad.PeerIntroductionURL, endpoint)
			digest := key.HashTagged(
				SignaturePurpose,
				try.To1(wire.Marshal(ad)),
			)
			assert.That(published.Signature.Verify(owner, digest[:]))
			plainDigest := key.HashTagged(
				"another-purpose",
				try.To1(wire.Marshal(ad)),
			)
			assert.ThatNot(published.Signature.Verify(owner, plainDigest[:]))
			stored := try.To1(records(store.Vault(), currentNamespace))
			assert.DeepEqual(stored[currentNamespace][currentSlot],
				try.To1(wire.Marshal(published)))
			try.To(store.Close())

			store = try.To1(nodevault.OpenForNode(
				t.Context(), local.dir, keyFile, r, owner))
			files := []string{filepath.Join(local.dir, "state", "vault.db"),
				filepath.Join(local.dir, "state", "usage.db"), keyFile,
				filepath.Join(local.dir, "identity.json"), local.unlock}
			before := make([][]byte, len(files))
			for i, path := range files {
				before[i] = try.To1(os.ReadFile(path))
			}
			got, found := try.To2(
				ReadCurrentLocal(store.Vault(), r, owner, fixedNow),
			)
			assert.That(found)
			assert.DeepEqual(got, published)
			assert.DeepEqual(
				try.To1(records(store.Vault(), currentNamespace)),
				stored,
			)
			// Mutating returned slices never changes persisted data or input keys.
			got.Payload.Root[0] ^= 1
			got.Payload.Node[0] ^= 1
			got.Payload.Device[0] ^= 1
			got.Payload.Token[0] ^= 1
			got.Signature[0] ^= 1
			again, found := try.To2(
				ReadCurrentLocal(store.Vault(), r, owner, fixedNow),
			)
			assert.That(found)
			assert.DeepEqual(again, published)
			assert.Equal(probe.calls, 2)
			for i, path := range files {
				assert.DeepEqual(try.To1(os.ReadFile(path)), before[i])
			}
			// Restoring the same signer is explicit, independent of ad reads.
			restored := try.To1(
				nodeidentity.OpenDirectory(local.dir, local.unlock),
			)
			assert.DeepEqual(try.To1(restored.CBORPublicKey()), []byte(owner))
			if isRoot {
				assert.Equal(len(try.To1(records(store.Vault(),
					"introduction-choice-demo", "received-introductions-v1",
					"known-introductions-v1"))), 0)
			}
		})
	}
}

func TestReplacementExpiryAndStateBoundary(t *testing.T) {
	defer assert.PushTester(t)()
	root, local := newSigner(t), newSigner(t)
	r, owner := root.public, local.public
	f := newVault(t)
	try.To(ownEvidence(f.vault, root, local, "known"))
	try.To1(device.BootstrapLocal(f.vault, r, owner, local.handle))
	names := []string{"introduction-choice-demo", "received-introductions-v1",
		"known-introductions-v1", "local-device-auth-v1"}
	for _, name := range []string{"trust", "pw", "deny", "unrelated",
		"received-ads", "verified-ads", "recovery"} {
		try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			ns := try.To1(tx.EnsureChild([]byte(name)))
			return ns.Put([]byte("sentinel"), []byte("unchanged"))
		}))
		names = append(names, name)
	}
	before := try.To1(records(f.vault, names...))
	remaining := f.lease.remaining
	first := try.To1(
		PublishLocal(f.vault, r, owner, local.handle, endpoint, fixedNow),
	)
	second := try.To1(
		PublishLocal(f.vault, r, owner, local.handle, endpoint, fixedNow),
	)
	assert.Equal(
		f.lease.remaining,
		remaining-2,
	) // Exactly one seal per publication.
	assert.ThatNot(bytes.Equal(first.Payload.Token, second.Payload.Token))
	assert.ThatNot(bytes.Equal(first.Signature, second.Signature))
	digest := key.HashTagged(
		SignaturePurpose,
		try.To1(wire.Marshal(first.Payload)),
	)
	assert.That(
		first.Signature.Verify(owner, digest[:]),
	) // Authentic but superseded.
	got, found := try.To2(ReadCurrentLocal(f.vault, r, owner, fixedNow))
	assert.That(found)
	assert.DeepEqual(got, second)
	assert.DeepEqual(try.To1(records(f.vault, names...)), before)
	stored := try.To1(records(f.vault, currentNamespace))
	expiry := time.Unix(0, second.Payload.ExpiresUnixNano)
	f.unchanged(t, func() {
		for _, tc := range []struct {
			now   time.Time
			found bool
		}{
			{expiry.Add(-time.Nanosecond), true}, {expiry, false},
			{expiry.Add(time.Hour), false},
		} {
			current, found := try.To2(
				ReadCurrentLocal(f.vault, r, owner, tc.now),
			)
			assert.Equal(found, tc.found)
			if !found {
				assert.DeepEqual(current, Current{})
			}
		}
	})
	assert.DeepEqual(try.To1(records(f.vault, currentNamespace)), stored)
	third := try.To1(
		PublishLocal(f.vault, r, owner, local.handle, endpoint, expiry),
	)
	assert.Equal(third.Payload.ExpiresUnixNano, expiry.Add(TTL).UnixNano())
	assert.ThatNot(bytes.Equal(third.Payload.Token, second.Payload.Token))
	assert.DeepEqual(try.To1(records(f.vault, names...)), before)
}

func TestEndpointNormalization(t *testing.T) {
	defer assert.PushTester(t)()
	local := newSigner(t)
	f := newVault(t)
	r := local.public
	try.To1(device.BootstrapLocal(f.vault, r, r, local.handle))
	for _, tc := range []struct{ input, normalized string }{
		{endpoint, endpoint},
		{"http://localhost:08080/peer/introduction", endpoint},
		{"http://[0:0:0:0:0:0:0:1]:00001/peer/introduction",
			"http://[::1]:1/peer/introduction"},
		{"http://127.8.9.10:65535/peer/introduction",
			"http://127.8.9.10:65535/peer/introduction"},
	} {
		got := try.To1(
			PublishLocal(f.vault, r, r, local.handle, tc.input, fixedNow),
		)
		assert.Equal(got.Payload.PeerIntroductionURL, tc.normalized)
	}
}
