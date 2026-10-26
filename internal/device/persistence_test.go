package device

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestAuthorizationSurvivesReopenButUsabilityNeedsSigner(t *testing.T) {
	defer assert.PushTester(t)()

	local := newSavedSigner(t)
	r := local.public
	keyFile := filepath.Join(t.TempDir(), "storage-key")
	store := try.To1(nodevault.CreateForNode(t.Context(), local.dir, keyFile, r, r))
	t.Cleanup(func() { assert.NoError(store.Close()) })
	material := try.To1(local.material())
	storageKey := try.To1(os.ReadFile(keyFile))
	assert.Equal(try.To1(InspectLocal(store.Vault(), r, r, nil)), Local{})
	assert.Equal(try.To1(BootstrapLocal(store.Vault(), r, r, local.handle)), Local{true, true})
	authorization := try.To1(namespaceRecords(store.Vault(), authNamespace))
	try.To(store.Close())
	local.handle = nil

	// Nodevault enforces the independently configured binding when opening.
	foreign := newSavedSigner(t)
	for _, binding := range [][2][]byte{{foreign.public, r}, {r, foreign.public}} {
		rejected, err := nodevault.OpenForNode(t.Context(), local.dir, keyFile, binding[0], binding[1])
		assert.Error(err)
		assert.Nil(rejected)
	}
	store = try.To1(nodevault.OpenForNode(t.Context(), local.dir, keyFile, r, r))
	statePath := filepath.Join(local.dir, "state", "vault.db")
	before := try.To1(os.ReadFile(statePath))
	usagePath := filepath.Join(local.dir, "state", "usage.db")
	usageBefore := try.To1(os.ReadFile(usagePath))
	assert.Equal(try.To1(InspectLocal(store.Vault(), r, r, nil)), Local{true, false})
	assert.Equal(try.To1(InspectLocal(store.Vault(), r, r, foreign.handle)), Local{true, false})
	failed := &probeSigner{Handle: foreign.handle, public: r}
	assert.Equal(try.To1(InspectLocal(store.Vault(), r, r, failed)), Local{true, false})
	restored := try.To1(nodeidentity.OpenDirectory(local.dir, local.unlock))
	assert.DeepEqual(try.To1(restored.CBORPublicKey()), []byte(r))
	assert.Equal(try.To1(InspectLocal(store.Vault(), r, r, restored)), Local{true, true})
	_, err := BootstrapLocal(store.Vault(), r, r, restored)
	assert.ErrorIs(err, ErrAlreadyAuthorized)
	assert.DeepEqual(try.To1(namespaceRecords(store.Vault(), authNamespace)), authorization)
	assert.DeepEqual(try.To1(os.ReadFile(statePath)), before)
	assert.DeepEqual(try.To1(os.ReadFile(usagePath)), usageBefore)
	assert.DeepEqual(try.To1(local.material()), material)
	assert.DeepEqual(try.To1(os.ReadFile(keyFile)), storageKey)
}

func TestInvalidAuthorizationFailsClosed(t *testing.T) {
	defer assert.PushTester(t)()
	local := newSavedSigner(t)
	r := local.public
	for _, scenario := range []string{
		"empty", "version", "owner", "root", "truncated", "trailing",
		"other device", "extra device", "empty namespace", "namespace is record", "device is namespace",
	} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newVault(t)
			binding := try.To1(authorizationBinding(f.vault, r, r))
			try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				if scenario == "namespace is record" {
					return tx.Put([]byte(authNamespace), binding)
				}
				ns := try.To1(tx.EnsureChild([]byte(authNamespace)))
				switch scenario {
				case "empty namespace":
					return nil
				case "device is namespace":
					try.To1(ns.EnsureChild([]byte(localDevice)))
					return nil
				case "other device":
					return ns.Put([]byte("other-device"), binding)
				case "extra device":
					try.To(ns.Put([]byte("other-device"), binding))
				case "empty":
					binding = nil
				case "version":
					binding[0] = 2
				case "owner":
					binding[len(binding)-1] ^= 1
				case "root":
					binding[len(binding)-len(r)-1] ^= 1
				case "truncated":
					binding = binding[:len(binding)-1]
				case "trailing":
					binding = append(binding, 0)
				}
				return ns.Put([]byte(localDevice), binding)
			}))
			f.provider.remaining.Store(0)
			probe := &probeSigner{Handle: local.handle}
			f.readOnly(t, func() {
				state, err := InspectLocal(f.vault, r, r, probe)
				assert.Error(err)
				assert.ErrorIsNot(err, storage.ErrKeyUsageExhausted)
				assert.Equal(state, Local{})
				state, err = BootstrapLocal(f.vault, r, r, probe)
				assert.Error(err)
				assert.ErrorIsNot(err, storage.ErrKeyUsageExhausted)
				assert.Equal(state, Local{})
			})
			assert.SLen(probe.probes, 0)
		})
	}
}

func TestExhaustedEncryptionLeavesNoPartialAuthorization(t *testing.T) {
	defer assert.PushTester(t)()

	local := newSavedSigner(t)
	f := newVault(t)
	f.provider.remaining.Store(0)
	probe := &probeSigner{Handle: local.handle}
	f.readOnly(t, func() {
		state, err := BootstrapLocal(f.vault, local.public, local.public, probe)
		assert.ErrorIs(err, storage.ErrKeyUsageExhausted)
		assert.Equal(state, Local{})
		assert.Equal(try.To1(InspectLocal(f.vault, local.public, local.public, probe)), Local{})
		assert.Equal(len(try.To1(namespaceRecords(f.vault, authNamespace))), 0)
	})
	assert.SLen(probe.probes, 1) // Probe succeeded; the atomic write failed.
}

func TestBootstrapRejectsInvalidKnownEvidence(t *testing.T) {
	defer assert.PushTester(t)()
	root, local := newSavedSigner(t), newSavedSigner(t)
	r, owner := root.public, local.public
	for _, scenario := range []string{"marker", "received", "wrong root"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newVault(t)
			path := intro.New(key.Info{Public: r}).Introduce(root.handle, key.Info{Public: owner})
			try.To2(onboarding.SaveIntroduction(f.vault, r, path.Bytes(),
				try.To1(path.SignAcceptance(local.handle))))
			try.To1(onboarding.VerifyReceived(f.vault, r))
			expectedRoot := bytes.Clone(r)
			if scenario == "wrong root" {
				expectedRoot[0] ^= 1
			} else {
				try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					name := "known-introductions-v1"
					if scenario == "received" {
						name = "received-introductions-v1"
					}
					ns := try.To1(tx.ChildForUpdate([]byte(name)))
					return ns.Put(owner, []byte("corrupt"))
				}))
			}
			probe := &probeSigner{Handle: local.handle}
			f.readOnly(t, func() {
				state, err := BootstrapLocal(f.vault, expectedRoot, owner, probe)
				assert.Error(err)
				assert.Equal(state, Local{})
			})
			assert.SLen(probe.probes, 0)
		})
	}
}
