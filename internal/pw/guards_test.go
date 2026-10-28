package pw

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
)

func TestInputAdmissionBeforeSignerUse(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	probe := &probeSigner{Handle: s.local.handle}
	bad := []key.Public{
		nil, {}, {0xff}, {0xa0}, make([]byte, 129),
		append(bytes.Clone(s.peer.public), 0),
		append([]byte{0xb8, 5}, s.peer.public[1:]...), // Noncanonical map length.
	}
	for _, field := range []int{1, 3, -1, -2, -3} {
		var fields map[int]any
		try.To(wire.Unmarshal(&fields, s.peer.public))
		fields[field] = int64(0)
		if field < -1 {
			fields[field] = make([]byte, 32) // Off-curve coordinates.
		}
		bad = append(bad, try.To1(wire.Marshal(fields)))
	}
	s.f.unchanged(t, func() {
		assert.Equal(CheckLocalAcceptor(nil, s.root.public, s.local.public, s.peer.public, probe), ErrInvalidInput)
		assert.Equal(CheckLocalAcceptor(s.f.vault, s.root.public, s.local.public,
			bytes.Clone(s.local.public), probe), ErrInvalidInput)
		for _, public := range bad {
			assert.Equal(CheckLocalAcceptor(s.f.vault, public, s.local.public, s.peer.public, probe), ErrInvalidInput)
			assert.Equal(CheckLocalAcceptor(s.f.vault, s.root.public, public, s.peer.public, probe), ErrInvalidInput)
			assert.Equal(CheckLocalAcceptor(s.f.vault, s.root.public, s.local.public, public, probe), ErrInvalidInput)
		}
	})
	assert.Equal(probe.publicCalls.Load(), int64(0))
	// Canonical COSE public keys share a prefix; equality must use every byte.
	assert.That(bytes.Equal(s.local.public[:5], s.peer.public[:5]))
	s.check(t, probe, nil)
}

func TestBindingAndStorageErrorsNeverSignOrRepair(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	probe := &probeSigner{Handle: s.local.handle}
	s.f.unchanged(t, func() {
		// Valid public encodings, but foreign Root and reader configurations.
		assert.Equal(CheckLocalAcceptor(s.f.vault, s.peer.public, s.local.public,
			s.root.public, probe), ErrLocalState)
		assert.Equal(CheckLocalAcceptor(s.f.vault, s.root.public, s.peer.public,
			s.local.public, probe), ErrLocalState)
	})
	putRecord(t, s.f.vault, authNS, []byte(authKey), []byte("corrupt authorization"))
	s.check(t, probe, ErrLocalState)
	assert.Equal(probe.publicCalls.Load(), int64(0))
	s.f.reopen(t)
	s.check(t, probe, ErrLocalState)
	try.To(s.f.vault.Close())
	s.check(t, probe, ErrLocalState)
	assert.Equal(probe.publicCalls.Load(), int64(0))
}

func TestProviderDiagnosticsAndInputNeverEscape(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	var trace bytes.Buffer
	previousError, previousReturn := err2.ErrorTracer(), err2.ErrRetTracer()
	err2.SetErrorTracer(&trace)
	err2.SetErrRetTracer(&trace)
	defer func() { err2.SetErrorTracer(previousError); err2.SetErrRetTracer(previousReturn) }()
	const secret = "PRIVATE_PROVIDER_OR_INPUT_DATA"
	for _, probe := range []*probeSigner{
		{Handle: s.local.handle, publicErr: errors.New(secret)},
		{Handle: s.local.handle, signErr: errors.New(secret)},
	} {
		s.check(t, probe, ErrUnusableSigner)
	}
	bad := try.To1(wire.Marshal(map[string]string{secret: secret}))
	s.f.unchanged(t, func() {
		assert.Equal(CheckLocalAcceptor(s.f.vault, s.root.public, s.local.public,
			bad, s.local.handle), ErrInvalidInput)
	})
	assert.ThatNot(strings.Contains(trace.String(), secret))
}

func TestInputsOwnedAcrossSignerCallback(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	root, local, peer := bytes.Clone(s.root.public), bytes.Clone(s.local.public), bytes.Clone(s.peer.public)
	probe := &probeSigner{Handle: s.local.handle, sign: func(data []byte) ([]byte, error) {
		clear(root)
		clear(local)
		clear(peer)
		return s.local.handle.Sign(data)
	}}
	s.f.unchanged(t, func() {
		assert.NoError(CheckLocalAcceptor(s.f.vault, root, local, peer, probe))
	})
	// The function used owned snapshots; the independent configuration and
	// stored evidence are still valid after the caller changed its own slices.
	s.check(t, s.local.handle, nil)
}

func TestBoundVaultReopenRequiresIndependentRootAndReader(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	keyFile := filepath.Join(t.TempDir(), "storage-key")
	store := try.To1(nodevault.CreateForNode(t.Context(), s.local.dir, keyFile,
		s.root.public, s.local.public))
	t.Cleanup(func() { assert.NoError(store.Close()) })
	// Copy genuine evidence/authorization into the production-bound fixture.
	for _, subject := range []key.Public{s.local.public, s.peer.public} {
		for _, name := range []string{receivedNS, knownNS} {
			putRecord(t, store.Vault(), name, subject, readRecord(t, s.f.vault, name, subject))
		}
	}
	putRecord(t, store.Vault(), authNS, []byte(authKey), readRecord(t, s.f.vault, authNS, []byte(authKey)))
	try.To(store.Close())
	for _, binding := range [][2]key.Public{
		{s.peer.public, s.local.public}, {s.root.public, s.peer.public},
	} {
		rejected, err := nodevault.OpenForNode(t.Context(), s.local.dir, keyFile, binding[0], binding[1])
		assert.Error(err)
		assert.Nil(rejected)
	}
	store = try.To1(nodevault.OpenForNode(t.Context(), s.local.dir, keyFile, s.root.public, s.local.public))
	handle := try.To1(nodeidentity.OpenDirectory(s.local.dir, s.local.unlock))
	statePath, usagePath := filepath.Join(s.local.dir, "state", "vault.db"), filepath.Join(s.local.dir, "state", "usage.db")
	state, usage := try.To1(os.ReadFile(statePath)), try.To1(os.ReadFile(usagePath))
	assert.Equal(CheckLocalAcceptor(store.Vault(), s.root.public, s.local.public, s.peer.public, nil), ErrUnusableSigner)
	assert.NoError(CheckLocalAcceptor(store.Vault(), s.root.public, s.local.public, s.peer.public, handle))
	assert.DeepEqual(try.To1(os.ReadFile(statePath)), state)
	assert.DeepEqual(try.To1(os.ReadFile(usagePath)), usage)
	assert.SLen(try.To1(onboarding.ListKnownIntroductions(store.Vault(), s.root.public)), 2)
}
