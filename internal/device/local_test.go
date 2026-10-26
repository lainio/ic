package device

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestBootstrapRequiresOwnKnownEvidence(t *testing.T) {
	defer assert.PushTester(t)()

	root, local, peer := newSavedSigner(t), newSavedSigner(t), newSavedSigner(t)
	f := newVault(t)
	r, owner := root.public, local.public
	base := intro.New(key.Info{Public: r})
	own := base.Introduce(root.handle, key.Info{Public: owner})
	acceptance := try.To1(onboarding.SignAfterStoredChoice(f.vault, local.handle, r, r, own))
	probe := &probeSigner{Handle: local.handle}
	refused := func() {
		f.readOnly(t, func() {
			state, err := BootstrapLocal(f.vault, r, owner, probe)
			assert.ErrorIs(err, ErrNotKnown)
			assert.Equal(state, Local{})
			assert.Equal(try.To1(InspectLocal(f.vault, r, owner, probe)), Local{})
		})
		assert.SLen(probe.probes, 0)
	}
	refused() // Completed choice alone is not Known.
	other := base.Introduce(root.handle, key.Info{Public: peer.public})
	try.To2(onboarding.SaveIntroduction(f.vault, r, other.Bytes(),
		try.To1(other.SignAcceptance(peer.handle))))
	assert.Equal(try.To1(onboarding.VerifyReceived(f.vault, r)), 1)
	refused() // Another full public key in Known is not this node.
	try.To2(onboarding.SaveIntroduction(f.vault, r, own.Bytes(), acceptance))
	refused() // Own Received evidence still needs explicit promotion.
	assert.Equal(try.To1(onboarding.VerifyReceived(f.vault, r)), 1)

	// Sentinels represent unrelated domains, not new domain schemas.
	untouched := []string{"introduction-choice-demo", "received-introductions-v1", "known-introductions-v1"}
	for _, name := range []string{"trust", "deny", "ads", "pw", "recovery"} {
		try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			ns := try.To1(tx.EnsureChild([]byte(name)))
			return ns.Put([]byte("sentinel"), []byte("unchanged"))
		}))
		untouched = append(untouched, name)
	}
	before := try.To1(namespaceRecords(f.vault, untouched...))
	material := try.To1(local.material())
	remaining := f.provider.remaining.Load()
	assert.Equal(try.To1(BootstrapLocal(f.vault, r, owner, probe)), Local{true, true})
	assert.Equal(f.provider.remaining.Load(), remaining-1)
	f.readOnly(t, func() {
		assert.Equal(try.To1(InspectLocal(f.vault, r, owner, nil)), Local{true, false})
		assert.Equal(try.To1(InspectLocal(f.vault, r, owner, probe)), Local{true, true})
	})
	assert.DeepEqual(try.To1(namespaceRecords(f.vault, untouched...)), before)
	assert.DeepEqual(try.To1(local.material()), material)
	authorization := try.To1(namespaceRecords(f.vault, authNamespace))
	assert.Equal(len(authorization[authNamespace]), 1)
	assert.DeepEqual(authorization[authNamespace][localDevice],
		try.To1(authorizationBinding(f.vault, r, owner)))
	assert.SLen(probe.probes, 2)
	assert.That(!bytes.Equal(probe.probes[0], probe.probes[1]))
	assert.SLen(probe.probes[0], key.HashSize)
}

func TestRootBootstrapGuardsAndRetry(t *testing.T) {
	defer assert.PushTester(t)()

	root, other := newSavedSigner(t), newSavedSigner(t)
	f := newVault(t)
	r := root.public
	f.readOnly(t, func() {
		state, err := BootstrapLocal(f.vault, other.public, r, root.handle)
		assert.ErrorIs(err, ErrNotKnown)
		assert.Equal(state, Local{})
		state, err = BootstrapLocal(f.vault, r, r, other.handle)
		assert.ErrorIs(err, ErrUnusableSigner)
		assert.Equal(state, Local{})
	})
	probe := &probeSigner{Handle: root.handle}
	assert.Equal(try.To1(BootstrapLocal(f.vault, r, r, probe)), Local{true, true})
	assert.Equal(len(try.To1(namespaceRecords(f.vault,
		"introduction-choice-demo", "received-introductions-v1", "known-introductions-v1"))), 0)
	before := try.To1(namespaceRecords(f.vault, authNamespace))
	f.provider.remaining.Store(0) // Even exhausted storage permits read-only retry.
	f.readOnly(t, func() {
		for _, handle := range []key.Handle{probe, other.handle, nil} {
			state, err := BootstrapLocal(f.vault, r, r, handle)
			assert.ErrorIs(err, ErrAlreadyAuthorized)
			assert.Equal(state, Local{})
		}
		state, err := BootstrapLocal(f.vault, other.public, other.public, other.handle)
		assert.ErrorIs(err, ErrInvalidAuthorization)
		assert.Equal(state, Local{})
		assert.Equal(try.To1(InspectLocal(f.vault, r, r, probe)), Local{true, true})
	})
	assert.DeepEqual(try.To1(namespaceRecords(f.vault, authNamespace)), before)
	assert.SLen(probe.probes, 2) // Bootstrap and explicit usability inspection only.
}

func TestSignerFailuresDoNotAuthorize(t *testing.T) {
	defer assert.PushTester(t)()

	local, foreign := newSavedSigner(t), newSavedSigner(t)
	cause := errors.New("injected signer failure")
	for _, tc := range []struct {
		name   string
		signer key.Handle
		cause  error
	}{
		{"missing", nil, nil},
		{"typed nil", (*probeSigner)(nil), nil},
		{"foreign", foreign.handle, nil},
		{"public error", &probeSigner{Handle: local.handle, publicErr: cause}, cause},
		{"sign error", &probeSigner{Handle: local.handle, signErr: cause}, cause},
		{"foreign signature", &probeSigner{Handle: foreign.handle, public: local.public}, nil},
		{"invalid signature", &probeSigner{Handle: local.handle,
			sign: func([]byte) ([]byte, error) { return []byte("invalid"), nil }}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newVault(t)
			f.readOnly(t, func() {
				state, err := BootstrapLocal(f.vault, local.public, local.public, tc.signer)
				assert.ErrorIs(err, ErrUnusableSigner)
				if tc.cause != nil {
					assert.ErrorIs(err, tc.cause)
				}
				assert.Equal(state, Local{})
				assert.Equal(try.To1(InspectLocal(f.vault, local.public, local.public, nil)), Local{})
			})
			try.To1(BootstrapLocal(f.vault, local.public, local.public, local.handle))
			f.readOnly(t, func() {
				assert.Equal(try.To1(InspectLocal(f.vault, local.public, local.public, tc.signer)),
					Local{true, false})
			})
		})
	}
}

func TestConcurrentBootstrapHasOneWinner(t *testing.T) {
	defer assert.PushTester(t)()

	local := newSavedSigner(t)
	f := newVault(t)
	remaining := f.provider.remaining.Load()
	ready, release := make(chan struct{}, 2), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	type result struct {
		state Local
		err   error
	}
	results := make(chan result, 2)
	for range 2 {
		probe := &probeSigner{Handle: local.handle, sign: func(data []byte) ([]byte, error) {
			ready <- struct{}{}
			<-release
			return local.handle.Sign(data)
		}}
		go func() {
			state, err := BootstrapLocal(f.vault, local.public, local.public, probe)
			results <- result{state, err}
		}()
	}
	for range 2 {
		select {
		case <-ready: // Both have observed an empty authorization before either writes.
		case <-time.After(5 * time.Second):
			t.Fatal("bootstrap did not reach signer outside transaction")
		}
	}
	close(release)
	winners := 0
	for range 2 {
		got := <-results
		if got.err == nil {
			winners++
			assert.Equal(got.state, Local{true, true})
		} else {
			assert.ErrorIs(got.err, ErrAlreadyAuthorized)
			assert.Equal(got.state, Local{})
		}
	}
	assert.Equal(winners, 1)
	assert.Equal(f.provider.remaining.Load(), remaining-1)
	assert.Equal(len(try.To1(namespaceRecords(f.vault, authNamespace))[authNamespace]), 1)
}
