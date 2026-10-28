package pw

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestLocalPreflightAbsentDenyWithoutAdsOrPeer(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	identity := try.To1(os.ReadFile(filepath.Join(s.local.dir, "identity.json")))
	unlock := try.To1(os.ReadFile(s.local.unlock))
	inputs := [][]byte{bytes.Clone(s.root.public), bytes.Clone(s.local.public), bytes.Clone(s.peer.public)}
	var probes [][]byte
	probe := &probeSigner{Handle: s.local.handle, sign: func(data []byte) ([]byte, error) {
		probes = append(probes, bytes.Clone(data))
		return s.local.handle.Sign(data)
	}}
	// No peer server or remote API exists; absent policy is an empty Deny set.
	// Entire encrypted-file equality also excludes any new hidden namespace.
	s.f.lease.remaining.Store(0)
	s.check(t, probe, nil)
	s.check(t, probe, nil)
	assert.Equal(probe.signCalls.Load(), int64(2))
	assert.SLen(probes[0], key.HashSize)
	assert.ThatNot(bytes.Equal(probes[0], probes[1]))
	assert.DeepEqual([][]byte{s.root.public, s.local.public, s.peer.public}, inputs)
	s.f.reopen(t)
	s.check(t, nil, ErrUnusableSigner) // Success persisted no usable/eligible bit.
	s.check(t, probe, nil)
	assert.Equal(probe.signCalls.Load(), int64(3))
	assert.DeepEqual(try.To1(os.ReadFile(filepath.Join(s.local.dir, "identity.json"))), identity)
	assert.DeepEqual(try.To1(os.ReadFile(s.local.unlock)), unlock)
	assertNoRelationshipState(t, s.f.vault)
}

func assertNoRelationshipState(t *testing.T, vault *storage.Vault) {
	t.Helper()
	defer assert.PushTester(t)()
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		for _, name := range []string{
			"local-current-ad-v1", "received-ad-claims-v1", "verified-ad-claims-v1",
			"pw", "trust", "deny", "local-denied-peers-v1",
		} {
			assert.ThatNot(try.To1(tx.HasChild([]byte(name))))
			_, found := try.To2(tx.Get([]byte(name)))
			assert.ThatNot(found)
		}
		return nil
	}))
}

func TestPinnedRootSelfKnownStillRequiresPeerAndDevice(t *testing.T) {
	defer assert.PushTester(t)()
	f, root, peer := newVault(t), newSigner(t), newSigner(t)
	probe := &probeSigner{Handle: root.handle}
	s := scenario{f: f, root: root, local: root, peer: peer}
	s.check(t, probe, ErrNotKnown)
	savePath(t, f.vault, root.public, intro.New(key.Info{Public: root.public}).
		Introduce(root.handle, key.Info{Public: peer.public}), peer)
	s.check(t, probe, ErrNotKnown)
	try.To1(onboarding.VerifyReceived(f.vault, root.public))
	s.check(t, probe, ErrUnauthorized)
	assert.Equal(probe.publicCalls.Load(), int64(0))
	try.To1(device.BootstrapLocal(f.vault, root.public, root.public, root.handle))
	s.check(t, probe, nil)
	assert.DeepEqual(try.To1(onboarding.ListIntroductions(f.vault, root.public)), []key.Public{peer.public})
	assert.DeepEqual(try.To1(onboarding.ListKnownIntroductions(f.vault, root.public)), []key.Public{peer.public})
	// The Root convention applies only to our own exact pinned identity.
	s.local, s.peer = peer, root
	s.check(t, probe, ErrNotKnown)
}

func TestKnownBeforeAnySignerUse(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	probe := &probeSigner{Handle: s.local.handle}
	unknown := newSigner(t)
	knownPeer := s.peer
	s.peer = unknown
	s.check(t, probe, ErrNotKnown)
	s.peer = knownPeer
	deleteRecord(t, s.f.vault, knownNS, s.peer.public)
	s.check(t, probe, ErrNotKnown) // Peer Received alone is not Known.
	try.To1(onboarding.VerifyReceived(s.f.vault, s.root.public))
	deleteRecord(t, s.f.vault, knownNS, s.local.public)
	s.check(t, probe, ErrNotKnown) // Own Received plus saved authorization is insufficient.
	deleteRecord(t, s.f.vault, receivedNS, s.local.public)
	s.check(t, probe, ErrNotKnown) // No non-Root self-Known exception.
	assert.Equal(probe.publicCalls.Load(), int64(0))
	assert.Equal(probe.signCalls.Load(), int64(0))
	s.f.reopen(t)
	s.check(t, probe, ErrNotKnown)
}

func TestAuthorizationDoesNotImplySignerUsability(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	providerErr := errors.New("private provider diagnostics and key material")
	for _, tc := range []struct {
		name   string
		signer key.Handle
	}{
		{"absent", nil},
		{"typed nil", (*probeSigner)(nil)},
		{"foreign", s.peer.handle},
		{"public unavailable", &probeSigner{Handle: s.local.handle, publicErr: providerErr}},
		{"sign unavailable", &probeSigner{Handle: s.local.handle, signErr: providerErr}},
		{"foreign signature", &probeSigner{Handle: s.peer.handle, public: s.local.public}},
		{"invalid signature", &probeSigner{Handle: s.local.handle,
			sign: func([]byte) ([]byte, error) { return []byte("invalid signature"), nil }}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			s.check(t, tc.signer, ErrUnusableSigner)
			assert.Equal(try.To1(device.InspectLocal(s.f.vault, s.root.public,
				s.local.public, nil)), device.Local{Authorized: true})
		})
	}
	s.check(t, s.local.handle, nil) // Failures create no latch or stored live bit.
}

func TestConcurrentChecksEachProbeOutsideVaultTransaction(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	const count = 4
	arrived, release := make(chan struct{}, count), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	probe := &probeSigner{Handle: s.local.handle, sign: func(data []byte) ([]byte, error) {
		// A nested View would deadlock if the guard held a Vault transaction.
		if _, err := onboarding.ListKnownIntroductions(s.f.vault, s.root.public); err != nil {
			return nil, err
		}
		arrived <- struct{}{}
		<-release
		return s.local.handle.Sign(data)
	}}
	s.f.unchanged(t, func() {
		results := make(chan error, count)
		for range count {
			go func() {
				results <- CheckLocalAcceptor(s.f.vault, s.root.public,
					s.local.public, s.peer.public, probe)
			}()
		}
		for range count {
			select {
			case <-arrived:
			case <-time.After(5 * time.Second):
				t.Fatal("preflight held a transaction or serialized signer probes")
			}
		}
		close(release)
		for range count {
			assert.NoError(<-results)
		}
	})
	assert.Equal(probe.signCalls.Load(), int64(count))
	s.check(t, nil, ErrUnusableSigner)
}
