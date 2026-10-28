package pw

import (
	"bytes"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const policyKey = "local-denied-peers-v1"

func TestDeniedKnownPeerNeverProbesAndAllowOnlyRestoresPreflight(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	probe := &probeSigner{Handle: s.local.handle}
	assert.That(
		try.To1(
			policy.DenyLocal(
				s.f.vault,
				s.root.public,
				s.local.public,
				s.peer.public,
			),
		),
	)
	s.check(t, probe, ErrDenied)
	s.f.reopen(t)
	s.check(t, probe, ErrDenied)
	assert.Equal(probe.publicCalls.Load(), int64(0))
	assert.Equal(probe.signCalls.Load(), int64(0))
	assert.That(
		try.To1(
			policy.AllowLocal(
				s.f.vault,
				s.root.public,
				s.local.public,
				s.peer.public,
			),
		),
	)
	s.check(t, nil, ErrUnusableSigner) // Allow grants no live signer.
	s.check(t, probe, nil)
	assert.Equal(probe.publicCalls.Load(), int64(1))
	assert.Equal(probe.signCalls.Load(), int64(1))
	s.f.reopen(t)
	s.check(t, probe, nil)
	assert.Equal(probe.signCalls.Load(), int64(2))
}

func TestUnknownPeerMayBeDeniedWithoutFetchOrPromotion(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	unknown := newSigner(t)
	s.peer = unknown
	before := try.To1(
		onboarding.ListKnownIntroductions(s.f.vault, s.root.public),
	)
	probe := &probeSigner{Handle: s.local.handle}
	assert.That(
		try.To1(
			policy.DenyLocal(
				s.f.vault,
				s.root.public,
				s.local.public,
				unknown.public,
			),
		),
	)
	s.check(t, probe, ErrNotKnown) // Known validation precedes Deny.
	assert.DeepEqual(
		try.To1(onboarding.ListKnownIntroductions(s.f.vault, s.root.public)),
		before,
	)
	assert.That(
		try.To1(
			policy.AllowLocal(
				s.f.vault,
				s.root.public,
				s.local.public,
				unknown.public,
			),
		),
	)
	s.check(t, probe, ErrNotKnown)
	assert.That(
		try.To1(
			policy.DenyLocal(
				s.f.vault,
				s.root.public,
				s.local.public,
				unknown.public,
			),
		),
	)
	savePath(
		t,
		s.f.vault,
		s.root.public,
		intro.New(key.Info{Public: s.root.public}).
			Introduce(s.root.handle, key.Info{Public: unknown.public}),
		unknown,
	)
	s.check(t, probe, ErrNotKnown) // Received still is not Known.
	try.To1(onboarding.VerifyReceived(s.f.vault, s.root.public))
	s.check(t, probe, ErrDenied)
	assert.Equal(probe.publicCalls.Load(), int64(0))
	assert.Equal(probe.signCalls.Load(), int64(0))
	assert.That(
		try.To1(
			policy.AllowLocal(
				s.f.vault,
				s.root.public,
				s.local.public,
				unknown.public,
			),
		),
	)
	s.check(t, probe, nil)
}

func TestRootSelfKnownWithLocalDenial(t *testing.T) {
	defer assert.PushTester(t)()
	root, peer := newSigner(t), newSigner(t)
	s := scenario{f: newVault(t), root: root, local: root, peer: peer}
	savePath(
		t,
		s.f.vault,
		root.public,
		intro.New(key.Info{Public: root.public}).
			Introduce(root.handle, key.Info{Public: peer.public}),
		peer,
	)
	try.To1(onboarding.VerifyReceived(s.f.vault, root.public))
	probe := &probeSigner{Handle: root.handle}
	assert.That(
		try.To1(
			policy.DenyLocal(s.f.vault, root.public, root.public, peer.public),
		),
	)
	s.check(t, probe, ErrDenied)
	assert.That(
		try.To1(
			policy.AllowLocal(s.f.vault, root.public, root.public, peer.public),
		),
	)
	s.check(t, probe, ErrUnauthorized) // Allow creates no authorization.
	assert.Equal(probe.publicCalls.Load(), int64(0))
	try.To1(
		device.BootstrapLocal(s.f.vault, root.public, root.public, root.handle),
	)
	s.check(t, probe, nil)
	assert.That(
		try.To1(
			policy.DenyLocal(s.f.vault, root.public, root.public, peer.public),
		),
	)
	s.check(t, probe, ErrDenied)
	assert.Equal(probe.signCalls.Load(), int64(1))
}

func TestCorruptPolicyRefusesBeforeSignerEvenForAbsentPeer(t *testing.T) {
	for _, damage := range []string{"encoding", "binding", "invalid other peer", "namespace"} {
		t.Run(damage, func(t *testing.T) {
			defer assert.PushTester(t)()
			s := ready(t)
			try.To(s.f.vault.Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				raw := []byte{0xff}
				switch damage {
				case "binding":
					raw = try.To1(
						wire.Marshal(
							[]any{
								1,
								s.root.public,
								s.peer.public,
								[]key.Public{},
							},
						),
					)
				case "invalid other peer":
					raw = try.To1(
						wire.Marshal(
							[]any{
								1,
								s.root.public,
								s.local.public,
								[]key.Public{{0xff}},
							},
						),
					)
				case "namespace":
					try.To1(tx.EnsureChild([]byte(policyKey)))
					return nil
				}
				return tx.Put([]byte(policyKey), raw)
			}))
			probe := &probeSigner{Handle: s.local.handle}
			s.check(t, probe, ErrLocalState)
			s.f.reopen(t)
			s.check(t, probe, ErrLocalState)
			assert.Equal(probe.publicCalls.Load(), int64(0))
			assert.Equal(probe.signCalls.Load(), int64(0))
		})
	}
}

func TestDenyAllowPreserveUnrelatedState(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	try.To1(ads.PublishLocal(s.f.vault, s.root.public, s.local.public,
		s.local.handle, "http://127.0.0.1:1/peer/introduction", now))
	// Real signed historical peer ad, seeded without any remote listener or
	// verification exchange; it carries no currentness assertion in this test.
	ad := ads.Current{Payload: ads.Payload{
		Version: 1, Root: s.root.public, Node: s.peer.public, Device: s.peer.public,
		Slot: 1, Token: bytes.Repeat([]byte{1}, 32), ExpiresUnixNano: int64(ads.TTL),
		PeerIntroductionURL: "http://127.0.0.1:1/peer/introduction",
	}}
	digest := key.HashTagged(
		ads.SignaturePurpose,
		try.To1(wire.Marshal(ad.Payload)),
	)
	ad.Signature = try.To1(s.peer.handle.Sign(digest[:]))
	raw := try.To1(wire.Marshal(ad))
	try.To1(ads.ReceiveClaim(s.f.vault, s.root.public, s.peer.public, raw))
	try.To(s.f.vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		try.To(tx.Put([]byte("verified-ad-claims-v1"),
			try.To1(wire.Marshal([]any{1, []any{[]any{s.peer.public, raw}}}))))
		for _, name := range []string{"trust", "pw"} {
			ns := try.To1(tx.EnsureChild([]byte(name)))
			try.To(
				ns.Put(s.peer.public, []byte("opaque future-state sentinel")),
			)
		}
		return nil
	}))
	before := preservedPolicyState(t, s.f.vault)
	probe := &probeSigner{Handle: s.local.handle}
	assert.That(
		try.To1(
			policy.DenyLocal(
				s.f.vault,
				s.root.public,
				s.local.public,
				s.peer.public,
			),
		),
	)
	s.check(t, probe, ErrDenied)
	assert.DeepEqual(preservedPolicyState(t, s.f.vault), before)
	assert.That(
		try.To1(
			policy.AllowLocal(
				s.f.vault,
				s.root.public,
				s.local.public,
				s.peer.public,
			),
		),
	)
	s.check(t, probe, nil)
	assert.DeepEqual(preservedPolicyState(t, s.f.vault), before)
	s.f.reopen(t)
	assert.DeepEqual(preservedPolicyState(t, s.f.vault), before)
}

func preservedPolicyState(
	t *testing.T,
	v *storage.Vault,
) map[string]map[string][]byte {
	t.Helper()
	defer assert.PushTester(t)()
	result := make(map[string]map[string][]byte)
	try.To(v.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		result[""] = make(map[string][]byte)
		try.To(tx.Each(func(k, value []byte) error {
			if string(k) != policyKey {
				result[""][string(k)] = value
			}
			return nil
		}))
		for _, name := range []string{receivedNS, knownNS, authNS, "local-current-ad-v1", "trust", "pw"} {
			if !try.To1(tx.HasChild([]byte(name))) {
				continue
			}
			result[name] = make(map[string][]byte)
			ns := try.To1(tx.Child([]byte(name)))
			try.To(ns.Each(func(k, value []byte) error {
				result[name][string(k)] = value
				return nil
			}))
		}
		return nil
	}))
	return result
}

func TestPreflightRacingDenyIsOnlyAMomentaryObservation(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	arrived, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	probe := &probeSigner{
		Handle: s.local.handle,
		sign: func(data []byte) ([]byte, error) {
			close(arrived)
			<-release
			return s.local.handle.Sign(data)
		},
	}
	result := make(chan error, 1)
	go func() {
		result <- CheckLocalAcceptor(s.f.vault, s.root.public, s.local.public, s.peer.public, probe)
	}()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("preflight did not reach signer")
	}
	// Signing holds no policy transaction. This commit invalidates the earlier
	// observation while the probe is still running; preflight creates no grant.
	assert.That(
		try.To1(
			policy.DenyLocal(
				s.f.vault,
				s.root.public,
				s.local.public,
				s.peer.public,
			),
		),
	)
	close(release)
	assert.NoError(<-result)
	s.check(t, probe, ErrDenied)
	assert.Equal(probe.signCalls.Load(), int64(1))
	assert.That(
		try.To1(
			policy.IsDenied(
				s.f.vault,
				s.root.public,
				s.local.public,
				s.peer.public,
			),
		),
	)
}
