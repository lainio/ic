package pw

import (
	"bytes"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestAdHistoryNeverSubstitutesForIndependentKnown(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	deleteRecord(t, s.f.vault, knownNS, s.peer.public)
	deleteRecord(t, s.f.vault, receivedNS, s.peer.public)
	// A genuine signed but long-expired ad; no publisher or peer socket exists.
	ad := ads.Current{Payload: ads.Payload{
		Version: 1, Root: s.root.public, Node: s.peer.public, Device: s.peer.public,
		Slot: 1, Token: bytes.Repeat([]byte{1}, 32), ExpiresUnixNano: int64(ads.TTL),
		PeerIntroductionURL: "http://127.0.0.1:1/peer/introduction",
	}}
	digest := key.HashTagged(ads.SignaturePurpose, try.To1(wire.Marshal(ad.Payload)))
	ad.Signature = try.To1(s.peer.handle.Sign(digest[:]))
	raw := try.To1(wire.Marshal(ad))
	try.To1(ads.ReceiveClaim(s.f.vault, s.root.public, s.peer.public, raw))
	probe := &probeSigner{Handle: s.local.handle}
	s.check(t, probe, ErrNotKnown) // Only an ad claim.

	// Seed the existing historical snapshot format, as ads' storage tests do.
	// This tests restored history without performing any remote verification.
	table := try.To1(wire.Marshal([]any{1, []any{[]any{s.peer.public, raw}}}))
	try.To(s.f.vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		try.To(tx.Delete([]byte("received-ad-claims-v1")))
		return tx.Put([]byte("verified-ad-claims-v1"), table)
	}))
	stored, found := try.To2(ads.ReadVerifiedClaim(s.f.vault, s.root.public, s.peer.public))
	assert.That(found)
	assert.DeepEqual(stored, raw)
	s.check(t, probe, ErrNotKnown) // Only historical VerifiedAd, no Known or Received.
	assert.Equal(probe.publicCalls.Load(), int64(0))
	s.f.reopen(t)
	s.check(t, probe, ErrNotKnown)

	base := intro.New(key.Info{Public: s.root.public})
	savePath(t, s.f.vault, s.root.public,
		base.Introduce(s.root.handle, key.Info{Public: s.peer.public}), s.peer)
	try.To1(onboarding.VerifyReceived(s.f.vault, s.root.public))
	// Local preflight ignores expiry/currentness; success says nothing about
	// remote acceptance or CreatePW. Historical bytes remain exactly unchanged.
	s.check(t, probe, nil)
	stored, found = try.To2(ads.ReadVerifiedClaim(s.f.vault, s.root.public, s.peer.public))
	assert.That(found)
	assert.DeepEqual(stored, raw)
	// Even corrupt ad storage is outside this guard's inputs and authority.
	try.To(s.f.vault.Update(func(tx storage.WriteTx) error {
		return tx.Put([]byte("verified-ad-claims-v1"), []byte("corrupt history"))
	}))
	s.check(t, probe, nil)
}

func TestWholeKnownViewMustValidateBeforeSigning(t *testing.T) {
	for _, damage := range []string{
		"marker", "missing received", "malformed received", "invalid acceptance", "received is namespace",
	} {
		t.Run(damage, func(t *testing.T) {
			defer assert.PushTester(t)()
			s := ready(t)
			extra := newSigner(t)
			base := intro.New(key.Info{Public: s.root.public})
			savePath(t, s.f.vault, s.root.public,
				base.Introduce(s.root.handle, key.Info{Public: extra.public}), extra)
			try.To1(onboarding.VerifyReceived(s.f.vault, s.root.public))
			// Both requested subjects remain healthy; a third entry is damaged.
			// The result must not depend on which encrypted key is visited first.
			switch damage {
			case "marker":
				putRecord(t, s.f.vault, knownNS, extra.public, []byte("corrupt marker"))
			case "missing received":
				deleteRecord(t, s.f.vault, receivedNS, extra.public)
			case "malformed received":
				replaceEvidence(t, s.f.vault, extra.public, []byte("corrupt received"))
			case "invalid acceptance":
				record := readRecord(t, s.f.vault, receivedNS, extra.public)
				record[len(record)-1] ^= 1
				replaceEvidence(t, s.f.vault, extra.public, record)
			case "received is namespace":
				try.To(s.f.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					ns := try.To1(tx.ChildForUpdate([]byte(receivedNS)))
					try.To(ns.Delete(extra.public))
					try.To1(ns.EnsureChild(extra.public))
					return nil
				}))
			}
			probe := &probeSigner{Handle: s.local.handle}
			s.check(t, probe, ErrLocalState)
			// Even an unknown requested peer cannot mask damaged local state.
			s.peer = newSigner(t)
			s.check(t, probe, ErrLocalState)
			assert.Equal(probe.publicCalls.Load(), int64(0))
			s.f.reopen(t)
			s.check(t, probe, ErrLocalState)
		})
	}
}

// Keep the marker consistent so proof validation, not just the digest, must fail.
func replaceEvidence(t *testing.T, v *storage.Vault, subject, record []byte) {
	t.Helper()
	putRecord(t, v, receivedNS, subject, record)
	digest := key.HashTagged(knownNS, record)
	putRecord(t, v, knownNS, subject, append([]byte{1}, digest[:]...))
}

func TestConflictingParentHistoryFailsClosed(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	extra, staging := newSigner(t), newVault(t)
	base := intro.New(key.Info{Public: s.root.public})
	// Main history: peer -> Root. Alternate history: peer -> local -> Root.
	// Each signed path is valid alone; together they have conflicting parents.
	alternate := base.Introduce(s.root.handle, key.Info{Public: s.local.public}).
		Introduce(s.local.handle, key.Info{Public: s.peer.public}).
		Introduce(s.peer.handle, key.Info{Public: extra.public})
	savePath(t, staging.vault, s.root.public, alternate, extra)
	try.To1(onboarding.VerifyReceived(staging.vault, s.root.public))
	for _, name := range []string{receivedNS, knownNS} {
		putRecord(t, s.f.vault, name, extra.public,
			readRecord(t, staging.vault, name, extra.public))
	}
	probe := &probeSigner{Handle: s.local.handle}
	s.check(t, probe, ErrLocalState)
	assert.Equal(probe.publicCalls.Load(), int64(0))
}

func TestForeignRootEvidenceFailsClosed(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	foreign, staging := newSigner(t), newVault(t)
	savePath(t, staging.vault, foreign.public, intro.New(key.Info{Public: foreign.public}).
		Introduce(foreign.handle, key.Info{Public: s.peer.public}), s.peer)
	try.To1(onboarding.VerifyReceived(staging.vault, foreign.public))
	for _, name := range []string{receivedNS, knownNS} {
		putRecord(t, s.f.vault, name, s.peer.public,
			readRecord(t, staging.vault, name, s.peer.public))
	}
	probe := &probeSigner{Handle: s.local.handle}
	s.check(t, probe, ErrLocalState)
	assert.Equal(probe.publicCalls.Load(), int64(0))
}

func TestRootCannotAcceptEarlyKnownHitBeforeCorruption(t *testing.T) {
	defer assert.PushTester(t)()
	f, root := newVault(t), newSigner(t)
	base := intro.New(key.Info{Public: root.public})
	for range 2 {
		peer := newSigner(t)
		savePath(t, f.vault, root.public,
			base.Introduce(root.handle, key.Info{Public: peer.public}), peer)
	}
	try.To1(onboarding.VerifyReceived(f.vault, root.public))
	try.To1(device.BootstrapLocal(f.vault, root.public, root.public, root.handle))
	// Observe actual encrypted iteration order, so the valid requested peer is
	// deterministically visited BEFORE the corrupt entry, regardless of keys.
	var order []key.Public
	try.To(f.vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		ns := try.To1(tx.Child([]byte(knownNS)))
		return ns.Each(func(subject, _ []byte) error {
			order = append(order, bytes.Clone(subject))
			return nil
		})
	}))
	assert.SLen(order, 2)
	s := scenario{f: f, root: root, local: root, peer: savedSigner{public: order[0]}}
	s.check(t, root.handle, nil)
	putRecord(t, f.vault, knownNS, order[1], []byte("corrupt later marker"))
	probe := &probeSigner{Handle: root.handle}
	s.check(t, probe, ErrLocalState)
	assert.Equal(probe.publicCalls.Load(), int64(0))
}
