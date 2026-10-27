package ads

import (
	"bytes"
	"slices"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

var claimBoundaryNames = []string{
	"introduction-choice-demo", "received-introductions-v1",
	"known-introductions-v1", currentNamespace, "local-device-auth-v1",
	"verified-ads", "pw", "pw-open", "trust", "deny", "peer-epoch",
	"peer-device", "recovery", "unrelated",
}

func publishClaim(t *testing.T, root, peer savedSigner) (vaultFixture, Current) {
	t.Helper()
	defer assert.PushTester(t)()
	f := newVault(t)
	try.To(ownEvidence(f.vault, root, peer, "known"))
	try.To1(device.BootstrapLocal(f.vault, root.public, peer.public, peer.handle))
	return f, try.To1(PublishLocal(f.vault, root.public, peer.public, peer.handle, endpoint, fixedNow))
}

func readClaim(t *testing.T, vault *storage.Vault, root, subject key.Public, want []byte) {
	t.Helper()
	defer assert.PushTester(t)()
	got, found := try.To2(ReadReceivedClaim(vault, root, subject))
	assert.Equal(found, want != nil)
	assert.DeepEqual(got, want)
}

func claimBytes(t *testing.T, root, subject key.Public) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	return try.To1(wire.Marshal(Current{Payload: Payload{
		Version: 1, Root: root, Node: subject, Device: subject, Slot: 1,
		Token: bytes.Repeat([]byte{7}, 32), ExpiresUnixNano: fixedNow.Add(TTL).UnixNano(),
		PeerIntroductionURL: endpoint,
	}, Signature: []byte{1}})) // Deliberately unauthentic, but structurally valid.
}

func changeClaim(t *testing.T, original []byte, change func(*Current)) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	var claim Current
	try.To(wire.UnmarshalCanonical(&claim, original))
	change(&claim)
	return try.To1(wire.Marshal(claim))
}

func TestReceiveClaimIndependentPublisherAndStateBoundary(t *testing.T) {
	defer assert.PushTester(t)()
	root, peer, receiver, unrelated := newSigner(t), newSigner(t), newSigner(t), newSigner(t)
	publisher, published := publishClaim(t, root, peer)
	f, _ := publishClaim(t, root, receiver)
	path := intro.New(key.Info{Public: root.public}).Introduce(root.handle, key.Info{Public: unrelated.public})
	acceptance := try.To1(path.SignAcceptance(unrelated.handle))
	try.To2(onboarding.SaveIntroduction(f.vault, root.public, path.Bytes(), acceptance))
	for _, name := range claimBoundaryNames[5:] {
		try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			ns := try.To1(tx.EnsureChild([]byte(name)))
			return ns.Put([]byte("sentinel"), []byte("unchanged"))
		}))
	}
	before := try.To1(records(f.vault, claimBoundaryNames...))
	ad := try.To1(wire.Marshal(published))
	remaining := f.lease.remaining
	publisher.unchanged(t, func() {
		assert.That(try.To1(ReceiveClaim(f.vault, root.public, peer.public, ad)))
		f.unchanged(t, func() { readClaim(t, f.vault, root.public, peer.public, ad) })
	})
	assert.Equal(f.lease.remaining, remaining-1)
	assert.DeepEqual(try.To1(records(f.vault, claimBoundaryNames...)), before)
	// In particular, the peer was not added to either introduction collection.
	assert.SLen(try.To1(onboarding.ListIntroductions(f.vault, root.public)), 2)
	assert.SLen(try.To1(onboarding.ListKnownIntroductions(f.vault, root.public)), 1)
}

func TestReceiveClaimForgedExpiredAndSupersededRemainUntrusted(t *testing.T) {
	defer assert.PushTester(t)()
	root, peer := newSigner(t), newSigner(t)
	publisher, genuine := publishClaim(t, root, peer)
	forged := genuine
	forged.Signature = []byte{1, 2, 3}
	_, err := decodeCurrent(try.To1(wire.Marshal(forged)), root.public, peer.public)
	assert.ErrorIs(err, ErrInvalidRecord) // Publisher authentication stays strict.
	expired := try.To1(PublishLocal(publisher.vault, root.public, peer.public,
		peer.handle, endpoint, fixedNow.Add(-2*TTL)))
	latest := try.To1(PublishLocal(publisher.vault, root.public, peer.public,
		peer.handle, endpoint, fixedNow))
	assert.ThatNot(bytes.Equal(latest.Payload.Token, genuine.Payload.Token))
	for _, tc := range []struct {
		name string
		ad   Current
	}{
		{"forged", forged}, {"expired", expired}, {"superseded", genuine},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newVault(t) // No Known, local authorization, or signer is needed.
			ad := try.To1(wire.Marshal(tc.ad))
			publisher.unchanged(t, func() {
				assert.That(try.To1(ReceiveClaim(f.vault, root.public, peer.public, ad)))
			})
			f.unchanged(t, func() { readClaim(t, f.vault, root.public, peer.public, ad) })
			assert.Equal(len(try.To1(records(f.vault, claimBoundaryNames...))), 0)
			try.To(f.vault.View(func(tx storage.ReadTx) error {
				return tx.Each(func(name, _ []byte) error {
					assert.Equal(string(name), receivedClaimsKey)
					return nil
				})
			}))
		})
	}
	// Authenticity alone cannot turn an expired publication into a local current
	// record. Received claims never perform even this local freshness check.
	_, found := try.To2(ReadCurrentLocal(publisher.vault, root.public, peer.public,
		time.Unix(0, latest.Payload.ExpiresUnixNano)))
	assert.ThatNot(found)
}

func TestReceiveClaimReplayReplacementIsolationAndCapacity(t *testing.T) {
	defer assert.PushTester(t)()
	root := newSigner(t)
	f := newVault(t)
	subjects := make([]key.Public, maxReceivedClaims+1)
	for i := range subjects {
		subjects[i] = newSigner(t).public
	}
	slices.SortFunc(subjects, func(a, b key.Public) int { return bytes.Compare(a, b) })
	want := make(map[string][]byte)
	for i := maxReceivedClaims - 1; i >= 0; i-- { // Insertion order must not leak into index order.
		subject := subjects[i]
		ad := claimBytes(t, root.public, subject)
		remaining := f.lease.remaining
		assert.That(try.To1(ReceiveClaim(f.vault, root.public, subject, ad)))
		assert.Equal(f.lease.remaining, remaining-1)
		want[string(subject)] = ad
	}
	first := subjects[0]
	fullBefore := rawClaims(t, f.vault)
	f.unchanged(t, func() {
		assert.ThatNot(try.To1(ReceiveClaim(f.vault, root.public, first, want[string(first)])))
		changed, err := ReceiveClaim(f.vault, root.public, subjects[maxReceivedClaims],
			claimBytes(t, root.public, subjects[maxReceivedClaims]))
		assert.ThatNot(changed)
		assert.ErrorIs(err, ErrReceivedClaimsFull)
	})
	assert.DeepEqual(rawClaims(t, f.vault), fullBefore)
	// Replacement at capacity is permitted, even with an earlier/expired expiry
	// and the same token. No freshness preference or token-reuse policy applies.
	replacement := changeClaim(t, want[string(first)], func(c *Current) {
		c.Payload.ExpiresUnixNano = 0
	})
	assert.That(try.To1(ReceiveClaim(f.vault, root.public, first, replacement)))
	want[string(first)] = replacement
	f.unchanged(t, func() {
		var stored receivedClaims
		try.To(wire.UnmarshalCanonical(&stored, rawClaims(t, f.vault)))
		assert.SLen(stored.Entries, maxReceivedClaims)
		for i, entry := range stored.Entries {
			assert.DeepEqual(entry.Subject, subjects[i])
			assert.DeepEqual(entry.Ad, want[string(entry.Subject)])
			readClaim(t, f.vault, root.public, entry.Subject, entry.Ad)
		}
		readClaim(t, f.vault, root.public, subjects[maxReceivedClaims], nil)
	})
}

func rawClaims(t *testing.T, vault *storage.Vault) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	var raw []byte
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		raw, _ = try.To2(tx.Get([]byte(receivedClaimsKey)))
		return nil
	}))
	return raw
}
