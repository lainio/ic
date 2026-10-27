package ads

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func proofPublication(t *testing.T, root, local savedSigner) (vaultFixture, []byte) {
	t.Helper()
	defer assert.PushTester(t)()
	f := newVault(t)
	if !bytes.Equal(root.public, local.public) {
		try.To(ownEvidence(f.vault, root, local, "known"))
	}
	try.To1(device.BootstrapLocal(f.vault, root.public, local.public, local.handle))
	current := try.To1(PublishLocal(f.vault, root.public, local.public,
		local.handle, endpoint, fixedNow))
	return f, try.To1(wire.Marshal(current))
}

func proofChallenge(t *testing.T) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	nonce := make([]byte, 32)
	try.To1(rand.Read(nonce))
	return nonce
}

// Construct the specified digest independently of the implementation's helper
// and struct: full keys, SHA-256 of the entire signed ad, and exact nonce.
func independentProofDigest(t *testing.T, root, subject key.Public, ad, nonce []byte) key.Hash {
	t.Helper()
	defer assert.PushTester(t)()
	digest := sha256.Sum256(ad)
	payload := try.To1(wire.Marshal([]any{uint8(1), root, subject, digest[:], nonce}))
	return key.HashTagged("ad-currentness-proof/v1", payload)
}

func TestCurrentProofRootAndNonRootReopenWithoutWrites(t *testing.T) {
	for _, name := range []string{"Root", "non-Root"} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			root, local, peer := newSigner(t), newSigner(t), newSigner(t)
			if name == "Root" {
				root = local
			}
			f, ad := proofPublication(t, root, local)
			received := claimBytes(t, root.public, peer.public)
			assert.That(try.To1(ReceiveClaim(f.vault, root.public, peer.public, received)))
			for _, name := range claimBoundaryNames[5:] {
				try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					ns := try.To1(tx.EnsureChild([]byte(name)))
					return ns.Put([]byte("sentinel"), []byte("unchanged"))
				}))
			}
			before := try.To1(records(f.vault, claimBoundaryNames...))
			known := try.To1(onboarding.ListKnownIntroductions(f.vault, root.public))
			assert.Equal(len(known), map[string]int{"Root": 0, "non-Root": 1}[name])
			try.To(f.db.Close())
			f.lease.remaining = 0
			f.db = try.To1(storage.OpenBolt(f.path))
			t.Cleanup(func() { assert.NoError(f.db.Close()) })
			f.vault = try.To1(f.db.OpenVault(t.Context(), storage.VaultID{1}, storage.KeyID{7}, f.lease))
			nonce := proofChallenge(t)
			f.unchanged(t, func() {
				r, subject, input, challenge := bytes.Clone(root.public), bytes.Clone(local.public), bytes.Clone(ad), bytes.Clone(nonce)
				var signedOutput []byte
				probe := &observedSigner{Handle: local.handle, sign: func(call int, data []byte) ([]byte, error) {
					if call == 2 {
						digest := independentProofDigest(t, root.public, local.public, ad, nonce)
						assert.DeepEqual(data, digest[:])
						signedOutput = try.To1(local.handle.Sign(data))
						return signedOutput, nil
					}
					return local.handle.Sign(data)
				}}
				proof := try.To1(ProveCurrentLocal(f.vault, r, subject, probe, endpoint, input, challenge, fixedNow))
				assert.Equal(probe.calls, 2) // Fresh usability probe, then scoped proof.
				assert.DeepEqual(input, ad)
				assert.DeepEqual(challenge, nonce)
				assert.That(bytes.Equal(r, root.public))
				assert.That(bytes.Equal(subject, local.public))
				clear(signedOutput) // The returned proof must not borrow signer memory.
				try.To(VerifyCurrentProof(r, subject, input, challenge, proof, fixedNow))
				clear(r)
				clear(subject)
				clear(input)
				clear(challenge)
				try.To(VerifyCurrentProof(bytes.Clone(root.public), bytes.Clone(local.public),
					bytes.Clone(ad), bytes.Clone(nonce), bytes.Clone(proof), fixedNow))
				digest := independentProofDigest(t, root.public, local.public, ad, nonce)
				assert.That(proof.Verify(local.public, digest[:]))
				assert.ThatNot(proof.Verify(local.public, nonce))
				adDigest := sha256.Sum256(ad)
				payload := try.To1(wire.Marshal([]any{1, root.public, local.public, adDigest[:], nonce}))
				for _, tag := range []string{SignaturePurpose, "local-device-usability/v1", "ad-currentness-proof/v2"} {
					wrong := key.HashTagged(tag, payload)
					assert.ThatNot(proof.Verify(local.public, wrong[:]))
				}
				clear(proof)
				assert.DeepEqual(try.To1(records(f.vault, claimBoundaryNames...)), before)
				readClaim(t, f.vault, root.public, peer.public, received)
				assert.DeepEqual(try.To1(onboarding.ListKnownIntroductions(f.vault, root.public)), known)
				state := try.To1(device.InspectLocal(f.vault, root.public, local.public, nil))
				assert.Equal(state, device.Local{Authorized: true})
			})
		})
	}
}

func TestCurrentProofRejectsSupersededUnexpiredAd(t *testing.T) {
	defer assert.PushTester(t)()
	root, local, other := newSigner(t), newSigner(t), newSigner(t)
	f, first := proofPublication(t, root, local)
	nonce := proofChallenge(t)
	oldProof := try.To1(ProveCurrentLocal(f.vault, root.public, local.public,
		local.handle, endpoint, first, nonce, fixedNow))
	now := fixedNow.Add(time.Second)
	second := try.To1(PublishLocal(f.vault, root.public, local.public, local.handle, endpoint, now))
	latest := try.To1(wire.Marshal(second))
	// A is still signed and unexpired. Offline proof authentication cannot know
	// that it was replaced; only the publisher's fresh current-record gate can.
	try.To1(decodeCurrent(first, root.public, local.public))
	try.To(VerifyCurrentProof(root.public, local.public, first, nonce, oldProof, now))
	_, foreignRoot := proofPublication(t, other, local)
	_, foreignSubject := proofPublication(t, root, other)
	_, alternate := proofPublication(t, root, local)
	alternate = changeClaim(t, alternate, func(c *Current) {
		c.Payload.PeerIntroductionURL = "http://127.0.0.1:9090/peer/introduction"
		resignAd(t, c, local.handle)
	})
	f.lease.remaining = 0
	f.unchanged(t, func() {
		for _, ad := range [][]byte{first, foreignRoot, foreignSubject, alternate} {
			probe := &observedSigner{Handle: local.handle}
			proof, err := ProveCurrentLocal(f.vault, root.public, local.public, probe, endpoint, ad, nonce, now)
			assert.Error(err)
			assert.SNil(proof)
			assert.Equal(probe.calls, 0)
		}
		proof := try.To1(ProveCurrentLocal(f.vault, root.public, local.public,
			local.handle, endpoint, latest, nonce, now))
		try.To(VerifyCurrentProof(root.public, local.public, latest, nonce, proof, now))
		assert.Error(VerifyCurrentProof(root.public, local.public, first, nonce, proof, now))
		assert.Error(VerifyCurrentProof(root.public, local.public, latest, nonce, oldProof, now))
	})
}

func resignAd(t *testing.T, ad *Current, signer key.Handle) {
	t.Helper()
	defer assert.PushTester(t)()
	digest := key.HashTagged(SignaturePurpose, try.To1(wire.Marshal(ad.Payload)))
	ad.Signature = try.To1(signer.Sign(digest[:]))
}
