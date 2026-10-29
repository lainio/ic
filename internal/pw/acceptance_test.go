package pw

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
)

func acceptanceChallenge(t *testing.T) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	challenge := make([]byte, 32)
	try.To1(rand.Read(challenge))
	return challenge
}

func (s scenario) prove(t *testing.T, signer key.Handle, challenge []byte,
	want error,
) (proof key.Signature) {
	t.Helper()
	defer assert.PushTester(t)()
	s.f.unchanged(t, func() {
		var err error
		proof, err = ProveLocalAcceptance(s.f.vault, s.root.public,
			s.local.public, s.peer.public, signer, challenge)
		assert.Equal(err, want)
		if want != nil {
			assert.SNil(proof)
			return
		}
		try.To(VerifyLocalAcceptanceProof(s.root.public, s.local.public,
			s.peer.public, challenge, proof))
	})
	return proof
}

func TestAcceptanceProofReopenWithoutStateOrSeals(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	challenge := acceptanceChallenge(t)
	inputs := [][]byte{bytes.Clone(s.root.public), bytes.Clone(s.local.public),
		bytes.Clone(s.peer.public), bytes.Clone(challenge)}
	var messages [][]byte
	probe := &probeSigner{Handle: s.local.handle,
		sign: func(data []byte) ([]byte, error) {
			messages = append(messages, bytes.Clone(data))
			return s.local.handle.Sign(data)
		}}
	s.f.lease.remaining.Store(0)
	proof := s.prove(t, probe, challenge, nil)
	assert.Equal(probe.publicCalls.Load(), int64(1))
	assert.Equal(probe.signCalls.Load(), int64(2))
	// Independent array construction fixes the exact v1 format and domain.
	payload := try.To1(wire.Marshal([]any{1, s.root.public, s.local.public,
		s.peer.public, challenge}))
	digest := key.HashTagged("pw-local-acceptance/v1", payload)
	assert.DeepEqual(messages[1], digest[:])
	assert.That(proof.Verify(s.local.public, digest[:]))
	assert.ThatNot(bytes.Equal(messages[0], messages[1]))
	assert.DeepEqual([][]byte{s.root.public, s.local.public, s.peer.public,
		challenge}, inputs)
	assertNoRelationshipState(t, s.f.vault)

	s.f.reopen(t)
	probe.Handle = try.To1(nodeidentity.OpenDirectory(
		s.local.dir, s.local.unlock))
	s.prove(t, nil, challenge, ErrUnusableSigner)
	s.prove(t, probe, challenge, nil)
	assert.Equal(probe.signCalls.Load(), int64(4))
	assertNoRelationshipState(t, s.f.vault)

	// A pure verifier still works with closed storage and an unusable signer.
	try.To(s.f.vault.Close())
	probe.Handle = nil
	s.f.unchanged(t, func() {
		try.To(VerifyLocalAcceptanceProof(s.root.public, s.local.public,
			s.peer.public, challenge, proof))
	})
	assert.Equal(probe.publicCalls.Load(), int64(2))
	assert.Equal(probe.signCalls.Load(), int64(4))
}

func TestAcceptanceProofPinnedRootRequiresKnownPeerAndAuthorization(t *testing.T) {
	defer assert.PushTester(t)()
	root, peer := newSigner(t), newSigner(t)
	s := scenario{f: newVault(t), root: root, local: root, peer: peer}
	challenge := acceptanceChallenge(t)
	probe := &probeSigner{Handle: root.handle}
	s.prove(t, probe, challenge, ErrNotKnown)
	path := intro.New(key.Info{Public: root.public}).
		Introduce(root.handle, key.Info{Public: peer.public})
	savePath(t, s.f.vault, root.public, path, peer)
	s.prove(t, probe, challenge, ErrNotKnown) // Received alone is insufficient.
	try.To1(onboarding.VerifyReceived(s.f.vault, root.public))
	s.prove(t, probe, challenge, ErrUnauthorized)
	assert.Equal(probe.publicCalls.Load(), int64(0))
	assert.Equal(probe.signCalls.Load(), int64(0))
	try.To1(device.BootstrapLocal(s.f.vault, root.public,
		root.public, root.handle))
	s.f.reopen(t)
	s.f.lease.remaining.Store(0)
	s.prove(t, probe, challenge, nil)
	assert.Equal(probe.signCalls.Load(), int64(2))
	known := try.To1(onboarding.ListKnownIntroductions(s.f.vault, root.public))
	assert.DeepEqual(known, []key.Public{peer.public})
	assertNoRelationshipState(t, s.f.vault)
}

func TestAcceptanceProofExactBindingAndSignature(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	challenge := acceptanceChallenge(t)
	probe := &probeSigner{Handle: s.local.handle}
	proof := s.prove(t, probe, challenge, nil)
	changed := bytes.Clone(challenge)
	changed[len(changed)-1] ^= 1
	corrupt := bytes.Clone(proof)
	corrupt[len(corrupt)-1] ^= 1
	payload := try.To1(wire.Marshal([]any{1, s.root.public, s.local.public,
		s.peer.public, challenge}))
	digest := key.HashTagged("pw-local-acceptance/v1", payload)
	foreign := try.To1(s.peer.handle.Sign(digest[:]))
	// The expected peer keys share a binary prefix, but differ in full bytes.
	assert.DeepEqual(s.root.public[:5], s.peer.public[:5])
	for _, tc := range []struct {
		name                 string
		root, acceptor, peer key.Public
		challenge            []byte
		proof                key.Signature
	}{
		{"Root", s.peer.public, s.local.public, s.peer.public, challenge, proof},
		{"acceptor", s.root.public, s.root.public, s.peer.public, challenge, proof},
		{"peer", s.root.public, s.local.public, s.root.public, challenge, proof},
		{"swapped", s.root.public, s.peer.public, s.local.public, challenge, proof},
		{"challenge", s.root.public, s.local.public, s.peer.public, changed, proof},
		{"missing", s.root.public, s.local.public, s.peer.public, challenge, nil},
		{"oversized", s.root.public, s.local.public, s.peer.public, challenge, make([]byte, 73)},
		{"invalid", s.root.public, s.local.public, s.peer.public, challenge, []byte{0xff}},
		{"corrupt", s.root.public, s.local.public, s.peer.public, challenge, corrupt},
		{"foreign", s.root.public, s.local.public, s.peer.public, challenge, foreign},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			s.f.unchanged(t, func() {
				assert.Equal(VerifyLocalAcceptanceProof(tc.root, tc.acceptor,
					tc.peer, tc.challenge, tc.proof), ErrInvalidProof)
			})
		})
	}
	assert.Equal(probe.signCalls.Load(), int64(2))
}

func TestAcceptanceProofRejectsOtherPurposesAndStatements(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	challenge := acceptanceChallenge(t)
	payload := try.To1(wire.Marshal([]any{1, s.root.public, s.local.public,
		s.peer.public, challenge}))
	for _, purpose := range []string{
		ads.SignaturePurpose, "ad-currentness-proof/v1",
		"local-device-usability/v1", "pw-local-acceptance/v2",
	} {
		t.Run(purpose, func(t *testing.T) {
			defer assert.PushTester(t)()
			digest := key.HashTagged(purpose, payload)
			proof := try.To1(s.local.handle.Sign(digest[:]))
			s.f.unchanged(t, func() {
				assert.Equal(VerifyLocalAcceptanceProof(s.root.public,
					s.local.public, s.peer.public, challenge, proof), ErrInvalidProof)
			})
		})
	}
	version2 := try.To1(wire.Marshal([]any{2, s.root.public, s.local.public,
		s.peer.public, challenge}))
	wrongVersion := key.HashTagged("pw-local-acceptance/v1", version2)
	// Raw request/payload bytes and a general-purpose digest are never signed.
	for _, message := range [][]byte{challenge, payload, wrongVersion[:]} {
		proof := try.To1(s.local.handle.Sign(message))
		s.f.unchanged(t, func() {
			assert.Equal(VerifyLocalAcceptanceProof(s.root.public,
				s.local.public, s.peer.public, challenge, proof), ErrInvalidProof)
		})
	}
}

func TestAcceptanceChallengesAndPolicyAreMomentary(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	first, second := acceptanceChallenge(t), acceptanceChallenge(t)
	var messages [][]byte
	probe := &probeSigner{Handle: s.local.handle,
		sign: func(data []byte) ([]byte, error) {
			messages = append(messages, bytes.Clone(data))
			return s.local.handle.Sign(data)
		}}
	proof := s.prove(t, probe, first, nil)
	other := s.prove(t, probe, second, nil)
	assert.ThatNot(bytes.Equal(messages[1], messages[3])) // Signed messages.
	s.f.unchanged(t, func() {
		assert.Equal(VerifyLocalAcceptanceProof(s.root.public, s.local.public,
			s.peer.public, second, proof), ErrInvalidProof)
		assert.Equal(VerifyLocalAcceptanceProof(s.root.public, s.local.public,
			s.peer.public, first, other), ErrInvalidProof)
		// Reused challenges remain verifiable: no replay cache is promised.
		for range 2 {
			try.To(VerifyLocalAcceptanceProof(s.root.public, s.local.public,
				s.peer.public, first, proof))
		}
	})
	try.To1(policy.DenyLocal(s.f.vault, s.root.public,
		s.local.public, s.peer.public))
	s.prove(t, probe, first, ErrDenied)
	assert.Equal(probe.publicCalls.Load(), int64(2))
	assert.Equal(probe.signCalls.Load(), int64(4))
	s.f.unchanged(t, func() {
		// Authentic endorsement survives Deny; current acceptance does not.
		try.To(VerifyLocalAcceptanceProof(s.root.public, s.local.public,
			s.peer.public, first, proof))
	})
	try.To1(policy.AllowLocal(s.f.vault, s.root.public,
		s.local.public, s.peer.public))
	s.prove(t, nil, first, ErrUnusableSigner) // Allow creates no usable bit.
	s.prove(t, probe, first, nil)
	assert.Equal(probe.signCalls.Load(), int64(6))
}
