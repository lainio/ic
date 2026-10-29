package pw

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestAcceptanceInputAdmissionBeforeVaultOrSigner(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	challenge := acceptanceChallenge(t)
	probe := &probeSigner{Handle: s.local.handle}
	var fields map[int]any
	try.To(wire.Unmarshal(&fields, s.peer.public))
	fields[-2], fields[-3] = make([]byte, 32), make([]byte, 32)
	offCurve := try.To1(wire.Marshal(fields))
	try.To(wire.Unmarshal(&fields, s.peer.public))
	fields[1], fields[3] = int64(1), int64(-8) // Foreign key/algorithm profile.
	foreign := try.To1(wire.Marshal(fields))
	badKeys := []key.Public{
		nil, {0xff}, offCurve, foreign, make([]byte, 129),
		append([]byte{0xb8, 5}, s.peer.public[1:]...), // Noncanonical map.
		bytes.Clone(s.peer.public[:5]),                // A common prefix is not an identity.
		append(bytes.Clone(s.peer.public), 0),
	}
	// Closed storage distinguishes admission from even an attempted View.
	try.To(s.f.vault.Close())
	reject := func(root, local, peer key.Public, nonce []byte) {
		s.f.unchanged(t, func() {
			proof, err := ProveLocalAcceptance(s.f.vault, root, local, peer,
				probe, nonce)
			assert.Equal(err, ErrInvalidInput)
			assert.SNil(proof)
			assert.Equal(VerifyLocalAcceptanceProof(root, local, peer,
				nonce, key.Signature{1}), ErrInvalidInput)
		})
	}
	for _, public := range badKeys {
		reject(public, s.local.public, s.peer.public, challenge)
		reject(s.root.public, public, s.peer.public, challenge)
		reject(s.root.public, s.local.public, public, challenge)
	}
	for _, nonce := range [][]byte{nil, {}, make([]byte, 31), make([]byte, 33)} {
		reject(s.root.public, s.local.public, s.peer.public, nonce)
	}
	reject(s.root.public, s.local.public, bytes.Clone(s.local.public), challenge)
	s.f.unchanged(t, func() {
		proof, err := ProveLocalAcceptance(nil, s.root.public,
			s.local.public, s.peer.public, probe, challenge)
		assert.Equal(err, ErrInvalidInput)
		assert.SNil(proof)
	})
	assert.Equal(probe.publicCalls.Load(), int64(0))
	assert.Equal(probe.signCalls.Load(), int64(0))
}

func TestAcceptancePreservesPreflightFailures(t *testing.T) {
	for _, name := range []string{
		"own Received only", "peer Received only", "own absent", "peer absent",
		"corrupt Known", "corrupt Deny", "corrupt authorization", "closed Vault",
		"foreign Root", "foreign reader",
	} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			s := ready(t)
			want := ErrLocalState
			switch name {
			case "own Received only", "own absent":
				deleteRecord(t, s.f.vault, knownNS, s.local.public)
				if name == "own absent" {
					deleteRecord(t, s.f.vault, receivedNS, s.local.public)
				}
				want = ErrNotKnown
			case "peer Received only", "peer absent":
				deleteRecord(t, s.f.vault, knownNS, s.peer.public)
				if name == "peer absent" {
					deleteRecord(t, s.f.vault, receivedNS, s.peer.public)
				}
				want = ErrNotKnown
			case "corrupt Known":
				putRecord(t, s.f.vault, knownNS, s.peer.public, []byte{0xff})
			case "corrupt Deny":
				try.To(s.f.vault.Update(func(tx storage.WriteTx) error {
					return tx.Put([]byte(policyKey), []byte{0xff})
				}))
			case "corrupt authorization":
				putRecord(t, s.f.vault, authNS, []byte(authKey), []byte{0xff})
			case "closed Vault":
				try.To(s.f.vault.Close())
			case "foreign Root":
				s.root = s.peer
			case "foreign reader":
				s.local, s.peer = s.peer, s.local
			}
			probe := &probeSigner{Handle: s.local.handle}
			s.prove(t, probe, acceptanceChallenge(t), want)
			assert.Equal(probe.publicCalls.Load(), int64(0))
			assert.Equal(probe.signCalls.Load(), int64(0))
		})
	}
}

func TestAcceptanceRequiresUsableAuthorizedSigner(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	challenge := acceptanceChallenge(t)
	for _, tc := range []struct {
		name   string
		signer key.Handle
	}{
		{"missing", nil},
		{"typed nil", (*probeSigner)(nil)},
		{"wrong public key", &probeSigner{Handle: s.peer.handle}},
		{"unusable", &probeSigner{Handle: s.local.handle,
			signErr: errors.New("private provider diagnostics")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s.prove(t, tc.signer, challenge, ErrUnusableSigner)
		})
	}
}

func TestAcceptanceSignerFailuresAreSanitized(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	challenge := acceptanceChallenge(t)
	const diagnostic = "PRIVATE_ACCEPTANCE_PROVIDER_DIAGNOSTIC"
	var trace bytes.Buffer
	previousError, previousReturn := err2.ErrorTracer(), err2.ErrRetTracer()
	err2.SetErrorTracer(&trace)
	err2.SetErrRetTracer(&trace)
	defer func() {
		err2.SetErrorTracer(previousError)
		err2.SetErrRetTracer(previousReturn)
	}()
	for _, name := range []string{
		"public error", "partial and error", "invalid", "empty", "oversized",
		"foreign signature", "changed digest",
	} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			probe := &probeSigner{Handle: s.local.handle}
			want, calls := ErrInvalidProof, int64(2)
			switch name {
			case "public error":
				probe.publicErr = errors.New(diagnostic)
				want, calls = ErrUnusableSigner, 0
			case "partial and error":
				want = ErrUnusableSigner
			}
			probe.sign = func(data []byte) ([]byte, error) {
				if probe.signCalls.Load() == 1 {
					return s.local.handle.Sign(data) // Preflight succeeds first.
				}
				switch name {
				case "partial and error":
					partial, err := s.local.handle.Sign(data)
					if err != nil {
						return nil, err
					}
					return partial, errors.New(diagnostic)
				case "empty":
					return nil, nil
				case "oversized":
					return make([]byte, 73), nil
				case "foreign signature":
					return s.peer.handle.Sign(data)
				case "changed digest":
					data[len(data)-1] ^= 1
					return s.local.handle.Sign(data)
				default:
					return []byte(diagnostic), nil
				}
			}
			s.prove(t, probe, challenge, want)
			assert.Equal(probe.publicCalls.Load(), int64(1))
			assert.Equal(probe.signCalls.Load(), calls)
		})
	}
	badKey := try.To1(wire.Marshal(map[string]string{diagnostic: diagnostic}))
	s.f.unchanged(t, func() {
		proof, err := ProveLocalAcceptance(s.f.vault, badKey,
			s.local.public, s.peer.public, s.local.handle, challenge)
		assert.Equal(err, ErrInvalidInput)
		assert.SNil(proof)
		assert.Equal(VerifyLocalAcceptanceProof(badKey, s.local.public,
			s.peer.public, challenge, []byte(diagnostic)), ErrInvalidInput)
	})
	assert.ThatNot(strings.Contains(trace.String(), diagnostic))
}

func TestAcceptanceOwnsInputsDigestAndSignature(t *testing.T) {
	for _, stage := range []int64{1, 2} {
		t.Run(map[int64]string{1: "preflight", 2: "acceptance"}[stage],
			func(t *testing.T) {
				defer assert.PushTester(t)()
				s := ready(t)
				challenge := acceptanceChallenge(t)
				root, local := bytes.Clone(s.root.public), bytes.Clone(s.local.public)
				peer, nonce := bytes.Clone(s.peer.public), bytes.Clone(challenge)
				var returned []byte
				probe := &probeSigner{Handle: s.local.handle}
				probe.sign = func(data []byte) ([]byte, error) {
					if probe.signCalls.Load() == stage {
						clear(root)
						clear(local)
						clear(peer)
						clear(nonce)
					}
					var err error
					returned, err = s.local.handle.Sign(data)
					clear(data) // The independent verification digest is owned.
					return returned, err
				}
				s.f.unchanged(t, func() {
					proof := try.To1(ProveLocalAcceptance(s.f.vault, root,
						local, peer, probe, nonce))
					clear(returned) // Proof must not borrow signer-owned memory.
					try.To(VerifyLocalAcceptanceProof(s.root.public, s.local.public,
						s.peer.public, challenge, proof))
				})
				assert.Equal(probe.signCalls.Load(), int64(2))
			})
	}
}

func TestAcceptanceCallbacksRunOutsideVaultTransaction(t *testing.T) {
	defer assert.PushTester(t)()
	s := ready(t)
	challenge := acceptanceChallenge(t)
	probe := &probeSigner{Handle: s.local.handle,
		sign: func(data []byte) ([]byte, error) {
			// Recursive View would block if either signature held the Vault.
			if _, err := onboarding.ListKnownIntroductions(
				s.f.vault, s.root.public); err != nil {
				return nil, err
			}
			return s.local.handle.Sign(data)
		}}
	type result struct {
		proof key.Signature
		err   error
	}
	s.f.unchanged(t, func() {
		done := make(chan result, 1)
		go func() {
			proof, err := ProveLocalAcceptance(s.f.vault, s.root.public,
				s.local.public, s.peer.public, probe, challenge)
			done <- result{proof, err}
		}()
		select {
		case got := <-done:
			assert.NoError(got.err)
			try.To(VerifyLocalAcceptanceProof(s.root.public, s.local.public,
				s.peer.public, challenge, got.proof))
		case <-time.After(5 * time.Second):
			t.Fatal("acceptance signer callback held a Vault transaction")
		}
	})
	assert.Equal(probe.signCalls.Load(), int64(2))
}
