package ads

import (
	"bytes"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
)

func TestCurrentProofMalformedAdsNeverSignOrWrite(t *testing.T) {
	defer assert.PushTester(t)()
	root, local, other := newSigner(t), newSigner(t), newSigner(t)
	f, good := proofPublication(t, root, local)
	nonce := proofChallenge(t)
	cases := malformedClaims(t, good, other.public)
	for name, change := range map[string]func(*Current){
		"changed token":                func(c *Current) { c.Payload.Token[0] ^= 1 },
		"changed expiry":               func(c *Current) { c.Payload.ExpiresUnixNano++ },
		"changed original signature":   func(c *Current) { c.Signature[0] ^= 1 },
		"truncated original signature": func(c *Current) { c.Signature = c.Signature[:len(c.Signature)-1] },
		"foreign original signature":   func(c *Current) { resignAd(t, c, other.handle) },
		"signed wrong slot":            func(c *Current) { c.Payload.Slot = 2; resignAd(t, c, local.handle) },
		"signed wrong epoch":           func(c *Current) { c.Payload.Epoch = 1; resignAd(t, c, local.handle) },
		"signed wrong device":          func(c *Current) { c.Payload.Device = other.public; resignAd(t, c, local.handle) },
		"signed wrong version":         func(c *Current) { c.Payload.Version = 2; resignAd(t, c, local.handle) },
	} {
		cases[name] = changeClaim(t, good, change)
	}
	f.lease.remaining = 0
	for name, ad := range cases {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			// Even a genuine currentness signature cannot bypass original ad
			// authentication, canonical encoding, or the v1 shape/bindings.
			digest := independentProofDigest(t, root.public, local.public, ad, nonce)
			proof := key.Signature(try.To1(local.handle.Sign(digest[:])))
			probe := &observedSigner{Handle: local.handle}
			f.unchanged(t, func() {
				assert.Error(VerifyCurrentProof(root.public, local.public, ad, nonce, proof, fixedNow))
				got, err := ProveCurrentLocal(f.vault, root.public, local.public, probe, endpoint, ad, nonce, fixedNow)
				assert.Error(err)
				assert.SNil(got)
			})
			assert.Equal(probe.calls, 0)
		})
	}
	f.unchanged(t, func() {
		got, found := try.To2(ReadCurrentLocal(f.vault, root.public, local.public, fixedNow))
		assert.That(found)
		assert.DeepEqual(try.To1(wire.Marshal(got)), good)
	})
}

func TestCurrentProofInputGuards(t *testing.T) {
	defer assert.PushTester(t)()
	root, local, other := newSigner(t), newSigner(t), newSigner(t)
	f, ad := proofPublication(t, root, local)
	nonce := proofChallenge(t)
	proof := try.To1(ProveCurrentLocal(f.vault, root.public, local.public, local.handle, endpoint, ad, nonce, fixedNow))
	f.lease.remaining = 0
	for _, tc := range []struct {
		name          string
		root, subject key.Public
		nonce         []byte
		now           time.Time
	}{
		{"wrong Root", other.public, local.public, nonce, fixedNow},
		{"wrong subject", root.public, other.public, nonce, fixedNow},
		{"truncated Root", root.public[:14], local.public, nonce, fixedNow},
		{"truncated subject", root.public, local.public[:14], nonce, fixedNow},
		{"nil nonce", root.public, local.public, nil, fixedNow},
		{"short nonce", root.public, local.public, nonce[:31], fixedNow},
		{"long nonce", root.public, local.public, append(bytes.Clone(nonce), 0), fixedNow},
		{"zero time", root.public, local.public, nonce, time.Time{}},
		{"negative time", root.public, local.public, nonce, time.Unix(-1, 0)},
		{"overflow time", root.public, local.public, nonce, time.Unix(0, math.MaxInt64).Add(time.Nanosecond)},
		{"exact expiry", root.public, local.public, nonce, fixedNow.Add(TTL)},
		{"after expiry", root.public, local.public, nonce, fixedNow.Add(TTL + time.Nanosecond)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			probe := &observedSigner{Handle: local.handle}
			f.unchanged(t, func() {
				got, err := ProveCurrentLocal(f.vault, tc.root, tc.subject, probe, endpoint, ad, tc.nonce, tc.now)
				assert.Error(err)
				assert.SNil(got)
				assert.Error(VerifyCurrentProof(tc.root, tc.subject, ad, tc.nonce, proof, tc.now))
			})
			assert.Equal(probe.calls, 0)
		})
	}
	for name, public := range malformedClaimKeys(t, local.public) {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			f.unchanged(t, func() {
				for _, binding := range [][2]key.Public{{public, local.public}, {root.public, public}} {
					// Make the ad agree with the malformed expected keys. Matching
					// bytes cannot bypass independent full public-key validation.
					bad := changeClaim(t, ad, func(c *Current) {
						c.Payload.Root, c.Payload.Node, c.Payload.Device = binding[0], binding[1], binding[1]
					})
					probe := &observedSigner{Handle: local.handle}
					got, err := ProveCurrentLocal(f.vault, binding[0], binding[1], probe, endpoint, bad, nonce, fixedNow)
					assert.Error(err)
					assert.SNil(got)
					assert.Equal(probe.calls, 0)
					assert.Error(VerifyCurrentProof(binding[0], binding[1], bad, nonce, proof, fixedNow))
				}
			})
		})
	}
	f.unchanged(t, func() {
		probe := &observedSigner{Handle: local.handle}
		got, err := ProveCurrentLocal(nil, root.public, local.public, probe, endpoint, ad, nonce, fixedNow)
		assert.ErrorIs(err, ErrInvalidInput)
		assert.SNil(got)
		for _, bound := range []string{"", "http://127.0.0.1:8081/peer/introduction", "http://localhost:8080/peer/introduction", "untrusted endpoint"} {
			got, err := ProveCurrentLocal(f.vault, root.public, local.public, probe, bound, ad, nonce, fixedNow)
			assert.ErrorIs(err, ErrNotCurrent)
			assert.SNil(got)
		}
		assert.Equal(probe.calls, 0)
		beforeExpiry := fixedNow.Add(TTL - time.Nanosecond)
		proof := try.To1(ProveCurrentLocal(f.vault, root.public, local.public, probe, endpoint, ad, nonce, beforeExpiry))
		try.To(VerifyCurrentProof(root.public, local.public, ad, nonce, proof, beforeExpiry))
	})
}

func TestCurrentProofRejectsReplayChangedAdAndForeignSignatures(t *testing.T) {
	defer assert.PushTester(t)()
	root, local, other := newSigner(t), newSigner(t), newSigner(t)
	f, ad := proofPublication(t, root, local)
	nonce := proofChallenge(t)
	proof := try.To1(ProveCurrentLocal(f.vault, root.public, local.public, local.handle, endpoint, ad, nonce, fixedNow))
	digest := independentProofDigest(t, root.public, local.public, ad, nonce)
	foreign := key.Signature(try.To1(other.handle.Sign(digest[:])))
	changed := bytes.Clone(proof)
	changed[len(changed)-1] ^= 1
	f.unchanged(t, func() {
		for _, bad := range []key.Signature{nil, {}, {1, 2, 3}, make([]byte, 73), proof[:len(proof)-1], append(bytes.Clone(proof), 0), changed, foreign} {
			assert.ErrorIs(VerifyCurrentProof(root.public, local.public, ad, nonce, bad, fixedNow), ErrInvalidProof)
		}
		assert.ErrorIs(VerifyCurrentProof(root.public, local.public, ad, proofChallenge(t), proof, fixedNow), ErrInvalidProof)
		for _, change := range []func(*Current){
			func(c *Current) { c.Payload.Token[0] ^= 1 },
			func(c *Current) { c.Payload.ExpiresUnixNano++ },
			func(c *Current) { c.Payload.PeerIntroductionURL = "http://127.0.0.1:9090/peer/introduction" },
			func(*Current) {}, // A new original signature also changes the exact ad.
		} {
			altered := changeClaim(t, ad, func(c *Current) { change(c); resignAd(t, c, local.handle) })
			try.To1(decodeCurrent(altered, root.public, local.public))
			assert.ErrorIs(VerifyCurrentProof(root.public, local.public, altered, nonce, proof, fixedNow), ErrInvalidProof)
		}
	})
}

func TestCurrentProofErrorsDoNotDiscloseUntrustedInput(t *testing.T) {
	defer assert.PushTester(t)()
	local := newSigner(t)
	f, ad := proofPublication(t, local, local)
	nonce := proofChallenge(t)
	proof := try.To1(ProveCurrentLocal(f.vault, local.public, local.public, local.handle, endpoint, ad, nonce, fixedNow))
	var trace bytes.Buffer
	previousError, previousReturn := err2.ErrorTracer(), err2.ErrRetTracer()
	err2.SetErrorTracer(&trace)
	err2.SetErrRetTracer(&trace)
	defer func() { err2.SetErrorTracer(previousError); err2.SetErrRetTracer(previousReturn) }()
	const secret = "UNTRUSTED_PRIVATE_VALUE"
	hostileMap := try.To1(wire.Marshal(map[string]string{secret: secret}))
	for _, bad := range [][]byte{hostileMap, changeClaim(t, ad, func(c *Current) {
		c.Payload.PeerIntroductionURL = "http://127.0.0.1:" + secret + "/peer/introduction"
	})} {
		probe := &observedSigner{Handle: local.handle}
		f.unchanged(t, func() {
			_, err := ProveCurrentLocal(f.vault, local.public, local.public, probe, endpoint, bad, nonce, fixedNow)
			assert.Error(err)
			assert.ThatNot(strings.Contains(err.Error(), secret))
			assert.Error(VerifyCurrentProof(local.public, local.public, bad, nonce, proof, fixedNow))
			assert.Error(VerifyCurrentProof(hostileMap, local.public, ad, nonce, proof, fixedNow))
		})
		assert.Equal(probe.calls, 0)
	}
	assert.ThatNot(strings.Contains(trace.String(), secret))
}
