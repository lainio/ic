package ads

import (
	"bytes"
	"errors"
	"os"
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

func TestCurrentProofRechecksStoredAdKnownAndAuthorization(t *testing.T) {
	defer assert.PushTester(t)()
	root, local, other := newSigner(t), newSigner(t), newSigner(t)
	nonce := proofChallenge(t)
	for _, name := range []string{"no ad", "unbootstrapped", "missing Known", "corrupt Known",
		"missing authorization", "corrupt authorization", "missing current record", "malformed current record",
		"forged current record", "noncanonical current record", "wrong Root record", "extra slot", "expired record", "closed Vault"} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			f, ad := proofPublication(t, root, local)
			switch name {
			case "no ad", "unbootstrapped":
				f = newVault(t)
				try.To(ownEvidence(f.vault, root, local, "known"))
				if name == "unbootstrapped" {
					// A valid signed record cannot supply device authorization.
					try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
						defer err2.Handle(&err, nil)
						ns := try.To1(tx.EnsureChild([]byte(currentNamespace)))
						return ns.Put([]byte(currentSlot), ad)
					}))
				}
			case "closed Vault":
				try.To(f.vault.Close())
			default:
				corrupt := changeClaim(t, ad, func(c *Current) {
					switch name {
					case "forged current record":
						c.Signature[0] ^= 1
					case "wrong Root record":
						c.Payload.Root = other.public
						resignAd(t, c, local.handle)
					case "expired record":
						c.Payload.ExpiresUnixNano = fixedNow.Add(-time.Nanosecond).UnixNano()
						resignAd(t, c, local.handle)
					}
				})
				try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					namespace, record := currentNamespace, []byte(currentSlot)
					switch name {
					case "missing Known", "corrupt Known":
						namespace, record = "known-introductions-v1", local.public
					case "missing authorization", "corrupt authorization":
						namespace, record = "local-device-auth-v1", []byte("local-software-signer")
					}
					ns := try.To1(tx.ChildForUpdate([]byte(namespace)))
					switch name {
					case "missing Known", "missing authorization", "missing current record":
						return ns.Delete(record)
					case "corrupt Known", "corrupt authorization", "malformed current record":
						return ns.Put(record, []byte{0xff})
					case "noncanonical current record":
						return ns.Put(record, append([]byte{0x98, 0x02}, ad[1:]...))
					case "extra slot":
						return ns.Put([]byte("slot-2"), ad)
					}
					return ns.Put(record, corrupt)
				}))
			}
			probe := &observedSigner{Handle: local.handle}
			f.lease.remaining = 0
			f.unchanged(t, func() {
				proof, err := ProveCurrentLocal(f.vault, root.public, local.public, probe, endpoint, ad, nonce, fixedNow)
				assert.Error(err)
				assert.ErrorIsNot(err, storage.ErrKeyUsageExhausted)
				assert.SNil(proof)
				if name == "missing Known" {
					assert.ErrorIs(err, ErrNotKnown)
					assert.SLen(try.To1(onboarding.ListKnownIntroductions(f.vault, root.public)), 0)
				}
			})
			assert.Equal(probe.calls, 0)
		})
	}
}

func TestCurrentProofSignerFailuresReturnNoPartialProof(t *testing.T) {
	defer assert.PushTester(t)()
	local, other := newSigner(t), newSigner(t)
	f, ad := proofPublication(t, local, local)
	nonce := proofChallenge(t)
	cause := errors.New("injected proof signing failure")
	f.lease.remaining = 0
	for _, name := range []string{"nil", "typed nil", "foreign signer", "foreign probe",
		"lost usability", "final failure", "valid output with error", "nil output", "malformed output",
		"oversize output", "truncated output", "foreign output", "mutated digest"} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			probe := &observedSigner{Handle: local.handle, sign: func(call int, data []byte) ([]byte, error) {
				if name == "lost usability" || call == 2 && name == "final failure" {
					return []byte("partial"), cause
				}
				if name == "foreign probe" {
					return other.handle.Sign(data)
				}
				if call == 2 {
					switch name {
					case "valid output with error":
						return try.To1(local.handle.Sign(data)), cause
					case "nil output":
						return nil, nil
					case "malformed output":
						return []byte("malformed"), nil
					case "oversize output":
						return make([]byte, 73), nil
					case "truncated output":
						sig := try.To1(local.handle.Sign(data))
						return sig[:len(sig)-1], nil
					case "foreign output":
						return other.handle.Sign(data)
					case "mutated digest":
						data[0] ^= 1
					}
				}
				return local.handle.Sign(data)
			}}
			var signer key.Handle = probe
			wantCalls := 2
			switch name {
			case "nil":
				signer, wantCalls = nil, 0
			case "typed nil":
				signer, wantCalls = (*observedSigner)(nil), 0
			case "foreign signer":
				probe.Handle, wantCalls = other.handle, 0
			case "lost usability", "foreign probe":
				wantCalls = 1
			}
			f.unchanged(t, func() {
				proof, err := ProveCurrentLocal(f.vault, local.public, local.public, signer, endpoint, ad, nonce, fixedNow)
				assert.Error(err)
				assert.SNil(proof)
				if name == "final failure" || name == "valid output with error" {
					assert.ErrorIs(err, cause)
				}
				assert.Equal(probe.calls, wantCalls)
				current, found := try.To2(ReadCurrentLocal(f.vault, local.public, local.public, fixedNow))
				assert.That(found)
				assert.DeepEqual(try.To1(wire.Marshal(current)), ad)
			})
		})
	}
	// Rejected attempts do not consume authority or poison a later proof.
	f.unchanged(t, func() {
		proof := try.To1(ProveCurrentLocal(f.vault, local.public, local.public, local.handle, endpoint, ad, nonce, fixedNow))
		try.To(VerifyCurrentProof(local.public, local.public, ad, nonce, proof, fixedNow))
	})
}

func TestCurrentProofSignerCallbackReplacementIsRejected(t *testing.T) {
	for _, replaceAt := range []int{1, 2} {
		t.Run(map[int]string{1: "usability probe", 2: "proof signature"}[replaceAt], func(t *testing.T) {
			defer assert.PushTester(t)()
			local := newSigner(t)
			f, ad := proofPublication(t, local, local)
			nonce := proofChallenge(t)
			remaining := f.lease.remaining
			var latest, afterReplacement []byte
			probe := &observedSigner{Handle: local.handle, sign: func(call int, data []byte) ([]byte, error) {
				if call == replaceAt {
					// Synchronous reentry performs reads, randomness, signing and a
					// Vault write. It would deadlock if either Sign held a transaction.
					current := try.To1(PublishLocal(f.vault, local.public, local.public, local.handle, endpoint, fixedNow))
					latest = try.To1(wire.Marshal(current))
					afterReplacement = try.To1(os.ReadFile(f.path))
				}
				return local.handle.Sign(data)
			}}
			proof, err := ProveCurrentLocal(f.vault, local.public, local.public, probe, endpoint, ad, nonce, fixedNow)
			assert.ErrorIs(err, ErrNotCurrent)
			assert.SNil(proof)
			assert.Equal(probe.calls, 2)
			assert.Equal(f.lease.remaining, remaining-1) // Only the callback's publication seals.
			assert.DeepEqual(try.To1(os.ReadFile(f.path)), afterReplacement)
			f.unchanged(t, func() {
				proof := try.To1(ProveCurrentLocal(f.vault, local.public, local.public, local.handle, endpoint, latest, nonce, fixedNow))
				try.To(VerifyCurrentProof(local.public, local.public, latest, nonce, proof, fixedNow))
			})
		})
	}
}

func TestCurrentProofCopiesInputsBeforeSignerCallbacks(t *testing.T) {
	defer assert.PushTester(t)()
	local := newSigner(t)
	f, ad := proofPublication(t, local, local)
	nonce := proofChallenge(t)
	r, subject, input, challenge := bytes.Clone(local.public), bytes.Clone(local.public), bytes.Clone(ad), bytes.Clone(nonce)
	probe := &observedSigner{Handle: local.handle, sign: func(_ int, data []byte) ([]byte, error) {
		clear(r)
		clear(subject)
		clear(input)
		clear(challenge)
		return local.handle.Sign(data)
	}}
	f.unchanged(t, func() {
		proof := try.To1(ProveCurrentLocal(f.vault, r, subject, probe, endpoint, input, challenge, fixedNow))
		assert.Equal(probe.calls, 2)
		try.To(VerifyCurrentProof(local.public, local.public, ad, nonce, proof, fixedNow))
	})
}
