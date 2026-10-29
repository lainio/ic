package ownerapi

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestAcceptanceAuthenticatesBeforeConsumingOrSigning(t *testing.T) {
	defer assert.PushTester(t)()
	f := newAcceptanceFixture(t)
	defer f.unchanged(t)()
	nonce := f.challenge(t)
	good := f.requesterProof(t, nonce)
	other := key.Public(try.To1(key.New().CBORPublicKey()))
	otherNonce := currentProofNonce(t)
	for _, scenario := range []string{
		"absent", "forged", "wrong key", "wrong Root", "wrong peer",
		"wrong nonce", "wrong purpose", "modified ad", "foreign ad",
		"old nonce", "wrong selector",
	} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			request, challenge, proof := f, nonce, good
			root, peer := f.root, f.child
			switch scenario {
			case "absent":
				proof = nil
			case "forged":
				proof = bytes.Clone(good)
				proof[len(proof)-1] ^= 1
			case "wrong key":
				proof = try.To1(key.New().Sign(nonce))
			case "wrong Root":
				root = other
			case "wrong peer":
				peer = other
			case "wrong nonce":
				proof = f.requesterProof(t, otherNonce)
			case "wrong purpose":
				choice, _ := try.To2(onboarding.ReadStoredChoice(
					f.vault, f.root, f.child))
				path := choice.Proposal.Introduce(f.signer.Handle,
					key.Info{Public: f.requester})
				proof = try.To1(path.SignAcceptance(f.requesterKey))
			case "modified ad", "foreign ad":
				var ad ads.Current
				try.To(wire.UnmarshalCanonical(&ad, f.ad))
				if scenario == "modified ad" {
					ad.Payload.Token[0] ^= 1
				} else {
					ad.Payload.Node = f.requester
				}
				request.ad = try.To1(wire.Marshal(ad))
			case "old nonce":
				challenge = otherNonce
				proof = f.requesterProof(t, challenge)
			case "wrong selector":
				request.requester = other
			}
			if scenario == "wrong Root" || scenario == "wrong peer" {
				// Hostile key holders can sign arbitrary transcripts without
				// policy checks. Only negative vectors use this raw encoding.
				payload := try.To1(wire.Marshal([]any{
					uint8(1), root, f.requester, peer, nonce,
				}))
				digest := key.HashTagged("pw-local-acceptance/v1", payload)
				proof = try.To1(f.requesterKey.Sign(digest[:]))
			}
			w := deviceRequest(f.peer, "", "POST", acceptancePath,
				request.body(t, challenge, proof))
			want := 400
			if scenario == "old nonce" {
				want = 409 // Authenticated but never issued by this listener.
			}
			assert.Equal(w.Code, want)
			assert.Equal(f.signer.signs.Load(), int32(0))
		})
	}
	checkAcceptanceResponse(t, deviceRequest(f.peer, "", "POST", acceptancePath,
		f.body(t, nonce, good)), f.root, f.child, f.requester, nonce)
	assert.Equal(f.signer.signs.Load(), int32(2))
}

// Save exact records to prove the nonce convention independently of the guard:
// after restoring state, callback failures still refuse the original nonce;
// ad admission failures leave it usable. Repairs exist only in these tests.
func replaceAcceptanceRecord(t *testing.T, vault *storage.Vault,
	namespace string, record, replacement []byte,
) func() {
	t.Helper()
	defer assert.PushTester(t)()
	var original []byte
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		original, _ = try.To2(try.To1(tx.Child([]byte(namespace))).Get(record))
		return nil
	}))
	write := func(value []byte) {
		try.To(vault.Update(func(tx storage.WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			ns := try.To1(tx.ChildForUpdate([]byte(namespace)))
			if value == nil {
				return ns.Delete(record)
			}
			return ns.Put(record, value)
		}))
	}
	write(replacement)
	return func() { write(original) }
}

func TestAcceptanceRechecksGuardsAndSpendsAuthenticatedAttempt(t *testing.T) {
	for _, scenario := range []string{
		"denied", "missing peer Known", "missing own Known", "corrupt Known",
		"missing authorization", "corrupt authorization", "nil signer", "typed nil signer",
		"foreign signer", "unusable signer", "signature failure", "invalid signature",
	} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newAcceptanceFixture(t)
			nonce := f.challenge(t)
			body := f.body(t, nonce, f.requesterProof(t, nonce))
			repair, signs := func() {}, int32(0)
			switch scenario {
			case "denied":
				try.To1(policy.DenyLocal(f.vault, f.root, f.child, f.requester))
				repair = func() {
					try.To1(policy.AllowLocal(f.vault, f.root, f.child, f.requester))
				}
			case "missing peer Known", "missing own Known", "corrupt Known":
				subject := f.requester
				if scenario == "missing own Known" {
					subject = f.child
				}
				var replacement []byte
				if scenario == "corrupt Known" {
					replacement = []byte("private corrupt Known")
				}
				repair = replaceAcceptanceRecord(t, f.vault,
					"known-introductions-v1", subject, replacement)
			case "missing authorization", "corrupt authorization":
				var replacement []byte
				if scenario == "corrupt authorization" {
					replacement = []byte("private corrupt authorization")
				}
				repair = replaceAcceptanceRecord(t, f.vault, "local-device-auth-v1",
					[]byte("local-software-signer"), replacement)
			case "nil signer", "typed nil signer", "foreign signer":
				switch scenario {
				case "nil signer":
					f.publisher.signer = nil
				case "typed nil signer":
					f.publisher.signer = (*deviceProbe)(nil)
				case "foreign signer":
					f.publisher.signer = key.New()
				}
				repair = func() { f.publisher.signer = f.signer }
			case "unusable signer", "signature failure", "invalid signature":
				signs = 2
				if scenario == "unusable signer" {
					signs = 1
				}
				f.signer.sign = func(data []byte) ([]byte, error) {
					if scenario != "unusable signer" && f.signer.signs.Load() == 1 {
						return f.signer.Handle.Sign(data)
					}
					if scenario == "invalid signature" {
						return []byte("private invalid signature"), nil
					}
					return nil, errors.New("private signer /secret/path")
				}
				repair = func() { f.signer.sign = nil }
			}
			t.Run("refusal is read only and quiet", func(t *testing.T) {
				defer assert.PushTester(t)()
				defer f.unchanged(t)()
				var trace bytes.Buffer
				previousError, previousReturn := err2.ErrorTracer(), err2.ErrRetTracer()
				err2.SetErrorTracer(&trace)
				err2.SetErrRetTracer(&trace)
				defer func() {
					err2.SetErrorTracer(previousError)
					err2.SetErrRetTracer(previousReturn)
				}()
				w := deviceRequest(f.peer, "", "POST", acceptancePath, body)
				assert.Equal(w.Code, 409)
				assert.Equal(w.Body.String(), "Conflict\n")
				assert.ThatNot(strings.Contains(trace.String(), "private"))
				assert.ThatNot(strings.Contains(trace.String(), "/secret/path"))
				assert.Equal(f.signer.signs.Load(), signs)
			})
			repair()
			defer f.unchanged(t)()
			assert.Equal(deviceRequest(f.peer, "", "POST", acceptancePath, body).Code, 409)
			assert.Equal(f.signer.signs.Load(), signs)
			// Recovery requires an explicitly requested fresh challenge.
			nonce = f.challenge(t)
			checkAcceptanceResponse(t, deviceRequest(f.peer, "", "POST", acceptancePath,
				f.body(t, nonce, f.requesterProof(t, nonce))),
				f.root, f.child, f.requester, nonce)
		})
	}
}

func TestAcceptanceAdRefusalLeavesNonceUnused(t *testing.T) {
	for _, scenario := range []string{
		"replaced", "expired", "different port", "corrupt", "missing",
	} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newAcceptanceFixture(t)
			nonce := f.challenge(t)
			body := f.body(t, nonce, f.requesterProof(t, nonce))
			var replacement []byte
			want := 409
			switch scenario {
			case "replaced", "expired", "different port":
				var current ads.Current
				try.To(wire.UnmarshalCanonical(&current, f.ad))
				switch scenario {
				case "replaced":
					current.Payload.Token[0] ^= 1
				case "expired":
					current.Payload.ExpiresUnixNano = time.Now().Add(-time.Second).UnixNano()
				default:
					current.Payload.PeerIntroductionURL = "http://127.0.0.1:1/peer/introduction"
				}
				digest := key.HashTagged(ads.SignaturePurpose,
					try.To1(wire.Marshal(current.Payload)))
				current.Signature = try.To1(f.signer.Handle.Sign(digest[:]))
				replacement = try.To1(wire.Marshal(current))
			case "corrupt":
				replacement, want = []byte("private corrupt ad"), 500
			case "missing":
				want = 500 // Partial publication namespace fails closed.
			}
			repair := replaceAcceptanceRecord(t, f.vault, "local-current-ad-v1",
				[]byte("slot-1"), replacement)
			t.Run("no writes or signing", func(t *testing.T) {
				defer assert.PushTester(t)()
				defer f.unchanged(t)()
				w := deviceRequest(f.peer, "", "POST", acceptancePath, body)
				assert.Equal(w.Code, want)
				assert.Equal(f.signer.signs.Load(), int32(0))
			})
			repair()
			defer f.unchanged(t)()
			checkAcceptanceResponse(t, deviceRequest(f.peer, "", "POST", acceptancePath,
				body), f.root, f.child, f.requester, nonce)
		})
	}
}

func TestAcceptanceRequesterDenyPreventsGenuineProof(t *testing.T) {
	defer assert.PushTester(t)()
	f := newAcceptanceFixture(t)
	nonce := f.challenge(t)
	try.To1(policy.DenyLocal(f.requesterVault.vault, f.root, f.requester, f.child))
	defer f.unchanged(t)()
	defer f.requesterVault.unchanged(t)()
	proof, err := pw.ProveLocalAcceptance(f.requesterVault.vault,
		f.root, f.requester, f.child, f.requesterKey, nonce)
	assert.Equal(err, pw.ErrDenied)
	assert.SNil(proof)
	assert.Equal(f.signer.signs.Load(), int32(0))
}
