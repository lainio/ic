package ads_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestVerifyRemoteFlowRetryAndRestart(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRemote(t)
	for _, name := range boundaryNames[5:] {
		try.To(f.receiver.Vault().Update(func(tx storage.WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			ns := try.To1(tx.EnsureChild([]byte(name)))
			return ns.Put([]byte("sentinel"), []byte("unchanged"))
		}))
	}
	before := try.To1(remoteState(f.receiver.Vault(), true))
	remaining := f.receiver.Remaining()
	f.publisher.Unchanged(t, func() {
		assert.That(try.To1(f.verify(t.Context())))
		assert.Equal(f.receiver.Remaining(), remaining-1)
		f.readVerified(t, f.ad)
		assert.DeepEqual(try.To1(remoteState(f.receiver.Vault(), true)), before)
		f.receiver.SetRemaining(0)
		f.receiver.Unchanged(t, func() {
			assert.ThatNot(try.To1(f.verify(t.Context()))) // Proof still performed with no seals left.
		})
	})
	assert.Equal(f.calls.Load(), int32(2))
	f.mu.Lock()
	exchanges := slices.Clone(f.exchanges)
	f.mu.Unlock()
	assert.SLen(exchanges, 2)
	for _, exchange := range exchanges {
		assert.DeepEqual(exchange.ad, f.ad)
		assert.SLen(exchange.nonce, 32)
		assert.ThatNot(bytes.Equal(exchange.nonce, make([]byte, 32)))
	}
	assert.ThatNot(bytes.Equal(exchanges[0].nonce, exchanges[1].nonce))
	assert.NotEqual(exchanges[0].remote, exchanges[1].remote) // Fresh connection, too.
	f.receiver.Reopen(t)
	f.receiver.Unchanged(t, func() { f.readVerified(t, f.ad) })
	// Remote supersession changes neither local historical record nor receipt.
	f.publish(t, time.Now())
	f.receiver.Unchanged(t, func() {
		changed, err := f.verify(t.Context())
		assert.ThatNot(changed)
		assert.ErrorIs(err, ads.ErrRemoteProof)
		f.readVerified(t, f.ad)
	})
}

func TestVerifyRemoteRefusesBeforeDial(t *testing.T) {
	cases := []string{"missing receipt", "Received only", "no Known", "corrupt Known", "corrupt evidence",
		"other Known", "Root reader is not a bypass", "wrong Root", "invalid Root", "invalid reader", "invalid subject",
		"self", "nil vault", "nil context", "canceled", "invalid signature", "forged signature", "expired", "slot", "epoch", "device",
		"noncanonical", "foreign subject", "foreign Root", "URL", "credentials", "DNS", "redirect path"}
	for _, scenario := range cases {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRemote(t)
			root, reader, subject, vault, ctx := f.root.public, f.reader.public, f.peer.public, f.receiver.Vault(), t.Context()
			other := remoteKey(t)
			switch scenario {
			case "missing receipt":
				try.To(vault.Update(func(tx storage.WriteTx) error { return tx.Delete([]byte(receivedKey)) }))
			case "Received only", "no Known", "Root reader is not a bypass", "other Known":
				try.To(vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					known := try.To1(tx.ChildForUpdate([]byte("known-introductions-v1")))
					return known.Delete(subject)
				}))
				if scenario == "Root reader is not a bypass" {
					reader = root
				}
				if scenario == "other Known" {
					path := intro.New(key.Info{Public: root}).Introduce(f.root.handle, key.Info{Public: other.public})
					acceptance := try.To1(path.SignAcceptance(other.handle))
					try.To2(onboarding.SaveIntroduction(vault, root, path.Bytes(), acceptance))
					try.To1(onboarding.VerifyReceived(vault, root))
					try.To(vault.Update(func(tx storage.WriteTx) (err error) {
						defer err2.Handle(&err, nil)
						known := try.To1(tx.ChildForUpdate([]byte("known-introductions-v1")))
						return known.Delete(subject)
					}))
				}
			case "corrupt Known", "corrupt evidence":
				name := "known-introductions-v1"
				if scenario == "corrupt evidence" {
					name = "received-introductions-v1"
				}
				try.To(vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					ns := try.To1(tx.ChildForUpdate([]byte(name)))
					return ns.Put(subject, []byte{1, 2, 3})
				}))
			case "wrong Root":
				root = other.public
			case "invalid Root":
				root = []byte{0xff}
			case "invalid reader":
				reader = nil
			case "invalid subject":
				subject = []byte{1}
			case "self":
				reader = subject
			case "nil vault":
				vault = nil
			case "nil context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			default:
				ad := mutateRemoteAd(t, f.ad, func(c *ads.Current) {
					switch scenario {
					case "invalid signature":
						c.Signature = []byte{1}
					case "forged signature":
						c.Payload.Token[0] ^= 1
					case "expired":
						c.Payload.ExpiresUnixNano = time.Now().Add(-time.Second).UnixNano()
					case "slot":
						c.Payload.Slot = 2
					case "epoch":
						c.Payload.Epoch = 1
					case "device":
						c.Payload.Device = other.public
					case "foreign subject":
						c.Payload.Node = other.public
					case "foreign Root":
						c.Payload.Root = other.public
					case "URL":
						c.Payload.PeerIntroductionURL = "http://192.0.2.1:8080/peer/introduction"
					case "credentials":
						c.Payload.PeerIntroductionURL = "http://user:secret@127.0.0.1:8080/peer/introduction"
					case "DNS":
						c.Payload.PeerIntroductionURL = "http://localhost:8080/peer/introduction"
					case "redirect path":
						c.Payload.PeerIntroductionURL = f.endpoint + "/../ad/proof"
					}
				}, nil)
				if scenario == "expired" {
					ad = mutateRemoteAd(t, ad, func(*ads.Current) {}, f.peer.handle)
				}
				if scenario == "noncanonical" {
					ad = append([]byte{0x98, 2}, ad[1:]...)
				}
				// Inject inadmissible stored claims too, rather than relying only on
				// ReceiveClaim to reject them. Verify must independently fail closed.
				table := try.To1(wire.Marshal([]any{1, []any{[]any{subject, ad}}}))
				setRemoteRecord(t, f.receiver.Vault(), receivedKey, table)
			}
			f.publisher.Unchanged(t, func() {
				f.receiver.Unchanged(t, func() {
					changed, err := ads.VerifyReceivedRemote(ctx, vault, root, reader, subject)
					assert.ThatNot(changed)
					assert.Error(err)
					f.readVerified(t, nil)
				})
			})
			assert.Equal(f.calls.Load(), int32(0))
		})
	}
}

func TestVerifyRemoteConcurrentFinalGuards(t *testing.T) {
	for _, scenario := range []string{"receipt replacement", "Known removal", "Known corruption", "evidence corruption", "cancellation"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRemote(t)
			assert.That(try.To1(f.verify(t.Context())))
			historic := bytes.Clone(f.ad)
			candidate := f.publish(t, time.Now())
			try.To1(ads.ReceiveClaim(f.receiver.Vault(), f.root.public, f.peer.public, candidate))
			entered, release := make(chan struct{}), make(chan struct{})
			defer close(release)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			f.setResponse(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				// Complete the genuine publisher proof before changing receiver state.
				recorded := newProofRecorder(next, r)
				close(entered)
				<-release
				copyProofResponse(w, recorded)
			})
			type result struct {
				changed bool
				err     error
			}
			done := make(chan result, 1)
			go func() { changed, err := f.verify(ctx); done <- result{changed, err} }()
			<-entered
			wantReceived := candidate
			switch scenario {
			case "receipt replacement":
				wantReceived = f.publish(t, time.Now())
				try.To1(ads.ReceiveClaim(f.receiver.Vault(), f.root.public, f.peer.public, wantReceived))
			case "Known removal", "Known corruption", "evidence corruption":
				name := "known-introductions-v1"
				if scenario == "evidence corruption" {
					name = "received-introductions-v1"
				}
				try.To(f.receiver.Vault().Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					ns := try.To1(tx.ChildForUpdate([]byte(name)))
					if scenario == "Known removal" {
						return ns.Delete(f.peer.public)
					}
					return ns.Put(f.peer.public, []byte{0xff})
				}))
			case "cancellation":
				cancel()
			}
			before := try.To1(remoteState(f.receiver.Vault(), false))
			f.receiver.Unchanged(t, func() {
				release <- struct{}{}
				result := <-done
				assert.ThatNot(result.changed)
				assert.Error(result.err)
				if scenario == "receipt replacement" {
					assert.ErrorIs(result.err, ads.ErrReceivedClaimChanged)
				}
				f.readVerified(t, historic)
				got, found := try.To2(ads.ReadReceivedClaim(f.receiver.Vault(), f.root.public, f.peer.public))
				assert.That(found)
				assert.DeepEqual(got, wantReceived)
				assert.DeepEqual(try.To1(remoteState(f.receiver.Vault(), false)), before)
			})
		})
	}
}

func TestVerifyRemoteEncryptionFailurePreservesHistory(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, failure := range []string{"exhaustion", "seal failure"} {
			t.Run(failure+map[bool]string{false: "/absent", true: "/historic"}[existing], func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRemote(t)
				var historic []byte
				if existing {
					assert.That(try.To1(f.verify(t.Context())))
					historic = f.ad
				}
				candidate := f.publish(t, time.Now())
				try.To1(ads.ReceiveClaim(f.receiver.Vault(), f.root.public, f.peer.public, candidate))
				want := storage.ErrKeyUsageExhausted
				if failure == "exhaustion" {
					f.receiver.SetRemaining(0)
				} else {
					want = errors.New("injected seal failure")
					f.receiver.SetSealError(want)
				}
				f.receiver.Unchanged(t, func() {
					changed, err := f.verify(t.Context())
					assert.ThatNot(changed)
					assert.ErrorIs(err, want)
					f.readVerified(t, historic)
				})
			})
		}
	}
}
