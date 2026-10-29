package pw_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
)

func TestRequestRemoteAcceptanceInflightChanges(t *testing.T) {
	for _, stage := range []string{challengePath, acceptPath} {
		for _, change := range []string{"local deny", "local receipt", "local Known",
			"local signer", "local device", "peer deny", "peer ad", "peer device"} {
			if stage == acceptPath && change[:4] == "peer" {
				continue
			}
			t.Run(stage+"/"+change, func(t *testing.T) {
				defer assert.PushTester(t)()
				entered, release := make(chan []byte, 1), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				var challenges, accepts atomic.Int64
				f := newExchange(t, func(next http.Handler) http.Handler {
					return http.HandlerFunc(
						func(w http.ResponseWriter, r *http.Request) {
							if r.URL.Path == challengePath {
								challenges.Add(1)
							}
							if r.URL.Path == acceptPath {
								accepts.Add(1)
							}
							if r.URL.Path != stage {
								next.ServeHTTP(w, r)
								return
							}
							reply := httptest.NewRecorder()
							next.ServeHTTP(reply, r)
							entered <- bytes.Clone(reply.Body.Bytes())
							select {
							case <-release:
								copyReply(w, reply)
							case <-r.Context().Done():
							}
						},
					)
				})
				defer unblock()
				done := make(chan error, 1)
				go func() { done <- f.request(t.Context()) }()
				reply := awaitExchange(t, entered)
				want := pw.ErrRemoteAcceptance
				switch change {
				case "local deny":
					try.To1(
						policy.DenyLocal(
							f.a.store.Vault(),
							f.root,
							f.a.public,
							f.b.public,
						),
					)
					want = pw.ErrDenied
				case "local receipt":
					ad := changedAd(
						t,
						f,
						func(ad *ads.Current) { ad.Payload.Token[0] ^= 1 },
					)
					try.To1(
						ads.ReceiveClaim(
							f.a.store.Vault(),
							f.root,
							f.b.public,
							ad,
						),
					)
					want = pw.ErrAdEvidence
				case "local Known":
					deleteExchangeRecord(
						t,
						f.a.store.Vault(),
						"known-introductions-v1",
						f.b.public,
					)
					want = pw.ErrNotKnown
				case "local signer":
					f.a.signer.mu.Lock()
					f.a.signer.fail = true
					f.a.signer.mu.Unlock()
					want = pw.ErrUnusableSigner
				case "local device":
					putExchangeRecord(
						t,
						f.a.store.Vault(),
						"local-device-auth-v1",
						[]byte("local-software-signer"),
						[]byte{0xff},
					)
					want = pw.ErrLocalState
				case "peer deny":
					try.To1(
						policy.DenyLocal(
							f.b.store.Vault(),
							f.root,
							f.b.public,
							f.a.public,
						),
					)
				case "peer ad":
					try.To1(
						ads.PublishLocal(
							f.b.store.Vault(),
							f.root,
							f.b.public,
							f.b.signer,
							f.server.URL+"/peer/introduction",
							time.Now(),
						),
					)
				case "peer device":
					f.b.signer.mu.Lock()
					f.b.signer.fail = true
					f.b.signer.mu.Unlock()
				}
				before := f.snapshot(t)
				unblock()
				assert.Equal(awaitExchange(t, done), want)
				assert.Equal(challenges.Load(), int64(1))
				if stage == challengePath && change[:5] == "local" {
					assert.Equal(accepts.Load(), int64(0))
					var challenge struct{ Challenge []byte }
					try.To(json.Unmarshal(reply, &challenge))
					payload := try.To1(wire.Marshal([]any{1, f.root, f.a.public,
						f.b.public, challenge.Challenge}))
					digest := key.HashTagged("pw-local-acceptance/v1", payload)
					for _, message := range f.a.signer.signed() {
						assert.ThatNot(bytes.Equal(message, digest[:]))
					}
				} else {
					assert.Equal(accepts.Load(), int64(1))
				}
				assert.DeepEqual(f.snapshot(t), before)
			})
		}
	}
}

func awaitExchange[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(10 * time.Second):
		t.Fatal("exchange did not finish")
		var zero T
		return zero
	}
}

func TestRequestRemoteAcceptanceConcurrentInvocations(t *testing.T) {
	defer assert.PushTester(t)()
	issued, release := make(chan []byte, 2), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var accepts atomic.Int64
	f := newExchange(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == acceptPath {
				accepts.Add(1)
			}
			if r.URL.Path != challengePath {
				next.ServeHTTP(w, r)
				return
			}
			reply := httptest.NewRecorder()
			next.ServeHTTP(reply, r)
			issued <- bytes.Clone(reply.Body.Bytes())
			select {
			case <-release:
				copyReply(w, reply)
			case <-r.Context().Done():
			}
		})
	})
	defer unblock()
	before := f.snapshot(t)
	done := make(chan error, 2)
	for range 2 {
		go func() { done <- f.request(t.Context()) }()
	}
	var nonces [][]byte
	for range 2 {
		var reply struct{ Challenge []byte }
		try.To(json.Unmarshal(awaitExchange(t, issued), &reply))
		assert.Equal(len(reply.Challenge), 32)
		nonces = append(nonces, reply.Challenge)
	}
	assert.ThatNot(bytes.Equal(nonces[0], nonces[1]))
	unblock()
	for range 2 {
		assert.NoError(awaitExchange(t, done))
	}
	assert.Equal(accepts.Load(), int64(2))
	for _, nonce := range nonces {
		assertAcceptanceSignedOnce(t, f, nonce)
	}
	assert.DeepEqual(f.snapshot(t), before)
}

func TestRequestRemoteAcceptanceCancellationAndDeadline(t *testing.T) {
	for _, mode := range []string{"challenge cancel", "accept cancel", "overall deadline"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			entered, exited := make(chan struct{}, 1), make(chan struct{}, 1)
			var challenges, accepts atomic.Int64
			stage := acceptPath
			if mode == "challenge cancel" {
				stage = challengePath
			}
			f := newExchange(t, func(next http.Handler) http.Handler {
				return http.HandlerFunc(
					func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path == challengePath {
							challenges.Add(1)
						}
						if r.URL.Path == acceptPath {
							accepts.Add(1)
						}
						if r.URL.Path != stage {
							next.ServeHTTP(w, r)
							return
						}
						// Genuine signing/consumption can precede cancellation.
						reply := httptest.NewRecorder()
						next.ServeHTTP(reply, r)
						entered <- struct{}{}
						<-r.Context().Done()
						exited <- struct{}{}
					},
				)
			})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			before := f.snapshot(t)
			started := time.Now()
			done := make(chan error, 1)
			go func() { done <- f.request(ctx) }()
			awaitExchange(t, entered)
			if mode != "overall deadline" {
				cancel()
			}
			assert.Equal(awaitExchange(t, done), pw.ErrRemoteAcceptance)
			awaitExchange(t, exited)
			assert.That(time.Since(started) < 7*time.Second)
			assert.Equal(challenges.Load(), int64(1))
			if stage == acceptPath {
				assert.Equal(accepts.Load(), int64(1))
			} else {
				assert.Equal(accepts.Load(), int64(0))
			}
			assert.DeepEqual(f.snapshot(t), before)
		})
	}
}
