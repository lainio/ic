package pw_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/ownerapi"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/internal/pw"
)

const ownerExchangePath = "/owner/pw/acceptance/exchange"

// Reuse #84's independently restored real-signing two-node fixture. The
// requester has no peer listener or current ad; only the acceptor publishes.
func requesterOwner(t *testing.T, f *exchangeFixture) (http.Handler, string) {
	t.Helper()
	defer assert.PushTester(t)()
	root, local := bytes.Clone(f.root), bytes.Clone(f.a.public)
	h, file, bind := try.To3(ownerapi.NewAcceptanceCredentials(t.Context(),
		f.a.store.Vault(), root, local, f.a.signer, t.TempDir()))
	clear(root)
	clear(local)
	prove, accept := bind(nil)
	assert.That(prove == nil && accept == nil)
	return h, strings.TrimSpace(strings.TrimPrefix(
		string(try.To1(os.ReadFile(file))), "Authorization: "))
}

func ownerExchangeRequest(
	ctx context.Context,
	auth, subject string,
) *http.Request {
	r := httptest.NewRequestWithContext(ctx, "POST", ownerExchangePath,
		strings.NewReader(`{"subject_public_key_hex":"`+subject+`"}`))
	r.Header.Set("Authorization", auth)
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestOwnerAcceptanceExchangeTwoRestoredNodes(t *testing.T) {
	defer assert.PushTester(t)()
	var challenges, accepts atomic.Int32
	f := newExchange(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case challengePath:
				challenges.Add(1)
			case acceptPath:
				accepts.Add(1)
			}
			next.ServeHTTP(w, r)
		})
	})
	before := f.snapshot(t)
	signed := len(f.a.signer.signed())
	h, auth := requesterOwner(t, f)
	owner := httptest.NewServer(h)
	defer owner.Close()
	r := httptest.NewRequest("GET", "/owner/status", nil)
	r.Header.Set("Authorization", auth)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(w.Code, 200)
	assert.Equal(challenges.Load(), int32(0))
	assert.Equal(accepts.Load(), int32(0))
	assert.Equal(len(f.a.signer.signed()), signed)

	subject := hex.EncodeToString(f.b.public)
	r = ownerExchangeRequest(t.Context(), auth, subject)
	r.URL.Scheme, r.URL.Host = "http", owner.Listener.Addr().String()
	r.RequestURI = ""
	response := try.To1(owner.Client().Do(r))
	body := try.To1(io.ReadAll(io.LimitReader(response.Body, 1025)))
	try.To(response.Body.Close())
	assert.Equal(response.StatusCode, 200)
	assert.Equal(response.Header.Get("Content-Type"), "application/json")
	assert.Equal(response.Header.Get("Cache-Control"), "no-store")
	assert.That(len(body) <= 1024)
	assert.Equal(string(body), `{"subject_public_key_hex":"`+subject+
		`","exchange_verified":true}`)
	assert.Equal(challenges.Load(), int32(1))
	assert.Equal(accepts.Load(), int32(1))
	// Whole encrypted stores, usage counters and identities: no PW/trust,
	// open-pipe record, Known/ad promotion or authorization on either node.
	assert.DeepEqual(f.snapshot(t), before)
	w = httptest.NewRecorder()
	f.server.Config.Handler.ServeHTTP(w,
		ownerExchangeRequest(t.Context(), auth, subject))
	assert.Equal(w.Code, 404)
}

func TestOwnerAcceptanceExchangeRefusals(t *testing.T) {
	for _, scenario := range []string{"unknown", "denied", "unauthorized",
		"missing ad", "missing verification", "replaced ad", "expired ad",
		"unusable signer", "corrupt state", "remote denied", "invalid proof",
		"canceled", "deadline"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			var challenges, accepts atomic.Int32
			f := newExchangeWithAuthorization(
				t,
				func(next http.Handler) http.Handler {
					return http.HandlerFunc(
						func(w http.ResponseWriter, r *http.Request) {
							switch r.URL.Path {
							case challengePath:
								challenges.Add(1)
							case acceptPath:
								accepts.Add(1)
								if scenario == "invalid proof" {
									w.Header().
										Set("Content-Type", "application/json")
									w.Header().
										Set("Cache-Control", "no-store")
									_, _ = io.WriteString(
										w,
										`{"version":1,"acceptor_proof":"cHJpdmF0ZSBkaWFnbm9zdGlj"}`,
									)
									return
								}
							}
							next.ServeHTTP(w, r)
						},
					)
				},
				scenario != "unauthorized",
			)
			v := f.a.store.Vault()
			want := 409
			ctx := t.Context()
			switch scenario {
			case "unknown":
				deleteExchangeRecord(
					t,
					v,
					"known-introductions-v1",
					f.b.public,
				)
			case "denied":
				try.To1(policy.DenyLocal(v, f.root, f.a.public, f.b.public))
			case "missing ad":
				deleteExchangeRecord(
					t,
					v,
					"",
					[]byte("received-ad-claims-v1"),
				)
			case "missing verification":
				deleteExchangeRecord(
					t,
					v,
					"",
					[]byte("verified-ad-claims-v1"),
				)
			case "replaced ad":
				ad := changedAd(
					t,
					f,
					func(ad *ads.Current) { ad.Payload.Token[0] ^= 1 },
				)
				try.To1(ads.ReceiveClaim(v, f.root, f.b.public, ad))
			case "expired ad":
				ad := changedAd(t, f, func(ad *ads.Current) {
					ad.Payload.ExpiresUnixNano = time.Now().
						Add(-time.Second).
						UnixNano()
				})
				// Simulate expired historical evidence, without a wall-clock wait.
				for _, field := range []string{"received-ad-claims-v1", "verified-ad-claims-v1"} {
					putExchangeRecord(t, v, "", []byte(field), try.To1(
						wire.Marshal(
							[]any{1, []any{[]any{f.b.public, ad}}},
						),
					))
				}
			case "unusable signer":
				f.a.signer.fail = true
			case "corrupt state":
				putExchangeRecord(
					t,
					v,
					"known-introductions-v1",
					f.b.public,
					[]byte{0xff},
				)
				want = 500
			case "remote denied":
				try.To1(
					policy.DenyLocal(
						f.b.store.Vault(),
						f.root,
						f.b.public,
						f.a.public,
					),
				)
				want = 502
			case "invalid proof":
				want = 502
			case "canceled", "deadline":
				var cancel context.CancelFunc
				if scenario == "canceled" {
					ctx, cancel = context.WithCancel(ctx)
				} else {
					ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				}
				cancel()
				want = 504
			}
			h, auth := requesterOwner(t, f)
			before := f.snapshot(t)
			w := httptest.NewRecorder()
			h.ServeHTTP(
				w,
				ownerExchangeRequest(
					ctx,
					auth,
					hex.EncodeToString(f.b.public),
				),
			)
			assert.Equal(w.Code, want)
			assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
			wantChallenges, wantAccepts := int32(0), int32(0)
			if want == 502 {
				wantChallenges = 1
			}
			if scenario == "invalid proof" {
				wantAccepts = 1
			}
			assert.Equal(challenges.Load(), wantChallenges)
			assert.Equal(accepts.Load(), wantAccepts)
			assert.DeepEqual(f.snapshot(t), before)
		})
	}
}

func TestOwnerAcceptanceExchangeCancellationReleasesServices(t *testing.T) {
	defer assert.PushTester(t)()
	entered, exited := make(chan struct{}, 1), make(chan struct{}, 1)
	var challenges, accepts atomic.Int32
	f := newExchange(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case challengePath:
				challenges.Add(1)
			case acceptPath:
				accepts.Add(1)
				// Sign and consume on the acceptor, then withhold the reply.
				next.ServeHTTP(httptest.NewRecorder(), r)
				entered <- struct{}{}
				<-r.Context().Done()
				exited <- struct{}{}
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	h, auth := requesterOwner(t, f)
	before := f.snapshot(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		h.ServeHTTP(
			w,
			ownerExchangeRequest(ctx, auth, hex.EncodeToString(f.b.public)),
		)
		done <- w
	}()
	awaitExchange(t, entered)

	// Both service mutation locks and the requester Vault/signer must remain
	// available while the outbound owner request waits for the acceptor.
	for _, owner := range []struct {
		handler http.Handler
		auth    string
	}{{h, auth}, {f.owner, f.ownerAuth}} {
		result := make(chan int, 1)
		go func() {
			r := httptest.NewRequestWithContext(ctx, "POST",
				"/owner/introductions/verify", strings.NewReader("{}"))
			r.Header.Set("Authorization", owner.auth)
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			owner.handler.ServeHTTP(w, r)
			result <- w.Code
		}()
		select {
		case status := <-result:
			assert.Equal(status, 200)
		case <-time.After(time.Second):
			t.Fatal("owner mutation lock or Vault held across outbound HTTP")
		}
	}
	probe := make(chan error, 1)
	go func() {
		probe <- pw.CheckLocalAcceptor(f.a.store.Vault(), f.root, f.a.public,
			f.b.public, f.a.signer)
	}()
	select {
	case err := <-probe:
		assert.NoError(err)
	case <-time.After(time.Second):
		t.Fatal("requester signer held across outbound HTTP")
	}
	cancel()
	w := awaitExchange(t, done)
	assert.Equal(w.Code, 504)
	assert.Equal(w.Body.String(), "Gateway Timeout\n")
	awaitExchange(t, exited)
	assert.Equal(challenges.Load(), int32(1))
	assert.Equal(accepts.Load(), int32(1))
	assert.DeepEqual(f.snapshot(t), before)
}
