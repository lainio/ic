package pw_test

import (
	"context"
	"net/http"
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

func TestRequestRemoteAcceptanceInvalidConfiguration(t *testing.T) {
	defer assert.PushTester(t)()
	var calls atomic.Int64
	f := newExchange(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			next.ServeHTTP(w, r)
		})
	})
	calls.Store(0)
	before := f.snapshot(t)
	for _, name := range []string{"nil context", "nil vault", "nil root",
		"nil local", "nil peer", "malformed root", "malformed local",
		"malformed peer", "self", "wrong root", "wrong local", "wrong peer",
		"nil signer", "typed nil signer", "foreign signer", "canceled"} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			v, root, local, peer := f.a.store.Vault(), f.root,
				f.a.public, f.b.public
			var signer key.Handle = f.a.signer
			inputCtx := ctx
			switch name {
			case "nil context":
				inputCtx = nil
			case "nil vault":
				v = nil
			case "nil root":
				root = nil
			case "nil local":
				local = nil
			case "nil peer":
				peer = nil
			case "malformed root":
				root = []byte{0xff}
			case "malformed local":
				local = []byte{0xff}
			case "malformed peer":
				peer = []byte{0xff}
			case "self":
				peer = local
			case "wrong root":
				root = f.a.public
			case "wrong local":
				local = f.root
			case "wrong peer":
				peer = f.root
			case "nil signer":
				signer = nil
			case "typed nil signer":
				signer = (*observedSigner)(nil)
			case "foreign signer":
				signer = f.b.signer
			case "canceled":
				cancel()
			}
			signed := len(f.a.signer.signed())
			assert.Error(pw.RequestRemoteAcceptance(inputCtx, v, root, local,
				peer, signer))
			assert.Equal(len(f.a.signer.signed()), signed)
			assert.Equal(calls.Load(), int64(0))
		})
	}
	assert.DeepEqual(f.snapshot(t), before)
}

func TestRequestRemoteAcceptanceLocalPreflight(t *testing.T) {
	for _, name := range []string{"own unknown", "peer unknown", "deny",
		"authorization absent", "signer unusable", "received absent",
		"verified absent", "replaced receipt", "corrupt known", "corrupt deny",
		"corrupt received", "corrupt verified", "corrupt device"} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			var calls atomic.Int64
			f := newExchangeWithAuthorization(
				t,
				func(next http.Handler) http.Handler {
					return http.HandlerFunc(
						func(w http.ResponseWriter, r *http.Request) {
							calls.Add(1)
							next.ServeHTTP(w, r)
						},
					)
				},
				name != "authorization absent",
			)
			calls.Store(0)
			v := f.a.store.Vault()
			want := pw.ErrLocalState
			switch name {
			case "own unknown", "peer unknown":
				subject := f.a.public
				if name == "peer unknown" {
					subject = f.b.public
				}
				deleteExchangeRecord(t, v, "known-introductions-v1", subject)
				want = pw.ErrNotKnown
			case "deny":
				try.To1(policy.DenyLocal(v, f.root, f.a.public, f.b.public))
				want = pw.ErrDenied
			case "authorization absent":
				want = pw.ErrUnauthorized
			case "signer unusable":
				f.a.signer.fail = true
				want = pw.ErrUnusableSigner
			case "received absent", "verified absent":
				field := "received-ad-claims-v1"
				if name == "verified absent" {
					field = "verified-ad-claims-v1"
				}
				deleteExchangeRecord(t, v, "", []byte(field))
				want = pw.ErrAdEvidence
			case "replaced receipt":
				ad := changedAd(
					t,
					f,
					func(ad *ads.Current) { ad.Payload.Token[0] ^= 1 },
				)
				try.To1(ads.ReceiveClaim(v, f.root, f.b.public, ad))
				want = pw.ErrAdEvidence
			case "corrupt known":
				putExchangeRecord(
					t,
					v,
					"known-introductions-v1",
					f.b.public,
					[]byte{0xff},
				)
			case "corrupt device":
				putExchangeRecord(
					t,
					v,
					"local-device-auth-v1",
					[]byte("local-software-signer"),
					[]byte{0xff},
				)
			default:
				field := map[string]string{"corrupt deny": "local-denied-peers-v1",
					"corrupt received": "received-ad-claims-v1", "corrupt verified": "verified-ad-claims-v1"}[name]
				putExchangeRecord(t, v, "", []byte(field), []byte{0xff})
			}
			signed := len(f.a.signer.signed())
			before := f.snapshot(t)
			assert.Equal(f.request(t.Context()), want)
			assert.Equal(calls.Load(), int64(0))
			if name != "signer unusable" {
				assert.Equal(len(f.a.signer.signed()), signed)
			}
			assert.DeepEqual(f.snapshot(t), before)
		})
	}
}

func TestRequestRemoteAcceptanceInvalidAd(t *testing.T) {
	cases := map[string]func(*ads.Current){
		"root":    func(a *ads.Current) { a.Payload.Root = a.Payload.Node },
		"node":    func(a *ads.Current) { a.Payload.Node = a.Payload.Root },
		"device":  func(a *ads.Current) { a.Payload.Device = a.Payload.Root },
		"slot":    func(a *ads.Current) { a.Payload.Slot++ },
		"epoch":   func(a *ads.Current) { a.Payload.Epoch++ },
		"expired": func(a *ads.Current) { a.Payload.ExpiresUnixNano = time.Now().Add(-time.Second).UnixNano() },
	}
	for _, endpoint := range []string{
		"http://192.0.2.1:80/peer/introduction", "http://localhost:80/peer/introduction",
		"http://example.invalid:80/peer/introduction", "https://127.0.0.1:80/peer/introduction",
		"http://127.0.0.1/peer/introduction", "http://127.0.0.1:0/peer/introduction",
		"http://user@127.0.0.1:80/peer/introduction", "http://127.0.0.1:80/peer/%69ntroduction",
		"http://127.0.0.1:80/peer/introduction?x", "http://127.0.0.1:80/peer/introduction#x",
		"http://127.0.0.1:080/peer/introduction", "http://[::ffff:127.0.0.1]:80/peer/introduction",
	} {
		cases[endpoint] = func(a *ads.Current) { a.Payload.PeerIntroductionURL = endpoint }
	}
	cases["signature"] = func(*ads.Current) {}
	cases["malformed"] = func(*ads.Current) {}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			var calls atomic.Int64
			f := newExchange(t, func(next http.Handler) http.Handler {
				return http.HandlerFunc(
					func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						next.ServeHTTP(w, r)
					},
				)
			})
			calls.Store(0)
			ad := changedAd(t, f, change)
			if name == "signature" {
				ad[len(ad)-1] ^= 1
			}
			if name == "malformed" {
				ad = []byte{0xff}
			}
			// Deliberate encrypted-storage corruption, never a production promotion.
			for _, field := range []string{"received-ad-claims-v1", "verified-ad-claims-v1"} {
				putExchangeRecord(
					t,
					f.a.store.Vault(),
					"",
					[]byte(field),
					try.To1(
						wire.Marshal([]any{1, []any{[]any{f.b.public, ad}}}),
					),
				)
			}
			before := f.snapshot(t)
			signed := len(f.a.signer.signed())
			assert.Error(f.request(t.Context()))
			assert.Equal(calls.Load(), int64(0))
			assert.Equal(len(f.a.signer.signed()), signed)
			assert.DeepEqual(f.snapshot(t), before)
		})
	}
}

func changedAd(t *testing.T, f *exchangeFixture,
	change func(*ads.Current),
) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	var ad ads.Current
	try.To(wire.DecMode.Unmarshal(f.ad, &ad))
	change(&ad)
	digest := key.HashTagged(
		ads.SignaturePurpose,
		try.To1(wire.Marshal(ad.Payload)),
	)
	ad.Signature = try.To1(f.b.signer.Sign(digest[:]))
	return try.To1(wire.Marshal(ad))
}
