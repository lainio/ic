package ownerapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

type adFetchFixture struct {
	deviceFixture
	root, subject, local key.Public
	parent, peer         key.Handle
	choice               onboarding.StoredChoice
	current              ads.Current
	handler              http.Handler
	auth                 string
	signer               *deviceProbe
}

func newAdFetchFixture(t *testing.T) adFetchFixture {
	t.Helper()
	defer assert.PushTester(t)()
	f := adFetchFixture{deviceFixture: newDeviceFixture(t), parent: key.New(), peer: key.New(), signer: &deviceProbe{Handle: key.New()}}
	f.root = try.To1(f.parent.CBORPublicKey())
	f.subject = try.To1(f.peer.CBORPublicKey())
	f.local = try.To1(f.signer.Handle.CBORPublicKey())
	f.choice.Proposal = intro.New(key.Info{Public: f.root}).Introduce(f.parent, key.Info{Public: f.subject})
	f.choice.Acceptance = try.To1(f.choice.Proposal.SignAcceptance(f.peer))
	f.current = ads.Current{Payload: ads.Payload{
		Version: 1, Root: f.root, Node: f.subject, Device: f.subject, Slot: 1,
		Token: bytes.Repeat([]byte{1}, 32), ExpiresUnixNano: time.Now().Add(ads.TTL).UnixNano(),
		PeerIntroductionURL: "http://127.0.0.1:1/peer/introduction",
	}}
	digest := key.HashTagged(ads.SignaturePurpose, try.To1(wire.Marshal(f.current.Payload)))
	f.current.Signature = try.To1(f.peer.Sign(digest[:]))
	root, local := bytes.Clone(f.root), bytes.Clone(f.local)
	f.handler, f.auth, _ = publicationCredential(t, f.vault, root, local, f.signer)
	clear(root)
	clear(local)
	return f
}

func adDocument(t *testing.T, choice onboarding.StoredChoice, ad []byte) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	return try.To1(json.Marshal(struct {
		Version      int             `json:"version"`
		Introduction json.RawMessage `json:"introduction"`
		Ad           []byte          `json:"ad"`
	}{1, try.To1(onboarding.EncodeIntroduction(choice)), ad}))
}

func adServer(t *testing.T, document []byte) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(document)
	}))
	t.Cleanup(server.Close)
	return server
}

func adFetchRequest(auth, endpoint string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, adFetchPath, strings.NewReader(`{"peer_url":"`+endpoint+`/peer/ad"}`))
	r.Header.Set("Authorization", auth)
	r.Header.Set("Content-Type", "application/json")
	return r
}

func (f adFetchFixture) fetch(endpoint string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, adFetchRequest(f.auth, endpoint))
	return w
}

func assertAdFetchResult(t *testing.T, w *httptest.ResponseRecorder, subject key.Public, created, changed bool) {
	t.Helper()
	defer assert.PushTester(t)()
	assert.Equal(w.Code, 200, w.Body.String())
	assert.Equal(w.Header().Get("Content-Type"), "application/json")
	assert.Equal(w.Header().Get("Cache-Control"), "no-store")
	var result map[string]any
	try.To(json.Unmarshal(w.Body.Bytes(), &result))
	assert.DeepEqual(result, map[string]any{
		"subject_public_key_hex": hex.EncodeToString(subject),
		"introduction_created":   created, "ad_changed": changed,
	})
}

func (f adFetchFixture) noAuthority(t *testing.T) {
	t.Helper()
	defer assert.PushTester(t)()
	assert.SEmpty(try.To1(onboarding.ListKnownIntroductions(f.vault, f.root)))
	// The dedicated Vault has no authorities. Probe the existing namespaces
	// and root records too; there is no receiver VerifyAd/PW implementation.
	try.To(f.vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		for _, name := range []string{"known-introductions-v1", "introduction-choice-demo", "local-device-auth-v1", "local-current-ad-v1"} {
			assert.ThatNot(try.To1(tx.HasChild([]byte(name))))
		}
		return tx.Each(func(k, _ []byte) error {
			assert.Equal(string(k), "received-ad-claims-v1")
			return nil
		})
	}))
	assert.Equal(f.signer.signs.Load(), int32(0))
	assert.Equal(f.signer.publics.Load(), int32(0))
}

func TestAdFetchReceivedOnlyRetryAndLostAcknowledgement(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "acknowledged", true: "lost response"}[lost], func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newAdFetchFixture(t)
			ad := try.To1(wire.Marshal(f.current))
			server := adServer(t, adDocument(t, f.choice, ad))
			before := f.lease.remaining.Load()
			if lost {
				w := &ownerStatusFailedWriter{ResponseRecorder: httptest.NewRecorder()}
				f.handler.ServeHTTP(w, adFetchRequest(f.auth, server.URL))
				assert.Equal(w.headerCalls, 1)
				assert.Equal(w.writeCalls, 1)
			} else {
				assertAdFetchResult(t, f.fetch(server.URL), f.subject, true, true)
			}
			assert.Equal(f.lease.remaining.Load(), before-2)
			assert.DeepEqual(try.To1(onboarding.ListIntroductions(f.vault, f.root)), []key.Public{f.subject})
			got, found := try.To2(ads.ReadReceivedClaim(f.vault, f.root, f.subject))
			assert.That(found)
			assert.DeepEqual(got, ad)
			f.noAuthority(t)
			// Both primitive no-ops must succeed with no remaining encryption.
			f.lease.remaining.Store(0)
			defer f.unchanged(t)()
			assertAdFetchResult(t, f.fetch(server.URL), f.subject, false, false)
		})
	}
}

func TestAdFetchAdmissionBindingAndUntrustedClaims(t *testing.T) {
	for _, scenario := range []string{"forged signature", "expired", "Root", "subject", "device", "slot", "epoch", "version", "token", "signature empty", "signature oversize", "negative expiry", "bad endpoint", "foreign introduction", "proof", "acceptance", "self", "noncanonical", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newAdFetchFixture(t)
			other := try.To1(key.New().CBORPublicKey())
			want := 502
			switch scenario {
			case "forged signature":
				f.current.Signature = []byte("forged")
				want = 200
			case "expired":
				f.current.Payload.ExpiresUnixNano = 0
				digest := key.HashTagged(ads.SignaturePurpose, try.To1(wire.Marshal(f.current.Payload)))
				f.current.Signature = try.To1(f.peer.Sign(digest[:]))
				want = 200
			case "Root":
				f.current.Payload.Root = other
			case "subject":
				f.current.Payload.Node = other
			case "device":
				f.current.Payload.Device = other
			case "slot":
				f.current.Payload.Slot = 2
			case "epoch":
				f.current.Payload.Epoch = 1
			case "version":
				f.current.Payload.Version = 2
			case "token":
				f.current.Payload.Token = []byte{1}
			case "signature empty":
				f.current.Signature = nil
			case "signature oversize":
				f.current.Signature = bytes.Repeat([]byte{1}, 73)
			case "negative expiry":
				f.current.Payload.ExpiresUnixNano = -1
			case "bad endpoint":
				f.current.Payload.PeerIntroductionURL = "http://example.com:80/peer/introduction"
			case "foreign introduction":
				parent := key.New()
				f.choice.Proposal = intro.New(key.Info{Public: try.To1(parent.CBORPublicKey())}).Introduce(parent, key.Info{Public: f.subject})
				f.choice.Acceptance = try.To1(f.choice.Proposal.SignAcceptance(f.peer))
			case "proof":
				f.choice.Proposal[1].Body.Options.Position++
			case "acceptance":
				f.choice.Acceptance = []byte("invalid acceptance")
			case "self":
				f.handler, f.auth, _ = publicationCredential(t, f.vault, f.root, f.subject, f.signer)
				want = 400
			}
			ad := try.To1(wire.Marshal(f.current))
			if scenario == "noncanonical" {
				ad = append([]byte{0x98, 0x02}, ad[1:]...)
			}
			if scenario == "oversize" {
				ad = bytes.Repeat([]byte{0}, 1025)
			}
			server := adServer(t, adDocument(t, f.choice, ad))
			if want != 200 {
				defer f.unchanged(t)()
			}
			w := f.fetch(server.URL)
			assert.Equal(w.Code, want)
			if want == 200 {
				assertAdFetchResult(t, w, f.subject, true, true)
				got, found := try.To2(ads.ReadReceivedClaim(f.vault, f.root, f.subject))
				assert.That(found)
				assert.DeepEqual(got, ad)
			} else {
				assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
				assert.SEmpty(try.To1(onboarding.ListIntroductions(f.vault, f.root)))
			}
			f.noAuthority(t)
		})
	}
}

func TestAdFetchUnavailableToEarlierCredentialsAndPeer(t *testing.T) {
	defer assert.PushTester(t)()
	for _, constructor := range []func(context.Context, *storage.Vault, key.Public, key.Public, string) (http.Handler, string, error){
		NewStatusCredentials, NewReadCredentials, NewEvidenceCredentials,
		func(ctx context.Context, v *storage.Vault, root, child key.Public, dir string) (http.Handler, string, error) {
			return NewDeviceCredentials(ctx, v, root, child, nil, dir)
		},
	} {
		h, file := try.To2(constructor(t.Context(), nil, nil, nil, t.TempDir()))
		auth := strings.TrimSpace(strings.TrimPrefix(string(try.To1(os.ReadFile(file))), "Authorization: "))
		for _, handler := range []http.Handler{h, peerapi.NewHandler(nil, nil, nil), peerapi.NewAdHandler(nil, nil, nil, "")} {
			for _, method := range []string{"GET", "POST", "PUT"} {
				r := adFetchRequest(auth, "http://127.0.0.1:1")
				r.Method = method
				body := &ownerStatusUnreadBody{}
				r.Body = io.NopCloser(body)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				assert.Equal(w.Code, 404)
				assert.Equal(body.reads, 0)
			}
		}
	}
}
