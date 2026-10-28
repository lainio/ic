package ads_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const receivedKey = "received-ad-claims-v1"
const verifiedKey = "verified-ad-claims-v1"

var boundaryNames = []string{
	"introduction-choice-demo", "received-introductions-v1", "known-introductions-v1",
	"local-current-ad-v1", "local-device-auth-v1", "pw", "pw-open", "trust", "deny",
	"peer-epoch", "peer-device", "recovery", "unrelated",
}

type remoteSigner struct {
	handle key.Handle
	public key.Public
}

func remoteKey(t *testing.T) remoteSigner {
	t.Helper()
	defer assert.PushTester(t)()
	h := key.New()
	return remoteSigner{h, try.To1(h.CBORPublicKey())}
}

type proofExchange struct {
	ad, nonce []byte
	remote    string
}

type remoteFixture struct {
	root, peer, reader  remoteSigner
	publisher, receiver ads.TestVault
	server              *httptest.Server
	endpoint            string
	ad                  []byte
	calls               atomic.Int32
	mu                  sync.Mutex
	exchanges           []proofExchange
	// Set before a request starts; the operation is caller-serialized.
	prove   func([]byte, []byte) (key.Signature, error)
	respond func(http.ResponseWriter, *http.Request, http.Handler)
}

func newRemote(t *testing.T) *remoteFixture {
	t.Helper()
	defer assert.PushTester(t)()
	f := &remoteFixture{root: remoteKey(t), peer: remoteKey(t), reader: remoteKey(t),
		publisher: ads.NewTestVault(t), receiver: ads.NewTestVault(t)}
	path := intro.New(key.Info{Public: f.root.public}).Introduce(f.root.handle, key.Info{Public: f.peer.public})
	acceptance := try.To1(path.SignAcceptance(f.peer.handle))
	for _, v := range []*storage.Vault{f.publisher.Vault(), f.receiver.Vault()} {
		try.To2(onboarding.SaveIntroduction(v, f.root.public, path.Bytes(), acceptance))
		try.To1(onboarding.VerifyReceived(v, f.root.public))
	}
	try.To1(device.BootstrapLocal(f.publisher.Vault(), f.root.public, f.peer.public, f.peer.handle))
	// Bind first: publication and proof capability use the actual bound listener.
	f.server = httptest.NewUnstartedServer(nil)
	f.endpoint = "http://" + f.server.Listener.Addr().String() + "/peer/introduction"
	f.prove = f.currentProof
	handler := peerapi.NewProofHandler(f.publisher.Vault(), f.root.public, f.peer.public, f.endpoint,
		func(ad, nonce []byte) (key.Signature, error) {
			f.mu.Lock()
			prove := f.prove
			f.mu.Unlock()
			return prove(ad, nonce)
		})
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		body, err := io.ReadAll(io.LimitReader(r.Body, 2049))
		if err != nil || len(body) > 2048 {
			t.Error("request exceeded its body bound")
		}
		if r.Method != http.MethodPost || r.URL.RequestURI() != "/peer/ad/proof" || !r.Close {
			t.Error("unexpected peer operation or connection reuse")
		}
		for name := range r.Header {
			switch name {
			case "Content-Type", "Content-Length", "Connection":
			default:
				t.Errorf("unexpected request header: %s", name)
			}
		}
		var request struct {
			Version   int    `json:"version"`
			Ad        []byte `json:"ad"`
			Challenge []byte `json:"challenge"`
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || request.Version != 1 || len(request.Challenge) != 32 {
			t.Error("unexpected proof envelope")
		}
		canonical, err := json.Marshal(request)
		if err != nil || !bytes.Equal(canonical, body) {
			t.Error("noncanonical request envelope")
		}
		f.mu.Lock()
		f.exchanges = append(f.exchanges, proofExchange{request.Ad, request.Challenge, r.RemoteAddr})
		respond := f.respond
		f.mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))
		if respond != nil {
			respond(w, r, handler)
		} else {
			handler.ServeHTTP(w, r)
		}
	})
	f.server.Start()
	t.Cleanup(f.server.Close)
	f.ad = f.publish(t, time.Now())
	try.To1(ads.ReceiveClaim(f.receiver.Vault(), f.root.public, f.peer.public, f.ad))
	return f
}

func (f *remoteFixture) setProof(prove func([]byte, []byte) (key.Signature, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prove = prove
}

func (f *remoteFixture) setResponse(respond func(http.ResponseWriter, *http.Request, http.Handler)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.respond = respond
}

func newProofRecorder(next http.Handler, r *http.Request) *httptest.ResponseRecorder {
	recorded := httptest.NewRecorder()
	next.ServeHTTP(recorded, r)
	return recorded
}

func copyProofResponse(w http.ResponseWriter, recorded *httptest.ResponseRecorder) {
	for name, values := range recorded.Header() {
		w.Header()[name] = slices.Clone(values)
	}
	w.WriteHeader(recorded.Code)
	_, _ = w.Write(recorded.Body.Bytes())
}

func (f *remoteFixture) currentProof(ad, nonce []byte) (key.Signature, error) {
	return ads.ProveCurrentLocal(f.publisher.Vault(), f.root.public, f.peer.public,
		f.peer.handle, f.endpoint, ad, nonce, time.Now())
}

func (f *remoteFixture) publish(t *testing.T, now time.Time) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	ad := try.To1(ads.PublishLocal(f.publisher.Vault(), f.root.public, f.peer.public, f.peer.handle, f.endpoint, now))
	return try.To1(wire.Marshal(ad))
}

func (f *remoteFixture) verify(ctx context.Context) (bool, error) {
	return ads.VerifyReceivedRemote(ctx, f.receiver.Vault(), f.root.public, f.reader.public, f.peer.public)
}

func (f *remoteFixture) readVerified(t *testing.T, want []byte) {
	t.Helper()
	defer assert.PushTester(t)()
	got, found := try.To2(ads.ReadVerifiedClaim(f.receiver.Vault(), f.root.public, f.peer.public))
	assert.Equal(found, want != nil)
	assert.DeepEqual(got, want)
	if found {
		var current ads.Current
		try.To(wire.UnmarshalCanonical(&current, got))
		digest := key.HashTagged(ads.SignaturePurpose, try.To1(wire.Marshal(current.Payload)))
		assert.That(current.Signature.Verify(f.peer.public, digest[:]))
		clear(got)
		again, _ := try.To2(ads.ReadVerifiedClaim(f.receiver.Vault(), f.root.public, f.peer.public))
		assert.DeepEqual(again, want)
	}
}

func remoteState(v *storage.Vault, omitVerified bool) (_ map[string][]byte, err error) {
	defer err2.Handle(&err, nil)
	result := make(map[string][]byte)
	try.To(v.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		try.To(tx.Each(func(name, value []byte) error {
			if !omitVerified || string(name) != verifiedKey {
				result[string(name)] = value
			}
			return nil
		}))
		for _, name := range boundaryNames {
			if !try.To1(tx.HasChild([]byte(name))) {
				continue
			}
			ns := try.To1(tx.Child([]byte(name)))
			try.To(ns.Each(func(k, value []byte) error {
				result[name+"/"+string(k)] = value
				return nil
			}))
		}
		return nil
	}))
	return result, nil
}

func setRemoteRecord(t *testing.T, v *storage.Vault, name string, data []byte) {
	t.Helper()
	defer assert.PushTester(t)()
	try.To(v.Update(func(tx storage.WriteTx) error { return tx.Put([]byte(name), data) }))
}

func mutateRemoteAd(t *testing.T, ad []byte, change func(*ads.Current), signer key.Handle) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	var current ads.Current
	try.To(wire.UnmarshalCanonical(&current, ad))
	change(&current)
	if signer != nil {
		digest := key.HashTagged(ads.SignaturePurpose, try.To1(wire.Marshal(current.Payload)))
		current.Signature = try.To1(signer.Sign(digest[:]))
	}
	return try.To1(wire.Marshal(current))
}
