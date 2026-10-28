package ownerapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
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

const currentProofPath = "/peer/ad/proof"

type proofFixture struct {
	deviceFixture
	root, child key.Public
	signer      *deviceProbe
	owner, peer http.Handler
	auth        string
	endpoint    string
	listener    net.Listener
	ad          []byte
}

func proofCredentials(t *testing.T, v *storage.Vault, root, child key.Public, signer key.Handle) (http.Handler, string, func(net.Listener) CurrentAdProver) {
	t.Helper()
	defer assert.PushTester(t)()
	h, file, bind := try.To3(NewPublicationProofCredentials(t.Context(), v, root, child, signer, t.TempDir()))
	return h, strings.TrimSpace(strings.TrimPrefix(string(try.To1(os.ReadFile(file))), "Authorization: ")), bind
}

func newProofFixture(t *testing.T) proofFixture {
	t.Helper()
	defer assert.PushTester(t)()
	f := proofFixture{deviceFixture: newDeviceFixture(t), signer: &deviceProbe{Handle: key.New()}}
	root := key.New()
	f.root, f.child = try.To1(root.CBORPublicKey()), try.To1(f.signer.Handle.CBORPublicKey())
	path := intro.New(key.Info{Public: f.root}).Introduce(root, key.Info{Public: f.child})
	try.To1(onboarding.SignAfterStoredChoice(f.vault, f.signer.Handle, f.root, f.root, path))
	choice, _ := try.To2(onboarding.ReadStoredChoice(f.vault, f.root, f.child))
	try.To2(onboarding.SaveIntroduction(f.vault, f.root, path.Bytes(), choice.Acceptance))
	try.To1(onboarding.VerifyReceived(f.vault, f.root))
	var bind func(net.Listener) CurrentAdProver
	f.owner, f.auth, bind = proofCredentials(t, f.vault, f.root, f.child, f.signer)
	listener := publicationListener(t)
	f.listener = listener
	f.endpoint = "http://" + listener.Addr().String() + "/peer/introduction"
	f.peer = peerapi.NewProofHandler(f.vault, f.root, f.child, f.endpoint, bind(listener))
	assert.Equal(deviceRequest(f.owner, f.auth, "POST", bootstrapPath, "{}").Code, 200)
	assert.Equal(deviceRequest(f.owner, f.auth, "POST", publishPath, "{}").Code, 200)
	f.ad = f.current(t)
	f.signer.publics.Store(0)
	f.signer.signs.Store(0)
	return f
}

func (f proofFixture) current(t *testing.T) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	w := httptest.NewRecorder()
	f.peer.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/peer/ad", nil))
	assert.Equal(w.Code, 200)
	var document struct{ Ad []byte }
	try.To(json.Unmarshal(w.Body.Bytes(), &document))
	return document.Ad
}

func currentProofBody(t *testing.T, ad, nonce []byte) string {
	t.Helper()
	defer assert.PushTester(t)()
	return string(try.To1(json.Marshal(map[string]any{"version": 1, "ad": ad, "challenge": nonce})))
}

func currentProofNonce(t *testing.T) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	nonce := make([]byte, 32)
	try.To1(rand.Read(nonce))
	return nonce
}

func checkCurrentProofResponse(t *testing.T, w *httptest.ResponseRecorder, root, subject key.Public, ad, nonce []byte) key.Signature {
	t.Helper()
	defer assert.PushTester(t)()
	assert.Equal(w.Code, 200)
	assert.Equal(w.Header().Get("Content-Type"), "application/json")
	assert.Equal(w.Header().Get("Cache-Control"), "no-store")
	assert.Empty(w.Header().Get("WWW-Authenticate"))
	assert.That(w.Body.Len() <= 1024)
	var fields map[string]json.RawMessage
	try.To(json.Unmarshal(w.Body.Bytes(), &fields))
	assert.Equal(len(fields), 2)
	assert.Equal(string(fields["version"]), "1")
	var encoded string
	try.To(json.Unmarshal(fields["proof"], &encoded))
	proof := key.Signature(try.To1(base64.StdEncoding.Strict().DecodeString(encoded)))
	assert.Equal(base64.StdEncoding.EncodeToString(proof), encoded)
	try.To(ads.VerifyCurrentProof(root, subject, ad, nonce, proof, time.Now()))
	return proof
}

func TestPeerProofNoWritesOrEncryptionAndNoWriterRetry(t *testing.T) {
	defer assert.PushTester(t)()
	f := newProofFixture(t)
	f.lease.remaining.Store(0)
	defer f.unchanged(t)()
	nonce := currentProofNonce(t)
	body := currentProofBody(t, f.ad, nonce)
	first := deviceRequest(f.peer, "", "POST", currentProofPath, body)
	proof := checkCurrentProofResponse(t, first, f.root, f.child, f.ad, nonce)
	otherNonce := currentProofNonce(t)
	second := deviceRequest(f.peer, "Bearer irrelevant", "POST", currentProofPath, currentProofBody(t, f.ad, otherNonce))
	otherProof := checkCurrentProofResponse(t, second, f.root, f.child, f.ad, otherNonce)
	assert.ThatNot(bytes.Equal(proof, otherProof))
	assert.Error(ads.VerifyCurrentProof(f.root, f.child, f.ad, otherNonce, proof, time.Now()))
	other := try.To1(key.New().CBORPublicKey())
	assert.Error(ads.VerifyCurrentProof(other, f.child, f.ad, nonce, proof, time.Now()))
	assert.Error(ads.VerifyCurrentProof(f.root, other, f.ad, nonce, proof, time.Now()))
	failed := &ownerStatusFailedWriter{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest(http.MethodPost, currentProofPath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	f.peer.ServeHTTP(failed, r)
	assert.Equal(failed.headerCalls, 1)
	assert.Equal(failed.writeCalls, 1)
	assert.DeepEqual(f.current(t), f.ad)
	get := httptest.NewRecorder()
	f.peer.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/peer/introduction", nil))
	assert.Equal(get.Code, 200)
	assert.Equal(f.signer.signs.Load(), int32(6)) // Probe + proof once per POST; GETs never sign.
}

func TestPeerProofReplacementRejectsUnexpiredAuthenticAd(t *testing.T) {
	defer assert.PushTester(t)()
	f := newProofFixture(t)
	nonce := currentProofNonce(t)
	proof := checkCurrentProofResponse(t, deviceRequest(f.peer, "", "POST", currentProofPath,
		currentProofBody(t, f.ad, nonce)), f.root, f.child, f.ad, nonce)
	assert.Equal(deviceRequest(f.owner, f.auth, "POST", publishPath, "{}").Code, 200)
	latest := f.current(t)
	assert.ThatNot(bytes.Equal(latest, f.ad))
	try.To(ads.VerifyCurrentProof(f.root, f.child, f.ad, nonce, proof, time.Now())) // Still authentic and unexpired.
	assert.Error(ads.VerifyCurrentProof(f.root, f.child, latest, nonce, proof, time.Now()))
	defer f.unchanged(t)()
	signs := f.signer.signs.Load()
	w := deviceRequest(f.peer, "", "POST", currentProofPath, currentProofBody(t, f.ad, nonce))
	assert.Equal(w.Code, 409)
	assert.Equal(f.signer.signs.Load(), signs)
	checkCurrentProofResponse(t, deviceRequest(f.peer, "", "POST", currentProofPath,
		currentProofBody(t, latest, nonce)), f.root, f.child, latest, nonce)
}

func TestPeerProofGuardFailuresDoNotSignOrRepair(t *testing.T) {
	for _, scenario := range []string{"missing Known", "corrupt Known", "missing authorization", "corrupt authorization",
		"corrupt ad", "expired", "different endpoint", "nil signer", "typed nil signer", "foreign signer", "unusable signer",
		"proof signer error", "invalid proof", "forged ad", "modified payload", "closed Vault"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newProofFixture(t)
			signs := int32(0)
			switch scenario {
			case "missing Known", "corrupt Known", "missing authorization", "corrupt authorization", "corrupt ad":
				try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					namespace, record := "local-current-ad-v1", []byte("slot-1")
					if strings.Contains(scenario, "Known") {
						namespace, record = "known-introductions-v1", f.child
					} else if strings.Contains(scenario, "authorization") {
						namespace, record = "local-device-auth-v1", []byte("local-software-signer")
					}
					ns := try.To1(tx.ChildForUpdate([]byte(namespace)))
					if strings.HasPrefix(scenario, "missing") {
						return ns.Delete(record)
					}
					return ns.Put(record, []byte{0xff})
				}))
			case "expired":
				current := try.To1(ads.PublishLocal(f.vault, f.root, f.child, f.signer.Handle, f.endpoint, time.Now().Add(-ads.TTL)))
				f.ad = try.To1(wire.Marshal(current))
			case "different endpoint", "nil signer", "typed nil signer", "foreign signer":
				var handle key.Handle = f.signer
				switch scenario {
				case "nil signer":
					handle = nil
				case "typed nil signer":
					handle = (*deviceProbe)(nil)
				case "foreign signer":
					f.signer.Handle = key.New()
				}
				_, _, bind := proofCredentials(t, f.vault, f.root, f.child, handle)
				bound := f.listener
				if scenario == "different endpoint" {
					bound = publicationListener(t)
				}
				f.peer = peerapi.NewProofHandler(f.vault, f.root, f.child, f.endpoint, bind(bound))
			case "unusable signer", "proof signer error", "invalid proof":
				signs = 2
				if scenario == "unusable signer" {
					signs = 1
				}
				f.signer.sign = func(data []byte) ([]byte, error) {
					if scenario != "unusable signer" && f.signer.signs.Load() == 1 {
						return f.signer.Handle.Sign(data)
					}
					if scenario == "invalid proof" {
						return []byte("private malformed signature"), nil
					}
					return nil, errors.New("private signer /secret/path diagnostic")
				}
			case "forged ad", "modified payload":
				var current ads.Current
				try.To(wire.UnmarshalCanonical(&current, f.ad))
				if scenario == "forged ad" {
					current.Signature[0] ^= 1
				} else {
					current.Payload.Token[0] ^= 1
				}
				f.ad = try.To1(wire.Marshal(current))
			case "closed Vault":
				try.To(f.vault.Close())
			}
			f.lease.remaining.Store(0)
			defer f.unchanged(t)()
			var trace bytes.Buffer
			previousError, previousReturn := err2.ErrorTracer(), err2.ErrRetTracer()
			err2.SetErrorTracer(&trace)
			err2.SetErrRetTracer(&trace)
			defer func() { err2.SetErrorTracer(previousError); err2.SetErrRetTracer(previousReturn) }()
			w := deviceRequest(f.peer, "", "POST", currentProofPath, currentProofBody(t, f.ad, currentProofNonce(t)))
			assert.Equal(w.Code, 409)
			assert.Equal(w.Body.String(), "Conflict\n")
			assert.ThatNot(strings.Contains(trace.String(), "private"))
			assert.ThatNot(strings.Contains(trace.String(), "/secret/path"))
			assert.Equal(f.signer.signs.Load(), signs)
		})
	}
}

func TestProofCapabilityBindingAndCredentialSeparation(t *testing.T) {
	defer assert.PushTester(t)()
	f := newProofFixture(t)
	defer f.unchanged(t)()
	_, _, disabled := proofCredentials(t, f.vault, f.root, f.child, f.signer)
	assert.That(disabled(nil) == nil)
	assert.That(disabled(publicationListener(t)) == nil)
	root, child := bytes.Clone(f.root), bytes.Clone(f.child)
	_, _, bind := proofCredentials(t, f.vault, root, child, f.signer)
	clear(root)
	clear(child)
	prover := bind(f.listener)
	bind(publicationListener(t)) // Cannot redirect the publication or the prover.
	bind(nil)
	nonce := currentProofNonce(t)
	proof := try.To1(prover(f.ad, nonce))
	try.To(ads.VerifyCurrentProof(f.root, f.child, f.ad, nonce, proof, time.Now()))
	signs := f.signer.signs.Load()
	for _, constructor := range []func(context.Context, *storage.Vault, key.Public, key.Public, string) (http.Handler, string, error){
		NewStatusCredentials, NewReadCredentials, NewEvidenceCredentials,
		func(ctx context.Context, v *storage.Vault, root, child key.Public, dir string) (http.Handler, string, error) {
			return NewDeviceCredentials(ctx, v, root, child, nil, dir)
		},
		func(ctx context.Context, v *storage.Vault, root, child key.Public, dir string) (http.Handler, string, error) {
			h, file, _, err := NewPublicationCredentials(ctx, v, root, child, nil, dir)
			return h, file, err
		},
	} {
		h, file := try.To2(constructor(t.Context(), nil, nil, nil, t.TempDir()))
		auth := strings.TrimSpace(strings.TrimPrefix(string(try.To1(os.ReadFile(file))), "Authorization: "))
		assert.Equal(deviceRequest(h, auth, "POST", currentProofPath, "{}").Code, 404)
	}
	assert.Equal(deviceRequest(f.owner, f.auth, "POST", currentProofPath, "{}").Code, 404)
	assert.Equal(f.signer.signs.Load(), signs)
}

func TestProofSerializesWithOwnerMutations(t *testing.T) {
	for _, blockAt := range []int32{1, 2} {
		for _, path := range []string{publishPath, bootstrapPath, "/owner/introductions/verify", "/owner/introductions"} {
			t.Run(fmt.Sprint(path, "/sign=", blockAt), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newProofFixture(t)
				mutationBody := "{}"
				if path == "/owner/introductions" || path == "/owner/introductions/verify" {
					other := key.New()
					choice, _ := try.To2(onboarding.ReadStoredChoice(f.vault, f.root, f.child))
					proposal := choice.Proposal.Introduce(f.signer.Handle, key.Info{Public: try.To1(other.CBORPublicKey())})
					acceptance := try.To1(proposal.SignAcceptance(other))
					if path == "/owner/introductions/verify" {
						try.To2(onboarding.SaveIntroduction(f.vault, f.root, proposal.Bytes(), acceptance))
					} else {
						mutationBody = string(try.To1(onboarding.EncodeIntroduction(onboarding.StoredChoice{Proposal: proposal, Acceptance: acceptance})))
					}
				}
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				defer unblock()
				f.signer.sign = func(data []byte) ([]byte, error) {
					if f.signer.signs.Load() == blockAt {
						close(entered)
						<-release
					}
					return f.signer.Handle.Sign(data)
				}
				nonce := currentProofNonce(t)
				body := currentProofBody(t, f.ad, nonce)
				proofDone := make(chan *httptest.ResponseRecorder, 1)
				go func() { proofDone <- deviceRequest(f.peer, "", "POST", currentProofPath, body) }()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("proof did not enter signer")
				}
				mutationDone, started := make(chan *httptest.ResponseRecorder, 1), make(chan struct{})
				go func() {
					close(started)
					mutationDone <- deviceRequest(f.owner, f.auth, "POST", path, mutationBody)
				}()
				<-started
				select {
				case <-mutationDone:
					t.Fatal("owner mutation escaped the admitted proof's lock")
				case <-time.After(30 * time.Millisecond):
				}
				assert.Equal(f.signer.signs.Load(), blockAt)
				assert.DeepEqual(f.current(t), f.ad)
				// An independent transaction can finish inside either signing call;
				// the enclosing lock must never be a Vault transaction.
				transaction := make(chan error, 1)
				go func() { transaction <- f.vault.Update(func(storage.WriteTx) error { return nil }) }()
				select {
				case err := <-transaction:
					assert.NoError(err)
				case <-time.After(5 * time.Second):
					t.Fatal("proof signing held a Vault transaction")
				}
				unblock()
				select {
				case w := <-proofDone:
					checkCurrentProofResponse(t, w, f.root, f.child, f.ad, nonce)
				case <-time.After(5 * time.Second):
					t.Fatal("proof did not finish")
				}
				select {
				case w := <-mutationDone:
					want := 200
					if path == bootstrapPath {
						want = 409
					}
					assert.Equal(w.Code, want)
					if path == "/owner/introductions/verify" {
						assert.SLen(try.To1(onboarding.ListKnownIntroductions(f.vault, f.root)), 2)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("owner mutation did not finish")
				}
			})
		}
	}
}
