package pw_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/lainio/ic/internal/ownerapi"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const redeemPath = "/owner/pw/invitations/redeem"

// Both independently bound nodevault.Store instances and restored signers come
// from newExchange. Ad admission uses the real peer current-ad proof exchange.
// This wrapper only observes/drops/delays the existing establishment response.
type redemptionFixture struct {
	*exchangeFixture
	aliceOwner          http.Handler
	aliceAuth           string
	body                []byte
	mu                  sync.Mutex
	bob                 http.Handler
	requests, responses [][]byte
	after               func() error
	drop                bool
	failure             error
}

func newRedemption(t *testing.T, directed bool) *redemptionFixture {
	t.Helper()
	defer assert.PushTester(t)()
	f := &redemptionFixture{}
	f.exchangeFixture = newExchange(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/peer/pw/establish" {
				f.establish(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	var recipient key.Public
	if directed {
		recipient = f.a.public
	}
	row := try.To1(
		pw.IssueInvitation(f.b.store.Vault(), f.root, f.b.public, recipient),
	)
	f.body = try.To1(json.Marshal(map[string]string{
		"target_public_key_hex": hex.EncodeToString(f.b.public),
		"invitation_id_hex": hex.EncodeToString(
			row.ID,
		), "audience": row.Audience,
	}))
	f.bindOwners(t)
	return f
}

func (f *redemptionFixture) bindOwners(t *testing.T) {
	t.Helper()
	defer assert.PushTester(t)()
	owner, file, bind := try.To3(
		ownerapi.NewEstablishmentCredentials(t.Context(),
			f.a.store.Vault(), f.root, f.a.public, f.a.signer, t.TempDir()),
	)
	bind(nil) // Alice needs no peer listener.
	f.aliceOwner = owner
	f.aliceAuth = strings.TrimSpace(strings.TrimPrefix(
		string(try.To1(os.ReadFile(file))), "Authorization:"))
	_, _, bobBind := try.To3(ownerapi.NewEstablishmentCredentials(t.Context(),
		f.b.store.Vault(), f.root, f.b.public, f.b.signer, t.TempDir()))
	_, _, establish := bobBind(f.server.Listener)
	f.bob = peerapi.NewEstablishmentHandler(establish, http.NotFoundHandler())
}

func exchangeRecords(v *storage.Vault) (result [3][]byte, err error) {
	defer err2.Handle(&err, nil)
	try.To(v.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		for i, name := range []string{"local-pw-attempt-v1", "local-pw-accepted-v1",
			"local-pw-held-v1"} {
			result[i], _ = try.To2(tx.Get([]byte(name)))
		}
		return nil
	}))
	return result, nil
}

func (f *redemptionFixture) establish(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.observe(r); err != nil {
		f.failure = err
		http.Error(w, "fixture observation failed", 500)
		return
	}
	recorder := httptest.NewRecorder()
	f.bob.ServeHTTP(recorder, r)
	f.responses = append(f.responses, bytes.Clone(recorder.Body.Bytes()))
	if f.after != nil {
		if err := f.after(); err != nil {
			f.failure = err
		}
	}
	if f.drop {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			f.failure = err
			return
		}
		if err := conn.Close(); err != nil {
			f.failure = err
		}
		return
	}
	for name, values := range recorder.Header() {
		w.Header()[name] = values
	}
	w.WriteHeader(recorder.Code)
	_, _ = w.Write(recorder.Body.Bytes())
}

func (f *redemptionFixture) observe(r *http.Request) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	var document struct {
		Version int    `json:"version"`
		Request []byte `json:"request"`
	}
	if json.Unmarshal(body, &document) != nil || document.Version != 1 ||
		r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
		return errors.New("invalid outbound envelope or credential forwarding")
	}
	records, err := exchangeRecords(f.a.store.Vault())
	if err != nil {
		return err
	}
	if !bytes.Equal(records[0], document.Request) || len(records[0]) == 0 {
		return errors.New("request was not saved before send")
	}
	f.requests = append(f.requests, bytes.Clone(document.Request))
	return nil
}

func (f *redemptionFixture) invoke() *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", redeemPath, bytes.NewReader(f.body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", f.aliceAuth)
	f.aliceOwner.ServeHTTP(w, r)
	return w
}

func TestRequesterOwnerTwoVaultsAndRestart(t *testing.T) {
	for _, directed := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "Any", true: "Directed"}[directed],
			func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRedemption(t, directed)
				f.drop = true
				first := f.invoke()
				assert.Equal(first.Code, 502)
				assert.That(
					strings.Contains(first.Body.String(), "outcome unknown"),
				)
				before := try.To1(exchangeRecords(f.a.store.Vault()))
				bob := try.To1(exchangeRecords(f.b.store.Vault()))
				assert.SNotEmpty(before[0])
				assert.SNil(before[1])
				assert.SNil(before[2])
				assert.SNotEmpty(bob[1])
				assert.SNotEmpty(bob[2])
				var request pw.SignedEstablishment
				try.To(wire.UnmarshalCanonical(&request, before[0]))
				digest := key.HashTagged(
					pw.EstablishPurpose,
					try.To1(wire.Marshal(request.Payload)),
				)
				assert.That(request.Signature.Verify(f.a.public, digest[:]))
				assert.Equal(len(request.Payload.AttemptID), 32)
				assert.DeepEqual(request.Payload.Root, f.root)
				assert.DeepEqual(request.Payload.Requester, f.a.public)
				assert.DeepEqual(request.Payload.Target, f.b.public)
				assert.DeepEqual(request.Payload.Device, f.a.public)
				assert.Equal(request.Payload.Epoch, uint64(0))
				assert.DeepEqual(request.Payload.Ad, f.ad)
				if directed {
					assert.DeepEqual(request.Payload.Recipient, f.a.public)
				} else {
					assert.SNil(request.Payload.Recipient)
				}
				// Join the observed HTTP callback before closing either real Store.
				f.mu.Lock()
				for _, n := range []*exchangeNode{f.a, f.b} {
					try.To(n.store.Close())
					n.store = try.To1(
						nodevault.OpenForNode(t.Context(), n.dir, n.storageKey,
							f.root, n.public),
					)
				}
				f.bindOwners(t)
				f.drop = false
				f.mu.Unlock()
				assert.DeepEqual(
					try.To1(exchangeRecords(f.a.store.Vault())),
					before,
				)
				assert.DeepEqual(
					try.To1(exchangeRecords(f.b.store.Vault())),
					bob,
				)
				w := f.invoke()
				assert.Equal(w.Code, 200)
				assert.Equal(
					w.Body.String(),
					`{"acceptance_saved":true,"local_held":true}`,
				)
				alice := try.To1(exchangeRecords(f.a.store.Vault()))
				assert.DeepEqual(alice[0], before[0])
				assert.DeepEqual(alice[1], bob[1])
				assert.DeepEqual(alice[2], bob[2])
				f.mu.Lock()
				assert.NoError(f.failure)
				assert.Equal(len(f.requests), 2)
				assert.DeepEqual(f.requests[0], f.requests[1])
				assert.DeepEqual(f.responses[0], f.responses[1])
				f.mu.Unlock()
				establishes := 0
				for _, message := range f.a.signer.signed() {
					if bytes.Equal(message, digest[:]) {
						establishes++
					}
				}
				assert.Equal(establishes, 1)
				// Lost owner acknowledgement / duplicate: no new peer I/O or encryption.
				snapshot := f.snapshot(t)
				assert.Equal(f.invoke().Code, 200)
				assert.DeepEqual(f.snapshot(t), snapshot)
				assert.Equal(len(f.requests), 2)
				// History cannot restore a test-only deletion of Alice's half.
				deleteExchangeRecord(
					t,
					f.a.store.Vault(),
					"",
					[]byte("local-pw-held-v1"),
				)
				snapshot = f.snapshot(t)
				assert.Equal(
					f.invoke().Body.String(),
					`{"acceptance_saved":true,"local_held":false}`,
				)
				assert.DeepEqual(f.snapshot(t), snapshot)
				assert.Equal(len(f.requests), 2)
			},
		)
	}
}

func TestRequesterOwnerDelayedAcceptance(t *testing.T) {
	for _, who := range []string{"Alice", "Bob"} {
		t.Run(who, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRedemption(t, false)
			f.after = func() error {
				node, peer := f.a, f.b
				if who == "Bob" {
					node, peer = f.b, f.a
				}
				_, err := policy.DenyLocal(
					node.store.Vault(),
					f.root,
					node.public,
					peer.public,
				)
				return err
			}
			w := f.invoke()
			alice := try.To1(exchangeRecords(f.a.store.Vault()))
			bob := try.To1(exchangeRecords(f.b.store.Vault()))
			assert.SNotEmpty(alice[0])
			assert.SNotEmpty(bob[1])
			assert.SNotEmpty(bob[2])
			if who == "Alice" {
				assert.Equal(w.Code, 409)
				assert.SNil(alice[1])
				assert.SNil(alice[2])
			} else {
				assert.Equal(w.Code, 200)
				assert.DeepEqual(alice[1], bob[1])
				assert.DeepEqual(alice[2], bob[2])
			}
			assert.NoError(f.failure)
			assert.Equal(len(f.requests), 1) // No third establishment ACK.
		})
	}
}

func TestRequesterOwnerConcurrentCalls(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRedemption(t, true)
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 8)
	for range 8 {
		go func() { <-start; results <- f.invoke() }()
	}
	close(start)
	for range 8 {
		assert.Equal((<-results).Code, 200)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	assert.NoError(f.failure)
	assert.That(len(f.requests) > 0 && len(f.requests) <= 8)
	for _, raw := range f.requests {
		assert.DeepEqual(raw, f.requests[0])
	}
	for _, raw := range f.responses {
		assert.DeepEqual(raw, f.responses[0])
	}
	alice := try.To1(exchangeRecords(f.a.store.Vault()))
	var request pw.SignedEstablishment
	try.To(wire.UnmarshalCanonical(&request, alice[0]))
	digest := key.HashTagged(
		pw.EstablishPurpose,
		try.To1(wire.Marshal(request.Payload)),
	)
	count := 0
	for _, message := range f.a.signer.signed() {
		if bytes.Equal(message, digest[:]) {
			count++
		}
	}
	assert.Equal(count, 1)
}
