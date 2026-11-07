package ownerapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const firstUsePeerPath = "/peer/pw/first-use"

type firstUseHTTPV2 struct {
	acceptanceFixture
	alice, bob *firstUseHandler
	owner      http.Handler
	auth       string
	peer       http.Handler
	server     *httptest.Server
}

func newFirstUseHTTPV2(t *testing.T,
	intercept func(http.ResponseWriter, *http.Request, http.Handler),
) *firstUseHTTPV2 {
	t.Helper()
	defer assert.PushTester(t)()
	f := &firstUseHTTPV2{acceptanceFixture: newAcceptanceFixture(t)}
	f.server = httptest.NewUnstartedServer(nil)
	t.Cleanup(f.server.Close)
	bobOwner, _, bobBind := try.To3(NewFirstUseCredentials(t.Context(),
		f.vault, f.root, f.child, f.signer, t.TempDir()))
	f.bob = bobOwner.(*authenticatedStatusHandler).next.(*firstUseHandler)
	prove, _, establish, use, _ := bobBind(f.server.Listener)
	endpoint := "http://" + f.server.Listener.Addr().String() +
		"/peer/introduction"
	f.peer = peerapi.NewFirstUseHandler(use,
		peerapi.NewEstablishmentHandler(establish, peerapi.NewProofHandler(
			f.vault, f.root, f.child, endpoint, prove)))
	var file string
	f.owner, file, bobBind = try.To3(NewFirstUseCredentials(t.Context(),
		f.requesterVault.vault, f.root, f.requester, f.requesterKey, t.TempDir()))
	bobBind(publicationListener(t))
	f.alice = f.owner.(*authenticatedStatusHandler).next.(*firstUseHandler)
	f.auth = strings.TrimSpace(strings.TrimPrefix(
		string(try.To1(os.ReadFile(file))), "Authorization:"))
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request,
	) {
		if intercept != nil && r.URL.Path == firstUsePeerPath {
			intercept(w, r, f.peer)
			return
		}
		f.peer.ServeHTTP(w, r)
	})
	f.server.Start()
	ad := try.To1(wire.Marshal(try.To1(ads.PublishLocal(f.vault, f.root,
		f.child, f.signer, endpoint, time.Now()))))
	v := f.requesterVault.vault
	try.To1(ads.ReceiveClaim(v, f.root, f.child, ad))
	try.To1(ads.VerifyReceivedRemote(t.Context(), v, f.root,
		f.requester, f.child))
	row := try.To1(pw.IssueInvitation(f.vault, f.root, f.child, nil))
	body := redemptionBody(t, f.child, row.ID)
	body = body[:len(body)-1] + `,"version":2}`
	assert.Equal(deviceRequest(f.owner, f.auth, "POST",
		invitationRedeemPath, body).Code, 200)
	return f
}

func firstUseRowsV2(t *testing.T, v *storage.Vault) map[string][]byte {
	t.Helper()
	defer assert.PushTester(t)()
	rows := make(map[string][]byte)
	try.To(v.View(func(tx storage.ReadTx) error {
		return tx.Each(func(k, value []byte) error {
			rows[string(k)] = bytes.Clone(value)
			return nil
		})
	}))
	return rows
}

func firstUseSavedV2(t *testing.T, f *firstUseHTTPV2) (string, []byte) {
	t.Helper()
	defer assert.PushTester(t)()
	var row struct {
		_                 struct{} `cbor:",toarray"`
		Version           uint8
		State             string
		Request, Response []byte
	}
	try.To(wire.UnmarshalCanonical(&row,
		firstUseRowsV2(t, f.requesterVault.vault)["local-pw-first-use-v1"]))
	assert.Equal(row.Version, 2)
	return row.State, row.Request
}

func TestFirstUseV2OwnerSelectorAndRuntime(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseHTTPV2(t, nil)
	defer f.requesterVault.unchanged(t)()
	defer f.deviceFixture.unchanged(t)()
	for _, body := range []string{"", " ", "null", "[]", "{ }",
		`{"version":1}`, `{"version":0}`, `{"version":3}`, `{"version":-2}`,
		`{"version":2.0}`, `{"version":2e0}`, `{"version":"2"}`,
		`{"version":null}`, `{"version":true}`, `{"version":[]}`,
		`{"version":2,"version":2}`, `{"ver\u0073ion":2}`,
		`{"Version":2}`, `{"version":2} {}`, `{"version": 2}`, "\xff",
	} {
		w := deviceRequest(f.owner, f.auth, "POST", firstUsePath, body)
		assert.Equal(w.Code, 400, body)
		assert.Equal(w.Body.String(), "Bad Request\n")
	}
	for _, field := range []string{"url", "peer_url", "contact", "root",
		"clock", "request", "runtime", "running", "bound_origin"} {
		body := `{"version":2,"` + field + `":"x"}`
		assert.Equal(deviceRequest(f.owner, f.auth, "POST", firstUsePath,
			body).Code, 400)
	}
	// Even genuine v2 history cannot supply Alice's runtime after restart.
	for _, endpoint := range []string{"", f.bob.endpoint} {
		f.alice.mutations.Lock()
		f.alice.endpoint = endpoint
		f.alice.mutations.Unlock()
		w := deviceRequest(f.owner, f.auth, "POST", firstUsePath,
			`{"version":2}`)
		assert.Equal(w.Code, 409)
		assert.Equal(w.Body.String(), "Conflict\n")
	}
}

func TestFirstUseV2HTTPCommitFailures(t *testing.T) {
	for _, allowance := range []struct{ alice, bob int64 }{
		{0, 1}, {1, 1}, {2, 0}, {2, 1},
	} {
		t.Run(fmt.Sprint(allowance), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newFirstUseHTTPV2(t, nil)
			beforeAlice := firstUseRowsV2(t, f.requesterVault.vault)
			beforeBob := firstUseRowsV2(t, f.vault)
			f.requesterVault.lease.remaining.Store(allowance.alice)
			f.lease.remaining.Store(allowance.bob)
			w := deviceRequest(f.owner, f.auth, "POST", firstUsePath,
				`{"version":2}`)
			want := 409
			if allowance.alice > 0 && allowance.bob == 0 {
				want = 502
			}
			if allowance.alice == 2 && allowance.bob == 1 {
				want = 200
			}
			assert.Equal(w.Code, want)
			afterAlice := firstUseRowsV2(t, f.requesterVault.vault)
			afterBob := firstUseRowsV2(t, f.vault)
			if allowance.alice > 0 {
				state, _ := firstUseSavedV2(t, f)
				expected := "Await"
				if want == 200 {
					expected = "Ready"
				}
				assert.Equal(state, expected)
				delete(afterAlice, "local-pw-first-use-v1")
			}
			if allowance.alice > 0 && allowance.bob > 0 {
				assert.SNotEmpty(afterBob["local-pw-use-seen-v1"])
				delete(afterBob, "local-pw-use-seen-v1")
			}
			assert.DeepEqual(afterAlice, beforeAlice)
			assert.DeepEqual(afterBob, beforeBob)
		})
	}
}

func TestFirstUseV2LostResponseAndIndependentReady(t *testing.T) {
	for _, mode := range []string{"drop", "deny", "delete", "alice deny",
		"alice runtime", "wrong version", "wrong signature"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			entered := make(chan *httptest.ResponseRecorder, 1)
			release := make(chan struct{})
			defer close(release)
			f := newFirstUseHTTPV2(t, func(w http.ResponseWriter,
				r *http.Request, peer http.Handler,
			) {
				saved := httptest.NewRecorder()
				peer.ServeHTTP(saved, r)
				entered <- saved
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
				if mode == "drop" {
					panic(http.ErrAbortHandler)
				}
				maps.Copy(w.Header(), saved.Header())
				data := saved.Body.Bytes()
				if mode == "wrong version" {
					data = bytes.Replace(data, []byte(`"version":2`),
						[]byte(`"version":1`), 1)
				}
				if mode == "wrong signature" {
					var envelope struct {
						Version  int    `json:"version"`
						Response []byte `json:"response"`
					}
					if json.Unmarshal(data, &envelope) == nil {
						envelope.Response[len(envelope.Response)-1] ^= 1
						data, _ = json.Marshal(envelope)
					}
				}
				w.WriteHeader(saved.Code)
				_, _ = w.Write(data)
			})
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				done <- deviceRequest(f.owner, f.auth, "POST", firstUsePath,
					`{"version":2}`)
			}()
			response := waitAcceptance(t, entered)
			assert.Equal(response.Code, 200)
			// Both service locks and Vaults are free while response I/O waits.
			for _, h := range []*firstUseHandler{f.alice, f.bob} {
				assert.That(h.mutations.TryLock())
				try.To(h.vault.Update(func(storage.WriteTx) error { return nil }))
				h.mutations.Unlock()
			}
			state, raw := firstUseSavedV2(t, f)
			assert.Equal(state, "Await")
			bobRows := firstUseRowsV2(t, f.vault)
			assert.SNotEmpty(bobRows["local-pw-use-seen-v1"])
			switch mode {
			case "deny":
				try.To1(policy.DenyLocal(f.vault, f.root, f.child, f.requester))
			case "delete":
				try.To1(pw.DeleteHeldLocal(f.vault, f.root, f.child))
			case "alice deny":
				try.To1(policy.DenyLocal(f.requesterVault.vault, f.root,
					f.requester, f.child))
			case "alice runtime":
				f.alice.mutations.Lock()
				f.alice.endpoint = f.bob.endpoint
				f.alice.mutations.Unlock()
			}
			release <- struct{}{}
			w := waitAcceptance(t, done)
			want := 409
			switch mode {
			case "drop", "wrong version":
				want = 502
			case "deny", "delete":
				want = 200
			}
			assert.Equal(w.Code, want)
			state, _ = firstUseSavedV2(t, f)
			if want == 200 {
				assert.Equal(w.Body.String(), `{"local_ready":true}`)
				assert.Equal(state, "Ready")
			} else {
				assert.Equal(state, "Await")
				assert.That(strings.Contains(w.Body.String(), "peer outcome unknown"))
			}
			// Lost-response repetition cannot retrieve or re-sign Bob's receipt.
			defer f.deviceFixture.unchanged(t)()
			defer f.requesterVault.unchanged(t)()
			signs := f.signer.signs.Load()
			assert.Equal(deviceRequest(f.peer, "", "POST", firstUsePeerPath,
				versionedEstablishmentBody(t, 2, raw)).Code, 409)
			assert.Equal(f.signer.signs.Load(), signs)
			assert.Equal(deviceRequest(f.owner, f.auth, "POST", firstUsePath,
				`{"version":2}`).Code, 409)
			assert.DeepEqual(firstUseRowsV2(t, f.vault)["local-pw-use-seen-v1"],
				bobRows["local-pw-use-seen-v1"])
		})
	}
}

func TestFirstUseV2PeerAuthenticatedVersionAndContact(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseHTTPV2(t, nil)
	_, err := f.alice.saveFirstUseV2(t.Context())
	assert.NoError(err)
	_, raw := firstUseSavedV2(t, f)
	var signed pw.SignedFirstUseV2
	try.To(wire.UnmarshalCanonical(&signed, raw))
	changed := signed.Payload
	changed.Established.Binding.RequesterContact = f.server.URL
	digest := key.HashTagged(pw.FirstUsePurposeV2, try.To1(wire.Marshal(changed)))
	wrongContact := try.To1(wire.Marshal(pw.SignedFirstUseV2{Payload: changed,
		Signature: try.To1(f.requesterKey.Sign(digest[:]))}))
	tampered := bytes.Clone(raw)
	tampered[len(tampered)-1] ^= 1
	defer f.deviceFixture.unchanged(t)()
	defer f.requesterVault.unchanged(t)()
	signs := f.signer.signs.Load()
	for _, body := range []string{
		versionedEstablishmentBody(t, 1, raw),
		versionedEstablishmentBody(t, 2, wrongContact),
		versionedEstablishmentBody(t, 2, tampered),
		versionedEstablishmentBody(t, 2, append(bytes.Clone(raw), 0)),
	} {
		w := deviceRequest(f.peer, "", "POST", firstUsePeerPath, body)
		assert.Equal(w.Code, 409)
		assert.Equal(w.Body.String(), "Conflict\n")
	}
	f.bob.mutations.Lock()
	f.bob.endpoint = f.alice.endpoint
	f.bob.mutations.Unlock()
	assert.Equal(deviceRequest(f.peer, "", "POST", firstUsePeerPath,
		versionedEstablishmentBody(t, 2, raw)).Code, 409)
	assert.Equal(f.signer.signs.Load(), signs)
}

func TestFirstUseV2RefusesLegacySignedRequest(t *testing.T) {
	defer assert.PushTester(t)()
	f, _, body := firstUseOwnerTarget(t)
	defer f.deviceFixture.unchanged(t)()
	defer f.requesterVault.unchanged(t)()
	signs := f.signer.signs.Load()
	for _, version := range []string{"2", "3"} {
		w := deviceRequest(f.peer, "", "POST", firstUsePeerPath,
			strings.Replace(body, `"version":1`, `"version":`+version, 1))
		want := 409
		if version == "3" {
			want = 400
		}
		assert.Equal(w.Code, want)
		assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
	}
	assert.Equal(f.signer.signs.Load(), signs)
}

func TestFirstUseV2ConcurrentReceiptOnlyOnce(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseHTTPV2(t, nil)
	_, err := f.alice.saveFirstUseV2(t.Context())
	assert.NoError(err)
	_, raw := firstUseSavedV2(t, f)
	body := versionedEstablishmentBody(t, 2, raw)
	before, signs := f.lease.remaining.Load(), f.signer.signs.Load()
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 8)
	for range 8 {
		go func() {
			<-start
			results <- deviceRequest(f.peer, "", "POST", firstUsePeerPath, body)
		}()
	}
	close(start)
	successes := 0
	for range 8 {
		w := waitAcceptance(t, results)
		if w.Code == 200 {
			successes++
		} else {
			assert.Equal(w.Code, 409)
		}
	}
	assert.Equal(successes, 1)
	assert.Equal(before-f.lease.remaining.Load(), int64(1))
	assert.Equal(f.signer.signs.Load()-signs, int32(2))
}

func TestFirstUseV2ReadyDuplicateCannotRestoreHolding(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseHTTPV2(t, nil)
	assert.Equal(deviceRequest(f.owner, f.auth, "POST", firstUsePath,
		`{"version":2}`).Code, 200)
	var receipt struct {
		_                 struct{} `cbor:",toarray"`
		Version           uint8
		Request, Response []byte
	}
	try.To(wire.UnmarshalCanonical(&receipt,
		firstUseRowsV2(t, f.vault)["local-pw-use-seen-v1"]))
	f.requesterVault.lease.remaining.Store(0)
	unchanged := f.requesterVault.unchanged(t)
	assert.That(f.alice.receiveFirstUseV2(receipt.Response))
	unchanged()
	assert.Equal(deviceRequest(f.owner, f.auth, "POST", deleteHeldPath,
		"{}").Code, 200)
	defer f.requesterVault.unchanged(t)()
	defer f.deviceFixture.unchanged(t)()
	assert.ThatNot(f.alice.receiveFirstUseV2(receipt.Response))
	assert.SNil(firstUseRowsV2(t, f.requesterVault.vault)["local-pw-held-v1"])
}

func TestFirstUseV2CurrentOwnerGuards(t *testing.T) {
	for _, alice := range []bool{false, true} {
		for _, change := range []string{"deny", "delete", "unusable signer"} {
			t.Run(fmt.Sprint(alice, change), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newFirstUseHTTPV2(t, nil)
				var raw []byte
				if !alice {
					_, err := f.alice.saveFirstUseV2(t.Context())
					assert.NoError(err)
					_, raw = firstUseSavedV2(t, f)
				}
				h, peer := f.bob, f.requester
				if alice {
					h, peer = f.alice, f.child
				}
				h.mutations.Lock()
				switch change {
				case "deny":
					try.To1(policy.DenyLocal(h.vault, h.root, h.child, peer))
				case "delete":
					try.To1(pw.DeleteHeldLocal(h.vault, h.root, h.child))
				case "unusable signer":
					h.signer = nil
				}
				h.mutations.Unlock()
				defer f.requesterVault.unchanged(t)()
				defer f.deviceFixture.unchanged(t)()
				var w *httptest.ResponseRecorder
				if alice {
					w = deviceRequest(f.owner, f.auth, "POST", firstUsePath,
						`{"version":2}`)
				} else {
					w = deviceRequest(f.peer, "", "POST", firstUsePeerPath,
						versionedEstablishmentBody(t, 2, raw))
				}
				assert.Equal(w.Code, 409)
				assert.Equal(w.Body.String(), "Conflict\n")
				assert.Equal(try.To1(pw.RequesterContactV2(f.requesterVault.vault,
					f.root, f.requester)), f.server.URL)
				assert.Equal(try.To1(pw.BobContactV2(f.vault, f.root, f.child)),
					strings.TrimSuffix(f.alice.endpoint, "/peer/introduction"))
			})
		}
	}
}
