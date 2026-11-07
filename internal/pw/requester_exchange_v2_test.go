package pw_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
)

// Both origins are actual independent listeners. The existing fixture observes
// only Bob's exchange; Alice's peer handler must never receive a callback.
type redemptionV2Fixture struct {
	*redemptionFixture
	alicePeer        *httptest.Server
	alicePeerHandler http.Handler
	callbacks        int
}

func newRedemptionV2(t *testing.T, directed bool) *redemptionV2Fixture {
	t.Helper()
	defer assert.PushTester(t)()
	f := &redemptionV2Fixture{redemptionFixture: newRedemption(t, directed)}
	f.version = 2
	f.body = append(
		bytes.Clone(f.body[:len(f.body)-1]),
		[]byte(`,"version":2}`)...)
	f.alicePeer = httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.callbacks++
			f.alicePeerHandler.ServeHTTP(w, r)
		}))
	f.bindV2(t)
	f.alicePeer.Start()
	t.Cleanup(f.alicePeer.Close)
	return f
}

// Call before serving or with the observation mutex after admitted HTTP joins.
// Reopening stores retains the listeners and their exact chosen ports.
func (f *redemptionV2Fixture) bindV2(t *testing.T) {
	t.Helper()
	defer assert.PushTester(t)()
	for _, n := range []*exchangeNode{f.a, f.b} {
		h, file, bind := try.To3(ownerapi.NewFirstUseCredentials(t.Context(),
			n.store.Vault(), f.root, n.public, n.signer, t.TempDir()))
		listener := f.server.Listener
		if n == f.a {
			listener = f.alicePeer.Listener
		}
		prove, _, establish, use, message := bind(listener)
		peer := peerapi.NewMessageHandler(message,
			peerapi.NewFirstUseHandler(use,
				peerapi.NewEstablishmentHandler(
					establish,
					peerapi.NewProofHandler(
						n.store.Vault(),
						f.root,
						n.public,
						"http://"+listener.Addr().
							String()+
							"/peer/introduction",
						prove,
					),
				)))
		auth := strings.TrimSpace(strings.TrimPrefix(
			string(try.To1(os.ReadFile(file))), "Authorization:"))
		if n == f.a {
			f.aliceOwner, f.aliceAuth, f.alicePeerHandler = h, auth, peer
		} else {
			f.owner, f.ownerAuth, f.bob = h, auth, peer
		}
	}
}

func checkV2Evidence(t *testing.T, f *redemptionV2Fixture) {
	t.Helper()
	defer assert.PushTester(t)()
	a := try.To1(exchangeRecords(f.a.store.Vault()))
	b := try.To1(exchangeRecords(f.b.store.Vault()))
	assert.SNil(b[0])
	assert.DeepEqual(a[1:], b[1:])
	var request pw.SignedEstablishmentV2
	try.To(wire.UnmarshalCanonical(&request, a[0]))
	p := request.Payload
	assert.Equal(p.Version, 2)
	assert.DeepEqual(p.Root, f.root)
	assert.DeepEqual(p.Requester, f.a.public)
	assert.DeepEqual(p.Target, f.b.public)
	assert.DeepEqual(p.Ad, f.ad)
	assert.Equal(p.RequesterContact, f.alicePeer.URL)
	assert.Equal(p.TargetContact, f.server.URL)
	digest := key.HashTagged(pw.EstablishPurposeV2,
		try.To1(wire.Marshal(p)))
	assert.That(request.Signature.Verify(f.a.public, digest[:]))
	assert.Equal(signedDigestCount(f.a.signer, digest[:]), 1)
	var history observedUseReceipt
	try.To(wire.UnmarshalCanonical(&history, a[1]))
	assert.Equal(history.Version, 2)
	assert.DeepEqual(history.Request, a[0])
	var response pw.SignedAcceptedV2
	try.To(wire.UnmarshalCanonical(&response, history.Response))
	assert.Equal(response.Payload.Version, 2)
	assert.DeepEqual(response.Payload.Binding, p)
	digest = key.HashTagged("pw-invitation-request-digest/v2", a[0])
	assert.DeepEqual(response.Payload.RequestDigest, digest[:])
	var held struct {
		_             struct{} `cbor:",toarray"`
		Version       uint8
		RequestDigest []byte
	}
	try.To(wire.UnmarshalCanonical(&held, a[2]))
	assert.Equal(held.Version, 2)
	assert.DeepEqual(held.RequestDigest, digest[:])
	digest = key.HashTagged(pw.AcceptedPurposeV2,
		try.To1(wire.Marshal(response.Payload)))
	assert.That(response.Signature.Verify(f.b.public, digest[:]))
	assert.Equal(signedDigestCount(f.b.signer, digest[:]), 1)
	assert.Equal(try.To1(pw.BobContactV2(f.b.store.Vault(), f.root,
		f.b.public)), f.alicePeer.URL)
	assert.Equal(try.To1(pw.RequesterContactV2(f.a.store.Vault(), f.root,
		f.a.public)), f.server.URL)
	row, found := try.To2(
		pw.ReadInvitation(f.b.store.Vault(), f.root, f.b.public),
	)
	assert.That(found)
	assert.Equal(row.State, pw.InvitationConsumed)
	assert.DeepEqual(row.ID, p.InvitationID)
}

func signedDigestCount(signer *observedSigner, digest []byte) int {
	count := 0
	for _, data := range signer.signed() {
		if bytes.Equal(data, digest) {
			count++
		}
	}
	return count
}

func TestOwnerV2LiveIndependentCommits(t *testing.T) {
	for _, directed := range []bool{false, true} {
		t.Run(map[bool]string{false: "Any", true: "Directed"}[directed],
			func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRedemptionV2(t, directed)
				f.after = func() (err error) {
					defer err2.Handle(&err, nil)
					a := try.To1(exchangeRecords(f.a.store.Vault()))
					b := try.To1(exchangeRecords(f.b.store.Vault()))
					ac := try.To1(pw.RequesterContactV2(f.a.store.Vault(),
						f.root, f.a.public))
					bc := try.To1(
						pw.BobContactV2(
							f.b.store.Vault(),
							f.root,
							f.b.public,
						),
					)
					if len(a[0]) == 0 || a[1] != nil || a[2] != nil || ac != "" ||
						len(b[1]) == 0 ||
						len(b[2]) == 0 ||
						bc != f.alicePeer.URL {
						return errors.New("commits were not independent")
					}
					return nil
				}
				w := f.invoke()
				assert.Equal(w.Code, 200)
				assert.Equal(
					w.Body.String(),
					`{"acceptance_saved":true,"local_held":true}`,
				)
				f.mu.Lock()
				defer f.mu.Unlock()
				assert.NoError(f.failure)
				assert.Equal(f.callbacks, 0)
				assert.Equal(len(f.requests), 1)
				checkV2Evidence(t, f)
			})
	}
}

func TestOwnerV2LostResponseExactRetryAndReopen(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRedemptionV2(t, true)
	f.drop = true
	assert.Equal(f.invoke().Code, 502)
	f.mu.Lock()
	assert.NoError(f.failure)
	a := try.To1(exchangeRecords(f.a.store.Vault()))
	b := try.To1(exchangeRecords(f.b.store.Vault()))
	assert.SNotEmpty(a[0])
	assert.SNil(a[1])
	assert.SNil(a[2])
	assert.SNotEmpty(b[1])
	assert.SNotEmpty(b[2])
	assert.Equal(len(f.requests), 1) // No automatic retry after response loss.
	for _, n := range []*exchangeNode{f.a, f.b} {
		try.To(n.store.Close())
		n.store = try.To1(
			nodevault.OpenForNode(t.Context(), n.dir, n.storageKey,
				f.root, n.public),
		)
	}
	f.bindV2(t)
	f.drop = false
	f.mu.Unlock()
	assert.Equal(f.invoke().Code, 200)
	f.mu.Lock()
	assert.NoError(f.failure)
	assert.Equal(len(f.requests), 2)
	assert.DeepEqual(f.requests[0], f.requests[1])
	assert.DeepEqual(f.responses[0], f.responses[1])
	assert.DeepEqual(try.To1(exchangeRecords(f.b.store.Vault())), b)
	checkV2Evidence(t, f)
	f.mu.Unlock()
	before := f.snapshot(t)
	assert.Equal(f.invoke().Code, 200)
	assert.DeepEqual(f.snapshot(t), before)
	assert.That(
		try.To1(pw.DeleteHeldLocal(f.a.store.Vault(), f.root, f.a.public)),
	)
	before = f.snapshot(t)
	assert.Equal(
		f.invoke().Body.String(),
		`{"acceptance_saved":true,"local_held":false}`,
	)
	assert.DeepEqual(f.snapshot(t), before)
	assert.Equal(len(f.requests), 2)
}

func TestOwnerV2DenyDeleteAndDelayedAcceptance(t *testing.T) {
	for _, deny := range []bool{false, true} {
		t.Run(map[bool]string{false: "Delete", true: "Deny"}[deny],
			func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRedemptionV2(t, false)
				f.drop = true
				assert.Equal(f.invoke().Code, 502)
				f.mu.Lock()
				assert.NoError(f.failure)
				var envelope struct {
					Version    int
					Acceptance []byte
				}
				try.To(json.Unmarshal(f.responses[0], &envelope))
				assert.Equal(envelope.Version, 2)
				f.drop = false
				f.mu.Unlock()
				if deny {
					try.To1(policy.DenyLocal(f.b.store.Vault(), f.root,
						f.b.public, f.a.public))
				} else {
					assert.That(try.To1(pw.DeleteHeldLocal(f.b.store.Vault(),
						f.root, f.b.public)))
				}
				before := f.snapshot(t)
				assert.Equal(
					f.invoke().Code,
					502,
				) // Bob now refuses a new reply.
				assert.DeepEqual(f.snapshot(t), before)
				assert.Equal(
					try.To1(pw.BobContactV2(f.b.store.Vault(), f.root,
						f.b.public)),
					f.alicePeer.URL,
				)
				// Previously transmitted bytes still satisfy Alice's own guards.
				assert.That(
					try.To1(pw.ReceiveAcceptanceV2(
						f.a.store.Vault(),
						f.root,
						f.a.public,
						f.a.signer,
						envelope.Acceptance,
					)),
				)
				assert.Equal(
					f.invoke().Code,
					200,
				) // Local history, no third request.
				assert.Equal(len(f.requests), 2)
				assert.That(try.To1(pw.DeleteHeldLocal(f.a.store.Vault(),
					f.root, f.a.public)))
				before = f.snapshot(t)
				assert.ThatNot(
					try.To1(pw.ReceiveAcceptanceV2(
						f.a.store.Vault(),
						f.root,
						f.a.public,
						f.a.signer,
						envelope.Acceptance,
					)),
				)
				assert.DeepEqual(f.snapshot(t), before)
			})
	}
}

func TestOwnerV2FirstUseAndMessagesFailClosed(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRedemptionV2(t, false)
	assert.Equal(f.invoke().Code, 200)
	before := f.snapshot(t)
	for _, n := range []*exchangeNode{f.a, f.b} {
		_, err := pw.SaveFirstUse(n.store.Vault(), f.root, n.public, n.signer)
		assert.Error(err)
		_, err = pw.PrepareMessageSend(n.store.Vault(), f.root, n.public,
			n.signer, "not ready")
		assert.Error(err)
	}
	for _, path := range []string{ownerUsePath, ownerMessageSendPath} {
		body := []byte(`{}`)
		if path == ownerMessageSendPath {
			body = []byte(`{"text":"not ready","peer_message_url":"` +
				f.server.URL + `/peer/pw/message"}`)
		}
		r := httptest.NewRequest("POST", path, bytes.NewReader(body))
		r.Header.Set("Authorization", f.aliceAuth)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.aliceOwner.ServeHTTP(w, r)
		assert.Equal(w.Code, 409)
	}
	assert.DeepEqual(f.snapshot(t), before)
	assert.Equal(len(f.requests), 1)
}

func TestOwnerV2RequiresListenerWhileV1DoesNot(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRedemptionV2(t, false)
	h, file, bind := try.To3(ownerapi.NewEstablishmentCredentials(t.Context(),
		f.a.store.Vault(), f.root, f.a.public, f.a.signer, t.TempDir()))
	bind(nil)
	f.aliceOwner = h
	f.aliceAuth = strings.TrimSpace(strings.TrimPrefix(
		string(try.To1(os.ReadFile(file))), "Authorization:"))
	before := f.snapshot(t)
	signs := len(f.a.signer.signed())
	assert.Equal(f.invoke().Code, 409)
	assert.DeepEqual(f.snapshot(t), before)
	assert.Equal(len(f.a.signer.signed()), signs)
	assert.Equal(len(f.requests), 0)
	f.body = bytes.Replace(f.body, []byte(`,"version":2`), nil, 1)
	f.version = 1
	assert.Equal(f.invoke().Code, 200)
	assert.Equal(len(f.requests), 1)
}

func TestOwnerV2AndV1SavedStateNeverCrossVersions(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, accepted := range []bool{false, true} {
			t.Run(fmt.Sprint(version, "/", accepted), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRedemptionV2(t, false)
				v2 := bytes.Clone(f.body)
				v1 := bytes.Replace(v2, []byte(`,"version":2`), nil, 1)
				f.version, f.drop = version, !accepted
				if version == 1 {
					f.body = v1
				}
				want := 502
				if accepted {
					want = 200
				}
				assert.Equal(f.invoke().Code, want)
				before := f.snapshot(t)
				signs := len(f.a.signer.signed())
				f.body = v1
				if version == 1 {
					f.body = v2
				}
				assert.Equal(f.invoke().Code, 409)
				assert.DeepEqual(f.snapshot(t), before)
				assert.Equal(len(f.a.signer.signed()), signs)
				assert.Equal(len(f.requests), 1)
			})
		}
	}
}

func TestOwnerV2ChangedBoundPortCannotRebind(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		t.Run(fmt.Sprint(accepted), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRedemptionV2(t, false)
			f.drop = !accepted
			want := 502
			if accepted {
				want = 200
			}
			assert.Equal(f.invoke().Code, want)
			before := f.snapshot(t)
			f.mu.Lock()
			oldPeer := f.alicePeer
			f.alicePeer = httptest.NewUnstartedServer(http.NotFoundHandler())
			defer f.alicePeer.Close()
			assert.NotEqual(f.alicePeer.Listener.Addr().String(),
				oldPeer.Listener.Addr().String())
			f.bindV2(t)
			f.alicePeer.Start()
			f.drop = false
			f.mu.Unlock()
			assert.Equal(f.invoke().Code, 409)
			assert.DeepEqual(f.snapshot(t), before)
			assert.Equal(len(f.requests), 1)
		})
	}
}

func TestOwnerV2ResponseVersionAndCanonicalEvidence(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRedemptionV2(t, false)
	f.drop = true
	assert.Equal(f.invoke().Code, 502)
	f.mu.Lock()
	var original struct {
		Version    int    `json:"version"`
		Acceptance []byte `json:"acceptance"`
	}
	try.To(json.Unmarshal(f.responses[0], &original))
	f.drop = false
	peer := f.bob
	f.mu.Unlock()
	var signed pw.SignedAcceptedV2
	try.To(wire.UnmarshalCanonical(&signed, original.Acceptance))
	signed.Payload.Version = 1
	digest := key.HashTagged(pw.AcceptedPurposeV2,
		try.To1(wire.Marshal(signed.Payload)))
	signed.Signature = try.To1(f.b.signer.Sign(digest[:]))
	wrongVersion := try.To1(wire.Marshal(signed))
	tampered := bytes.Clone(original.Acceptance)
	tampered[len(tampered)-1] ^= 1
	for _, tc := range []struct {
		name    string
		version int
		raw     []byte
		status  int
	}{
		{"envelope version", 1, original.Acceptance, 502},
		{"signed version", 2, wrongVersion, 409},
		{"tampered", 2, tampered, 409},
		{"malformed", 2, []byte{0xff}, 409},
		{"noncanonical", 2, append([]byte{0x98, 2}, original.Acceptance[1:]...), 409},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			document := try.To1(json.Marshal(struct {
				Version    int    `json:"version"`
				Acceptance []byte `json:"acceptance"`
			}{tc.version, tc.raw}))
			f.mu.Lock()
			f.bob = http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					recorder := httptest.NewRecorder()
					peer.ServeHTTP(recorder, r)
					maps.Copy(w.Header(), recorder.Header())
					w.WriteHeader(recorder.Code)
					_, _ = w.Write(document)
				},
			)
			f.mu.Unlock()
			before := f.snapshot(t)
			assert.Equal(f.invoke().Code, tc.status)
			assert.DeepEqual(f.snapshot(t), before)
		})
	}
	f.mu.Lock()
	f.bob = peer
	f.mu.Unlock()
	assert.Equal(f.invoke().Code, 200)
	checkV2Evidence(t, f)
}
