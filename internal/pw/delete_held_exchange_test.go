package pw_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/ownerapi"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/storage"
)

const deleteHoldingPath = "/owner/pw/holding/delete"

func deleteExchangeHolding(t *testing.T, f *exchangeFixture, n *exchangeNode) {
	t.Helper()
	defer assert.PushTester(t)()
	before := f.snapshot(t)
	records := exchangeHeldState(t, n.store.Vault())
	signs := len(n.signer.signed())
	// Construction and nil binding must neither sign nor mutate, even with a
	// holding already present. This is a local owner action with no listener.
	h, file, bind := try.To3(ownerapi.NewFirstUseCredentials(t.Context(),
		n.store.Vault(), f.root, n.public, n.signer, t.TempDir()))
	bind(nil)
	assert.DeepEqual(f.snapshot(t), before)
	auth := strings.TrimSpace(strings.TrimPrefix(
		string(try.To1(os.ReadFile(file))), "Authorization:"))
	r := httptest.NewRequest("POST", deleteHoldingPath, strings.NewReader("{}"))
	r.Header.Set("Authorization", auth)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(w.Code, http.StatusOK)
	assert.Equal(w.Body.String(), `{"deleted":true}`)
	assert.Equal(w.Header().Get("Cache-Control"), "no-store")
	assert.Equal(len(n.signer.signed()), signs)
	delete(records["root"], "local-pw-held-v1")
	assert.DeepEqual(exchangeHeldState(t, n.store.Vault()), records)
	// All other local files (including usage) and every remote file stay exact.
	after := f.snapshot(t)
	delete(before, filepath.Join(n.dir, "state", "vault.db"))
	delete(after, filepath.Join(n.dir, "state", "vault.db"))
	assert.DeepEqual(after, before)
	before = f.snapshot(t)
	assert.ThatNot(
		try.To1(pw.DeleteHeldLocal(n.store.Vault(), f.root, n.public)),
	)
	assert.DeepEqual(f.snapshot(t), before)
}

func exchangeHeldState(
	t *testing.T,
	v *storage.Vault,
) map[string]map[string][]byte {
	t.Helper()
	defer assert.PushTester(t)()
	result := make(map[string]map[string][]byte)
	try.To(v.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		for _, name := range []string{"root", "known-introductions-v1",
			"received-introductions-v1", "local-device-auth-v1",
			"introduction-choice-demo"} {
			var ns storage.ReadNS = tx
			if name != "root" {
				if !try.To1(tx.HasChild([]byte(name))) {
					continue
				}
				ns = try.To1(tx.Child([]byte(name)))
			}
			result[name] = make(map[string][]byte)
			try.To(ns.Each(func(k, value []byte) error {
				result[name][string(k)] = value
				return nil
			}))
		}
		return nil
	}))
	return result
}

func TestDeleteHeldBobOnlyAlreadyTransmittedAcceptance(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRedemption(t, true)
	f.drop = true
	assert.Equal(f.invoke().Code, 502)
	f.mu.Lock()
	assert.NoError(f.failure)
	var sent struct {
		Version    int
		Acceptance []byte
	}
	try.To(json.Unmarshal(f.responses[0], &sent))
	f.mu.Unlock()
	alice := try.To1(exchangeRecords(f.a.store.Vault()))
	assert.SNotEmpty(alice[0])
	assert.SNil(alice[1])
	assert.SNil(alice[2])
	deleteExchangeHolding(t, f.exchangeFixture, f.b)
	before := f.snapshot(t)
	response, err := pw.BobReply(f.b.store.Vault(), f.root, f.b.public,
		f.b.signer, f.server.URL+"/peer/introduction", alice[0])
	assert.Equal(err, pw.ErrEstablishment)
	assert.SNil(response)
	assert.Equal(pw.BobAccept(
		f.b.store.Vault(),
		f.root,
		f.b.public,
		f.b.signer,
		f.server.URL+"/peer/introduction",
		alice[0],
	), pw.ErrEstablishment)
	assert.DeepEqual(f.snapshot(t), before)
	// Already-transmitted signed bytes can still be accepted under Alice's own
	// guards. They reveal no current Bob permission and cannot restore his half.
	assert.That(try.To1(pw.ReceiveAcceptance(f.a.store.Vault(), f.root,
		f.a.public, f.a.signer, sent.Acceptance)))
	assert.SNil(try.To1(exchangeRecords(f.b.store.Vault()))[2])
	try.To1(pw.SaveFirstUse(f.a.store.Vault(), f.root, f.a.public, f.a.signer))
	var pending observedUseRecord
	try.To(wire.UnmarshalCanonical(&pending,
		try.To1(readUseRecord(f.a.store.Vault(), aliceUseKey))))
	response, err = pw.BobFirstUse(f.b.store.Vault(), f.root, f.b.public,
		f.b.signer, pending.Request)
	assert.Equal(err, pw.ErrFirstUse)
	assert.SNil(response)
	assert.Equal(pending.State, "Await")
	assert.SNil(try.To1(readUseRecord(f.b.store.Vault(), bobUseKey)))
}

func TestDeleteHeldTwoNodeHistoryRestartAndNoResurrection(t *testing.T) {
	for _, role := range []string{"Alice", "Bob"} {
		for _, state := range []string{"Idle", "Await", "Ready", "Expired"} {
			t.Run(role+"/"+state, func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newFirstUseExchange(t)
				if state != "Idle" {
					f.drop = state == "Await"
					status, _ := try.To2(
						f.post(t.Context(), ownerUsePath, []byte("{}")),
					)
					if f.drop {
						assert.Equal(status, 502)
					} else {
						assert.Equal(status, 200)
					}
					f.mu.Lock()
					assert.NoError(f.failure)
					f.mu.Unlock()
					if state == "Expired" {
						assert.That(
							try.To1(pw.ExpireFirstUse(f.a.store.Vault(), f.root,
								f.a.public, true)),
						)
					}
				}
				node := f.a
				if role == "Bob" {
					node = f.b
				}
				deleteExchangeHolding(t, f.exchangeFixture, node)
				alice, bob := exchangeHeldState(
					t,
					f.a.store.Vault(),
				), exchangeHeldState(
					t,
					f.b.store.Vault(),
				)
				f.reopen(
					t,
				) // Real independently bound nodevault.Store close/open.
				assert.DeepEqual(exchangeHeldState(t, f.a.store.Vault()), alice)
				assert.DeepEqual(exchangeHeldState(t, f.b.store.Vault()), bob)
				before := f.snapshot(t)
				assert.ThatNot(
					try.To1(
						pw.DeleteHeldLocal(
							node.store.Vault(),
							f.root,
							node.public,
						),
					),
				)
				if role == "Alice" {
					var accepted struct {
						_                 struct{} `cbor:",toarray"`
						Version           uint8
						Request, Response []byte
					}
					try.To(
						wire.UnmarshalCanonical(
							&accepted,
							alice["root"]["local-pw-accepted-v1"],
						),
					)
					assert.ThatNot(
						try.To1(pw.ReceiveAcceptance(f.a.store.Vault(), f.root,
							f.a.public, f.a.signer, accepted.Response)),
					)
					_, err := pw.SaveFirstUse(
						f.a.store.Vault(),
						f.root,
						f.a.public,
						f.a.signer,
					)
					assert.Equal(err, pw.ErrFirstUse)
					if state != "Idle" {
						var receipt observedUseReceipt
						try.To(
							wire.UnmarshalCanonical(
								&receipt,
								bob["root"][bobUseKey],
							),
						)
						ready, err := pw.ReceiveFirstUse(
							f.a.store.Vault(),
							f.root,
							f.a.public,
							f.a.signer,
							receipt.Response,
						)
						assert.Equal(err, pw.ErrFirstUse)
						assert.ThatNot(ready)
					}
				} else {
					_, err := pw.BobReply(f.b.store.Vault(), f.root, f.b.public,
						f.b.signer, f.server.URL+"/peer/introduction", alice["root"]["local-pw-attempt-v1"])
					assert.Equal(err, pw.ErrEstablishment)
				}
				assert.DeepEqual(f.snapshot(t), before)
				if role == "Alice" && (state == "Await" || state == "Ready") {
					assert.That(
						try.To1(
							pw.ExpireFirstUse(
								f.a.store.Vault(),
								f.root,
								f.a.public,
								true,
							),
						),
					)
					var expired observedUseRecord
					try.To(wire.UnmarshalCanonical(&expired,
						try.To1(readUseRecord(f.a.store.Vault(), aliceUseKey))))
					assert.Equal(expired.State, "Expired")
					var prior observedUseRecord
					try.To(
						wire.UnmarshalCanonical(
							&prior,
							alice["root"][aliceUseKey],
						),
					)
					assert.DeepEqual(expired.Request, prior.Request)
					assert.DeepEqual(expired.Response, prior.Response)
				}
			})
		}
	}
}
