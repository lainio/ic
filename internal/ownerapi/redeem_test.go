package ownerapi

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/storage"
)

func redemptionBody(t *testing.T, target, id []byte) string {
	t.Helper()
	defer assert.PushTester(t)()
	return string(try.To1(json.Marshal(map[string]string{
		"target_public_key_hex": hex.EncodeToString(target),
		"invitation_id_hex":     hex.EncodeToString(id), "audience": "Any",
	})))
}

func TestRedemptionStrictInputNoSigning(t *testing.T) {
	defer assert.PushTester(t)()
	f := newAdFetchFixture(t)
	h, auth := redemptionCredential(t, f.vault, f.root, f.local, f.signer)
	defer f.unchanged(t)()
	valid := redemptionBody(t, f.subject, make([]byte, 32))
	for _, body := range []string{"", "null", "[]", "{}", valid + "{}", valid[:len(valid)-1],
		strings.Replace(valid, `"Any"`, `null`, 1),
		strings.Replace(valid, `"Any"`, `"any"`, 1),
		strings.Replace(valid, `"Any"`, `[]`, 1),
		strings.Replace(valid, `"audience"`, `"Audience"`, 1),
		strings.Replace(valid, strings.Repeat("0", 64), strings.Repeat("AB", 32), 1),
		strings.Replace(valid, strings.Repeat("0", 64), strings.Repeat("a", 63), 1),
		strings.Replace(valid, strings.Repeat("0", 64), "gg", 1),
		strings.Replace(valid, `"Any"`, "\"\xff\"", 1),
		valid[:len(valid)-1] + `,"audience":"Any"}`,
	} {
		w := deviceRequest(h, auth, "POST", invitationRedeemPath, body)
		assert.Equal(w.Code, 400, body)
		assert.Equal(w.Body.String(), "Bad Request\n")
	}
	for _, field := range []string{"url", "peer_url", "root", "signer", "time",
		"request", "recipient_public_key_hex", "ad", "device", "epoch"} {
		body := valid[:len(valid)-1] + `,"` + field + `":"x"}`
		assert.Equal(
			deviceRequest(h, auth, "POST", invitationRedeemPath, body).Code,
			400,
		)
	}
	reader := strings.NewReader(strings.Repeat(" ", 1024))
	r := httptest.NewRequest("POST", invitationRedeemPath, reader)
	r.ContentLength = 1
	r.Header.Set("Authorization", auth)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(w.Code, 413)
	assert.Equal(reader.Len(), 1024-513)
	assert.Equal(f.signer.signs.Load(), int32(0))
}

func TestRedemptionSaveFailureAndUnlockedIO(t *testing.T) {
	for _, version := range []int{1, 2} {
		for allowance := range int64(4) {
			name := fmt.Sprint(allowance) // Retain diagnostic v1 test selectors.
			if version == 2 {
				name = fmt.Sprint("v2/", allowance)
			}
			t.Run(name, func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newAcceptanceFixture(t)
				server := httptest.NewUnstartedServer(nil)
				defer server.Close()
				_, _, bind := try.To3(
					NewEstablishmentCredentials(t.Context(), f.vault,
						f.root, f.child, f.signer, t.TempDir()),
				)
				prove, _, establish := bind(server.Listener)
				endpoint := "http://" + server.Listener.Addr().
					String() +
					"/peer/introduction"
				peer := peerapi.NewEstablishmentHandler(
					establish,
					peerapi.NewProofHandler(
						f.vault,
						f.root,
						f.child,
						endpoint,
						prove,
					),
				)
				h, auth := redemptionCredential(t, f.requesterVault.vault, f.root,
					f.requester, f.requesterKey)
				if version == 2 {
					var file string
					h, file, bind = try.To3(NewEstablishmentCredentials(t.Context(),
						f.requesterVault.vault, f.root, f.requester,
						f.requesterKey, t.TempDir()))
					bind(publicationListener(t))
					auth = strings.TrimSpace(strings.TrimPrefix(
						string(try.To1(os.ReadFile(file))), "Authorization: "))
				}
				requester := h.(*authenticatedStatusHandler).next.(*redemptionHandler)
				var calls atomic.Int32
				var unlocked atomic.Bool
				networkTx := make(chan error, 1)
				server.Config.Handler = http.HandlerFunc(
					func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path == establishmentPath {
							calls.Add(1)
							if requester.mutations.TryLock() {
								unlocked.Store(true)
								requester.mutations.Unlock()
							}
							networkTx <- f.requesterVault.vault.Update(
								func(storage.WriteTx) error { return nil },
							)
						}
						peer.ServeHTTP(w, r)
					},
				)
				server.Start()
				ad := try.To1(wire.Marshal(try.To1(ads.PublishLocal(f.vault, f.root,
					f.child, f.signer, endpoint, time.Now()))))
				v := f.requesterVault.vault
				try.To1(ads.ReceiveClaim(v, f.root, f.child, ad))
				try.To1(
					ads.VerifyReceivedRemote(
						t.Context(),
						v,
						f.root,
						f.requester,
						f.child,
					),
				)
				row := try.To1(pw.IssueInvitation(f.vault, f.root, f.child, nil))
				body := redemptionBody(t, f.child, row.ID)
				if version == 2 {
					body = body[:len(body)-1] + `,"version":2}`
				}
				f.requesterVault.lease.remaining.Store(allowance)
				// Even lost owner response writes must happen after all locks/transactions.
				w := &establishmentWriter{
					ResponseRecorder: httptest.NewRecorder(),
					fail:             true,
					onHeader: func() {
						assert.That(requester.mutations.TryLock())
						requester.mutations.Unlock()
						try.To(v.View(func(tx storage.ReadTx) error {
							_, _, err := tx.Get([]byte("local-pw-attempt-v1"))
							return err
						}))
					},
				}
				r := httptest.NewRequest(
					"POST",
					invitationRedeemPath,
					strings.NewReader(body),
				)
				r.Header.Set("Authorization", auth)
				r.Header.Set("Content-Type", "application/json")
				h.ServeHTTP(w, r)
				bob, found := try.To2(pw.ReadInvitation(f.vault, f.root, f.child))
				assert.That(found)
				want := pw.InvitationConsumed
				if allowance == 0 {
					want = pw.InvitationActive
				}
				assert.Equal(bob.State, want)
				var attempt, history, held []byte
				try.To(v.View(func(tx storage.ReadTx) (err error) {
					defer err2.Handle(&err, nil)
					attempt, _ = try.To2(tx.Get([]byte("local-pw-attempt-v1")))
					history, _ = try.To2(tx.Get([]byte("local-pw-accepted-v1")))
					held, _ = try.To2(tx.Get([]byte("local-pw-held-v1")))
					return nil
				}))
				if allowance == 0 {
					assert.Equal(calls.Load(), int32(0))
					assert.SNil(attempt)
				} else {
					assert.Equal(calls.Load(), int32(1))
					assert.SNotEmpty(attempt)
					assert.That(unlocked.Load())
					assert.NoError(<-networkTx)
				}
				if allowance < 3 {
					assert.Equal(w.Code, 409)
					assert.SNil(history)
					assert.SNil(held)
				} else {
					assert.Equal(w.Code, 200)
					assert.SNotEmpty(history)
					assert.SNotEmpty(held)
					defer f.requesterVault.unchanged(t)()
					assert.Equal(deviceRequest(h, auth, "POST", invitationRedeemPath, body).Code, 200)
					assert.Equal(calls.Load(), int32(1))
				}
			})
		}
	}
}
