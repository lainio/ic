package ownerapi

import (
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

func TestFirstUseHTTPOnlyAfterCommits(t *testing.T) {
	for _, allowance := range []struct{ alice, bob int64 }{{0, 1}, {1, 1}, {2, 0}, {2, 1}} {
		t.Run(fmt.Sprint(allowance), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newAcceptanceFixture(t)
			server := httptest.NewUnstartedServer(nil)
			defer server.Close()
			bobOwner, _, bobBind := try.To3(
				NewFirstUseCredentials(
					t.Context(),
					f.vault,
					f.root,
					f.child,
					f.signer,
					t.TempDir(),
				),
			)
			bob := bobOwner.(*authenticatedStatusHandler).next.(*firstUseHandler)
			prove, _, establish, use := bobBind(server.Listener)
			endpoint := "http://" + server.Listener.Addr().
				String() +
				"/peer/introduction"
			peer := peerapi.NewFirstUseHandler(
				use,
				peerapi.NewEstablishmentHandler(
					establish,
					peerapi.NewProofHandler(
						f.vault,
						f.root,
						f.child,
						endpoint,
						prove,
					),
				),
			)
			aliceOwner, file, bind := try.To3(
				NewFirstUseCredentials(
					t.Context(),
					f.requesterVault.vault,
					f.root,
					f.requester,
					f.requesterKey,
					t.TempDir(),
				),
			)
			bind(nil)
			alice := aliceOwner.(*authenticatedStatusHandler).next.(*firstUseHandler)
			auth := strings.TrimSpace(
				strings.TrimPrefix(
					string(try.To1(os.ReadFile(file))),
					"Authorization:",
				),
			)
			var calls atomic.Int32
			var unlocked atomic.Bool
			server.Config.Handler = http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/peer/pw/first-use" {
						calls.Add(1)
						if alice.mutations.TryLock() {
							unlocked.Store(true)
							alice.mutations.Unlock()
						}
					}
					peer.ServeHTTP(w, r)
				},
			)
			server.Start()
			ad := try.To1(
				wire.Marshal(
					try.To1(
						ads.PublishLocal(
							f.vault,
							f.root,
							f.child,
							f.signer,
							endpoint,
							time.Now(),
						),
					),
				),
			)
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
			assert.Equal(
				deviceRequest(
					aliceOwner,
					auth,
					"POST",
					invitationRedeemPath,
					redemptionBody(t, f.child, row.ID),
				).Code,
				200,
			)
			f.requesterVault.lease.remaining.Store(allowance.alice)
			f.lease.remaining.Store(allowance.bob)
			// Even a lost owner reply must follow Ready commit with all locks free.
			w := &establishmentWriter{
				ResponseRecorder: httptest.NewRecorder(),
				fail:             true,
				onHeader: func() {
					for _, h := range []*firstUseHandler{alice, bob} {
						assert.That(h.mutations.TryLock())
						h.mutations.Unlock()
					}
					if allowance.alice == 2 && allowance.bob == 1 {
						try.To(v.View(func(tx storage.ReadTx) (err error) {
							defer err2.Handle(&err, nil)
							raw, found := try.To2(
								tx.Get([]byte("local-pw-first-use-v1")),
							)
							assert.That(found)
							var record struct {
								_                 struct{} `cbor:",toarray"`
								Version           uint8
								State             string
								Request, Response []byte
							}
							try.To(wire.UnmarshalCanonical(&record, raw))
							assert.Equal(record.State, "Ready")
							return nil
						}))
					}
				},
			}
			r := httptest.NewRequest(
				"POST",
				firstUsePath,
				strings.NewReader("{}"),
			)
			r.Header.Set("Authorization", auth)
			r.Header.Set("Content-Type", "application/json")
			aliceOwner.ServeHTTP(w, r)
			want := 409
			if allowance.alice > 0 && allowance.bob == 0 {
				want = 502
			}
			if allowance.alice == 2 && allowance.bob == 1 {
				want = 200
			}
			assert.Equal(w.Code, want)
			if allowance.alice == 0 {
				assert.Equal(calls.Load(), int32(0))
			} else {
				assert.Equal(calls.Load(), int32(1))
				assert.That(unlocked.Load())
			}
			try.To(f.vault.View(func(tx storage.ReadTx) (err error) {
				defer err2.Handle(&err, nil)
				_, found := try.To2(tx.Get([]byte("local-pw-use-seen-v1")))
				assert.Equal(found, allowance.alice > 0 && allowance.bob == 1)
				return nil
			}))
		})
	}
}
