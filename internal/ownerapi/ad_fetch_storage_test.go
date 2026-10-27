package ownerapi

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestAdFetchSequentialFailureReceipts(t *testing.T) {
	for _, scenario := range []string{"first seal", "second seal", "corrupt ad table", "ad table full", "introduction conflict", "introductions full", "corrupt introduction"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newAdFetchFixture(t)
			want, introductionRemains := 500, false
			switch scenario {
			case "first seal":
				f.lease.remaining.Store(0)
			case "second seal":
				f.lease.remaining.Store(1)
				introductionRemains = true
			case "corrupt ad table":
				try.To(f.vault.Update(func(tx storage.WriteTx) error {
					return tx.Put([]byte("received-ad-claims-v1"), []byte("private corrupt ad table"))
				}))
				introductionRemains = true
			case "ad table full":
				for range 32 {
					public := key.Public(try.To1(key.New().CBORPublicKey()))
					current := f.current
					current.Payload.Node, current.Payload.Device = public, public
					assert.That(try.To1(ads.ReceiveClaim(f.vault, f.root, public, try.To1(wire.Marshal(current)))))
				}
				want, introductionRemains = 409, true
			case "introduction conflict":
				different := intro.New(key.Info{Public: f.root}).Introduce(f.parent, key.Info{Public: f.subject}, intro.WithEndpoint("different", false))
				try.To2(onboarding.SaveIntroduction(f.vault, f.root, different.Bytes(), try.To1(different.SignAcceptance(f.peer))))
				want = 409
			case "introductions full":
				for range 32 {
					peer := key.New()
					path := intro.New(key.Info{Public: f.root}).Introduce(f.parent, key.Info{Public: try.To1(peer.CBORPublicKey())})
					try.To2(onboarding.SaveIntroduction(f.vault, f.root, path.Bytes(), try.To1(path.SignAcceptance(peer))))
				}
				want = 409
			case "corrupt introduction":
				try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					return try.To1(tx.EnsureChild([]byte("received-introductions-v1"))).Put(f.subject, []byte("private corrupt introduction"))
				}))
			}
			previousAd := receivedAdTable(t, f.vault)
			if !introductionRemains {
				defer f.unchanged(t)()
			}
			server := adServer(t, adDocument(t, f.choice, try.To1(wire.Marshal(f.current))))
			for range 2 {
				w := f.fetch(server.URL)
				assert.Equal(w.Code, want)
				assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
				assert.Equal(w.Header().Get("Cache-Control"), "no-store")
				assert.DeepEqual(receivedAdTable(t, f.vault), previousAd)
			}
			if introductionRemains {
				assert.DeepEqual(try.To1(onboarding.ListIntroductions(f.vault, f.root)), []key.Public{f.subject})
				// The first distinct commit is durable and must not be deleted
				// to pretend the composite was atomic. Repeating it is read-only.
				_, created := try.To2(onboarding.SaveIntroduction(f.vault, f.root, f.choice.Proposal.Bytes(), f.choice.Acceptance))
				assert.ThatNot(created)
			}
			if scenario == "second seal" {
				f.lease.remaining.Store(1)
				assertAdFetchResult(t, f.fetch(server.URL), f.subject, false, true)
				defer f.unchanged(t)()
				assertAdFetchResult(t, f.fetch(server.URL), f.subject, false, false)
			}
			assert.Equal(f.signer.signs.Load(), int32(0))
		})
	}
}

func receivedAdTable(t *testing.T, vault *storage.Vault) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	var result []byte
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		result, _ = try.To2(tx.Get([]byte("received-ad-claims-v1")))
		return nil
	}))
	return result
}

func TestAdFetchLockOnlyAfterNetwork(t *testing.T) {
	defer assert.PushTester(t)()
	f := newAdFetchFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	document := adDocument(t, f.choice, try.To1(wire.Marshal(f.current)))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
		}
		_, _ = w.Write(document)
	}))
	defer server.Close()
	finished := make(chan int, 1)
	go func() { finished <- f.fetch(server.URL).Code }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("fetch did not reach peer")
	}
	// Existing mutations and independent Vault transactions can finish while
	// the peer is stalled. A Vault transaction is never the service mutex.
	bootstrap := make(chan int, 1)
	go func() { bootstrap <- deviceRequest(f.handler, f.auth, "POST", bootstrapPath, "{}").Code }()
	assert.Equal(waitDeviceResponse(t, bootstrap), 409)
	rollback := errors.New("rollback probe")
	unlocked := make(chan error, 1)
	go func() { unlocked <- f.vault.Update(func(storage.WriteTx) error { return rollback }) }()
	select {
	case err := <-unlocked:
		assert.ErrorIs(err, rollback)
	case <-time.After(time.Second):
		t.Fatal("fetch held a Vault transaction during network I/O")
	}
	h := f.handler.(*authenticatedStatusHandler).next.(*publicationHandler)
	h.mutations.Lock()
	close(release)
	// Once the body completes, this same lock must gate both receipts.
	select {
	case <-finished:
		h.mutations.Unlock()
		t.Fatal("fetch bypassed the service mutation lock")
	case <-time.After(50 * time.Millisecond):
	}
	assert.SEmpty(try.To1(onboarding.ListIntroductions(f.vault, f.root)))
	assert.That(bytes.Equal(receivedAdTable(t, f.vault), nil))
	h.mutations.Unlock()
	assert.Equal(waitDeviceResponse(t, finished), 200)
	f.noAuthority(t)
}
