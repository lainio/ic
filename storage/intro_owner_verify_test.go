package storage_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func verifyRequest(f introductionFixture) *http.Request {
	r := checkRequest(f.authorization, []byte("{}"))
	r.URL.Path = "/owner/introductions/verify"
	return r
}

func verifyResponse(f introductionFixture) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, verifyRequest(f))
	return w
}

func assertVerified(t *testing.T, w *httptest.ResponseRecorder, count int, subjects ...key.Public) {
	t.Helper()
	defer assert.PushTester(t)()

	assert.Equal(w.Code, http.StatusOK)
	assert.Equal(w.Header().Get("Cache-Control"), "no-store")
	assert.Equal(w.Header().Get("Content-Type"), "application/json")
	assert.That(w.Body.Len() <= 16*1024)
	slices.SortFunc(subjects, func(a, b key.Public) int { return bytes.Compare(a, b) })
	keys := make([]any, 0, len(subjects))
	for _, subject := range subjects {
		keys = append(keys, hex.EncodeToString(subject))
	}
	var result map[string]any
	try.To(json.Unmarshal(w.Body.Bytes(), &result))
	assert.DeepEqual(result, map[string]any{"newly_known": float64(count), "known_subjects": keys})
}

func TestOwnerVerifyExplicitPromotionReopenAndNoWriteRetry(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob, carol := key.New(), key.New(), key.New(), key.New()
	r, a := key.InfoFromHandle(root).Public, key.InfoFromHandle(alice).Public
	b, c := key.InfoFromHandle(bob).Public, key.InfoFromHandle(carol).Public
	f := newIntroductionFixture(t, r, a)
	evidenceCredentials(t, &f, r, a)
	own := intro.New(key.Info{Public: r}).Introduce(root, key.Info{Public: a})
	try.To1(onboarding.SignAfterStoredChoice(f.vault, alice, r, r, own))
	// A completed local choice is never synthesized as Received/Known.
	assertVerified(t, verifyResponse(f), 0)
	assert.SEmpty(try.To1(onboarding.ListIntroductions(f.vault, r)))
	for _, child := range []key.Handle{bob, carol} {
		path := own.Introduce(alice, key.Info{Public: key.InfoFromHandle(child).Public})
		document := checkDocument(path, try.To1(path.SignAcceptance(child)))
		checked := httptest.NewRecorder()
		f.handler.ServeHTTP(checked, checkRequest(f.authorization, document))
		assertChecked(t, checked, path.LeafPubKey(), false)
		assertSaved(t, receivedResponse(f, http.MethodPost, document), path.LeafPubKey(), false, true)
	}
	assertListed(t, f, a, b, c)
	assert.SEmpty(try.To1(onboarding.ListKnownIntroductions(f.vault, r)))
	received := try.To1(introductionRecords(f.vault, "received-introductions-v1"))
	choice := try.To1(introductionRecords(f.vault, "introduction-choice-demo"))
	// Unrelated state canaries are test data, not application namespaces/schema.
	try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		for _, name := range []string{"Trust", "PW", "DeviceAuth", "CurrentAd"} {
			try.To(tx.Put([]byte(name), []byte("unchanged")))
		}
		return nil
	}))
	wrong := f
	evidenceCredentials(t, &wrong, key.InfoFromHandle(key.New()).Public, a)
	t.Run("wrong configured Root", func(t *testing.T) {
		defer assert.PushTester(t)()
		wrong.assertReadOnly(t)
		assertCheckError(t, verifyResponse(wrong), http.StatusConflict)
		assert.SEmpty(try.To1(onboarding.ListKnownIntroductions(f.vault, r)))
	})
	// Restore only the test provider allowance after the read-only subtest.
	f.provider.mu.Lock()
	f.provider.remainingEncryptions = 2
	f.provider.mu.Unlock()
	beforeExport := httptest.NewRecorder()
	f.handler.ServeHTTP(beforeExport, f.request())
	assertVerified(t, verifyResponse(f), 2, b, c)
	f.provider.mu.Lock()
	remaining := f.provider.remainingEncryptions
	f.provider.mu.Unlock()
	assert.Equal(remaining, uint32(0)) // Two subjects, not three graph edges.
	assert.DeepEqual(try.To1(introductionRecords(f.vault, "received-introductions-v1")), received)
	assert.DeepEqual(try.To1(introductionRecords(f.vault, "introduction-choice-demo")), choice)
	try.To(f.vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		for _, name := range []string{"Trust", "PW", "DeviceAuth", "CurrentAd"} {
			value, found := try.To2(tx.Get([]byte(name)))
			assert.That(found)
			assert.Equal(string(value), "unchanged")
		}
		return nil
	}))
	assert.Equal(try.To1(readOwnerStatus(f.handler, f.authorization)), "completed")
	afterExport := httptest.NewRecorder()
	f.handler.ServeHTTP(afterExport, f.request())
	peer := httptest.NewRecorder()
	peerapi.NewHandler(f.vault, r, a).ServeHTTP(peer, httptest.NewRequest(http.MethodGet, "/peer/introduction", nil))
	assert.Equal(afterExport.Code, http.StatusOK)
	assert.Equal(peer.Code, http.StatusOK)
	assert.Equal(afterExport.Body.String(), beforeExport.Body.String())
	assert.Equal(peer.Body.String(), beforeExport.Body.String())
	try.To(f.vault.Close())
	try.To(f.db.Close())
	reopened := try.To1(storage.OpenBolt(f.path))
	defer func() { try.Out(reopened.Close()).Logf() }()
	p := f.provider
	f.vault = try.To1(reopened.OpenVault(t.Context(), p.vault, p.id, p))
	defer func() { try.Out(f.vault.Close()).Logf() }()
	evidenceCredentials(t, &f, r, a)
	f.assertReadOnly(t) // Entire persistent file and exhausted seal budget.
	assertVerified(t, verifyResponse(f), 0, b, c)
	assertVerified(t, verifyResponse(f), 0, b, c)
}

func TestOwnerVerifyInvalidRecordHasNoPartialPromotion(t *testing.T) {
	defer assert.PushTester(t)()

	f := newFetchPair(t)
	assertSaved(t, receivedResponse(f.receiver, http.MethodPost,
		checkDocument(f.proposal, f.acceptance)), f.alice, false, true)
	try.To(f.receiver.vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		ns := try.To1(tx.ChildForUpdate([]byte("received-introductions-v1")))
		return ns.Put(f.bob, []byte("corrupt received record"))
	}))
	f.receiver.assertReadOnly(t)
	assertCheckError(t, verifyResponse(f.receiver), http.StatusConflict)
	assert.SEmpty(try.To1(onboarding.ListKnownIntroductions(f.receiver.vault, f.root)))
	// The core storage/intro_known_test.go matrix covers conflicts and rollback.
}

func TestOwnerVerifyLostAcknowledgementExplicitRetry(t *testing.T) {
	defer assert.PushTester(t)()

	f := newFetchPair(t)
	assertSaved(t, receivedResponse(f.receiver, http.MethodPost,
		checkDocument(f.proposal, f.acceptance)), f.alice, false, true)
	failed := &ownerStatusFailedWriter{ResponseRecorder: httptest.NewRecorder()}
	f.receiver.handler.ServeHTTP(failed, verifyRequest(f.receiver))
	assert.Equal(failed.Code, http.StatusOK)
	assert.Equal(failed.headerCalls, 1)
	assert.Equal(failed.writeCalls, 1)
	f.receiver.assertReadOnly(t)
	assertVerified(t, verifyResponse(f.receiver), 0, f.alice)
}
