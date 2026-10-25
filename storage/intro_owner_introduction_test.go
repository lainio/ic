package storage_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/ownerapi"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

type introductionFixture struct {
	db            *storage.Database
	vault         *storage.Vault
	provider      *consumerProvider
	path          string
	handler       http.Handler
	authorization string
}

func newIntroductionFixture(t *testing.T, root, child key.Public) introductionFixture {
	t.Helper()
	defer assert.PushTester(t)()

	p := newConsumerProvider(storage.VaultID{1}, storage.KeyID{7}, make([]byte, 32))
	try.To1(rand.Read(p.secret))
	t.Cleanup(func() { clear(p.secret) })
	path := filepath.Join(t.TempDir(), "vault.db")
	db := try.To1(storage.OpenBolt(path))
	t.Cleanup(func() { try.Out(db.Close()).Logf() })
	try.To(db.CreateVault(t.Context(), p.vault, p.id, p))
	vault := try.To1(db.OpenVault(t.Context(), p.vault, p.id, p))
	t.Cleanup(func() { try.Out(vault.Close()).Logf() })
	rootBinding, childBinding := bytes.Clone(root), bytes.Clone(child)
	handler, file := try.To2(ownerapi.NewReadCredentials(
		t.Context(), vault, rootBinding, childBinding, t.TempDir(),
	))
	clear(rootBinding)
	clear(childBinding)
	header := string(try.To1(os.ReadFile(file)))
	assert.Equal(try.To1(os.Stat(file)).Mode().Perm(), os.FileMode(0600))
	return introductionFixture{db, vault, p, path, handler,
		strings.TrimSpace(strings.TrimPrefix(header, "Authorization: "))}
}

func (f introductionFixture) request() *http.Request {
	r := httptest.NewRequest(http.MethodGet,
		"/owner/introduction?root=other&child=other&action=retry", nil)
	r.Header.Set("Authorization", f.authorization)
	return r
}

// Freeze the provider budget and assert the complete database is unchanged.
func (f introductionFixture) assertReadOnly(t *testing.T) {
	t.Helper()
	defer assert.PushTester(t)()

	before := try.To1(os.ReadFile(f.path))
	f.provider.mu.Lock()
	f.provider.remainingEncryptions = 0
	f.provider.mu.Unlock()
	t.Cleanup(func() {
		defer assert.PushTester(t)()
		assert.DeepEqual(try.To1(os.ReadFile(f.path)), before)
		f.provider.mu.Lock()
		remaining := f.provider.remainingEncryptions
		f.provider.mu.Unlock()
		assert.Equal(remaining, uint32(0))
	})
}

func TestOwnerIntroductionCompleted(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	rootPublic := key.Public(try.To1(root.CBORPublicKey()))
	childPublic := key.Public(try.To1(alice.CBORPublicKey()))
	proposal := intro.New(key.Info{Public: rootPublic}).Introduce(
		root, key.Info{Public: childPublic}, intro.WithEndpoint("saved public endpoint", false),
	)
	f := newIntroductionFixture(t, rootPublic, childPublic)
	signer := &choiceSigningHandle{Handle: alice}
	try.To1(onboarding.SignAfterStoredChoice(
		f.vault, signer, rootPublic, rootPublic, proposal,
	))
	savedProposal, _ := try.To2(readSelectedProposal(f.vault))
	savedAcceptance, _ := try.To2(readStoredAcceptance(f.vault))
	signer.signErr = errors.New("export must not sign")
	f.assertReadOnly(t)

	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, f.request())
	assert.Equal(response.Code, http.StatusOK)
	assert.Equal(response.Header().Get("Content-Type"), "application/json")
	assert.Equal(response.Header().Get("Cache-Control"), "no-store")
	var fields map[string]json.RawMessage
	try.To(json.Unmarshal(response.Body.Bytes(), &fields))
	assert.Equal(len(fields), 3)
	var version int
	var exportedProposal []byte
	var exportedAcceptance key.Signature
	try.To(json.Unmarshal(fields["version"], &version))
	try.To(json.Unmarshal(fields["proposal"], &exportedProposal))
	try.To(json.Unmarshal(fields["acceptance"], &exportedAcceptance))
	assert.Equal(version, 1)
	assert.DeepEqual(exportedProposal, savedProposal)
	assert.DeepEqual(exportedAcceptance, savedAcceptance)
	parsed := try.To1(intro.ParsePath(exportedProposal))
	assert.NoError(parsed.ProveFromRoot(rootPublic))
	assert.NoError(parsed.VerifyAcceptance(exportedAcceptance))
	assert.Equal(signer.signCalls, 1)
	assert.Equal(try.To1(readOwnerStatus(f.handler, f.authorization)), "completed")

	failed := &ownerStatusFailedWriter{ResponseRecorder: httptest.NewRecorder()}
	f.handler.ServeHTTP(failed, f.request())
	assert.Equal(failed.Code, http.StatusOK)
	assert.Equal(failed.headerCalls, 1)
	assert.Equal(failed.writeCalls, 1)
}

func TestOwnerIntroductionRefusals(t *testing.T) {
	defer assert.PushTester(t)()

	root, parent, alice := key.New(), key.New(), key.New()
	rootPublic := key.Public(try.To1(root.CBORPublicKey()))
	parentPublic := key.Public(try.To1(parent.CBORPublicKey()))
	childPublic := key.Public(try.To1(alice.CBORPublicKey()))
	for _, scenario := range []string{
		"absent", "pending", "orphaned", "bad acceptance", "closed",
		"root ID", "parent ID", "child ID", "oversize",
	} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()

			rootInfo := key.Info{Public: rootPublic}
			parentInfo := key.Info{Public: parentPublic}
			childInfo := key.Info{Public: childPublic}
			// Synthetic opaque IDs suffice: no private key need be materialized.
			switch scenario {
			case "root ID":
				rootInfo.ID = []byte("private handle")
			case "parent ID":
				parentInfo.ID = []byte("private handle")
			case "child ID":
				childInfo.ID = []byte("private handle")
			}
			endpoint := "saved endpoint"
			if scenario == "oversize" {
				endpoint = strings.Repeat("x", 128*1024)
			}
			proposal := intro.New(rootInfo).Introduce(root, parentInfo).
				Introduce(parent, childInfo, intro.WithEndpoint(endpoint, false))
			acceptance := try.To1(proposal.SignAcceptanceFor(alice, rootPublic, parentPublic))
			assert.NoError(proposal.VerifyAcceptance(acceptance))
			f := newIntroductionFixture(t, rootPublic, childPublic)
			if scenario != "absent" {
				try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					records := try.To1(tx.EnsureChild([]byte("introduction-choice-demo")))
					if scenario != "orphaned" {
						try.To(records.Put([]byte("selected-proposal"), proposal.Bytes()))
					}
					if scenario == "bad acceptance" {
						acceptance = []byte("invalid")
					}
					if scenario != "pending" {
						try.To(records.Put([]byte("acceptance"), acceptance))
					}
					return nil
				}))
			}
			f.assertReadOnly(t)
			if scenario == "closed" {
				try.To(f.vault.Close())
			}
			response := httptest.NewRecorder()
			f.handler.ServeHTTP(response, f.request())
			want := http.StatusInternalServerError
			if scenario == "absent" || scenario == "pending" {
				want = http.StatusConflict
			}
			assert.Equal(response.Code, want)
			assert.Equal(response.Body.String(), http.StatusText(want)+"\n")
			assert.Equal(response.Header().Get("Content-Type"), "text/plain; charset=utf-8")
			assert.Equal(response.Header().Get("Cache-Control"), "no-store")
		})
	}
}

func TestOwnerIntroductionAuthenticationAndRoutes(t *testing.T) {
	defer assert.PushTester(t)()

	// A nil Vault would panic if inspection preceded authorization or routing.
	dir := t.TempDir()
	handler, file := try.To2(ownerapi.NewReadCredentials(t.Context(), nil, nil, nil, dir))
	header := try.To1(os.ReadFile(file))
	authorization := strings.TrimSpace(strings.TrimPrefix(string(header), "Authorization: "))
	_, _, err := ownerapi.NewReadCredentials(t.Context(), nil, nil, nil, dir)
	assert.ErrorIs(err, os.ErrExist)
	assert.DeepEqual(try.To1(os.ReadFile(file)), header)
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{http.MethodPost, "/owner/introduction", http.StatusMethodNotAllowed},
		{http.MethodHead, "/owner/introduction", http.StatusMethodNotAllowed},
		{http.MethodGet, "/owner/introduction/", http.StatusNotFound},
		{http.MethodGet, "/intro/offer", http.StatusNotFound},
	} {
		for _, credential := range []string{"", authorization} {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			r.Header.Set("Authorization", credential)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			want, allow := http.StatusUnauthorized, ""
			if credential != "" {
				want = tc.status
			}
			if want == http.StatusMethodNotAllowed {
				allow = "GET"
			}
			assert.Equal(w.Code, want)
			assert.Equal(w.Header().Get("Allow"), allow)
		}
	}
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, httptest.NewRequest(http.MethodGet, "/owner/introduction", nil))
	assert.Equal(denied.Code, http.StatusUnauthorized)

	token := make([]byte, 32)
	try.To1(rand.Read(token))
	statusOnly := try.To1(ownerapi.NewAuthenticatedStatusHandler(nil, nil, nil, token))
	statusCredentials, statusFile := try.To2(ownerapi.NewStatusCredentials(t.Context(), nil, nil, nil, t.TempDir()))
	statusHeader := string(try.To1(os.ReadFile(statusFile)))
	for _, tc := range []struct {
		handler       http.Handler
		authorization string
	}{
		{ownerapi.NewStatusHandler(nil, nil, nil), ""},
		{statusOnly, "Bearer " + hex.EncodeToString(token)},
		{statusCredentials, strings.TrimSpace(strings.TrimPrefix(statusHeader, "Authorization: "))},
	} {
		r := httptest.NewRequest(http.MethodGet, "/owner/introduction", nil)
		r.Header.Set("Authorization", tc.authorization)
		w := httptest.NewRecorder()
		tc.handler.ServeHTTP(w, r)
		assert.Equal(w.Code, http.StatusNotFound)
	}
}
