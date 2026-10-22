package storage_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
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

// ExampleVault_ownerStatus observes one dedicated Vault through an unmounted
// owner handler. Only explicit workflow calls select and complete the choice.
func ExampleVault_ownerStatus() {
	defer err2.Catch(err2.Stdout)

	root, alice := key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	expectedChild := key.Public(try.To1(alice.CBORPublicKey()))
	offered := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	dir := try.To1(os.MkdirTemp("", "intro-owner-status-example-"))
	defer func() { try.Out(os.RemoveAll(dir)).Logf() }()
	p := newConsumerProvider(
		storage.VaultID{1}, storage.KeyID{7}, make([]byte, 32),
	)
	defer clear(p.secret) // After handle cleanup, including on failure.
	try.To1(rand.Read(p.secret))

	ctx := context.Background()
	db := try.To1(storage.OpenBolt(filepath.Join(dir, "vault.db")))
	defer func() { try.Out(db.Close()).Logf() }()
	try.To(db.CreateVault(ctx, p.vault, p.id, p))
	vault := try.To1(db.OpenVault(ctx, p.vault, p.id, p))
	defer func() { try.Out(vault.Close()).Logf() }()
	handler := ownerapi.NewStatusHandler(vault, expectedRoot, expectedChild)

	before := try.To1(readOwnerStatus(handler))
	assert.Equal(before, "unselected")

	// Inject a signing error after selection, leaving a pending choice.
	cause := errors.New("injected signing error")
	signer := &choiceSigningHandle{Handle: alice, signErr: cause}
	failed, err := onboarding.SignAfterStoredChoice(
		vault, signer, expectedRoot, expectedRoot, offered,
	)
	assert.ErrorIs(err, cause)
	assert.SNil(failed)
	pending := try.To1(readOwnerStatus(handler))
	assert.Equal(pending, "pending")

	signer.signErr = nil
	acceptance := try.To1(onboarding.SignAfterStoredChoice(
		vault, signer, expectedRoot, expectedRoot, offered,
	))
	try.To(offered.VerifyAcceptance(acceptance))
	completed := try.To1(readOwnerStatus(handler))
	assert.Equal(completed, "completed")

	try.To(vault.Close())
	try.To(db.Close())
	clear(p.secret)
	try.To(os.RemoveAll(dir))

	try.To1(fmt.Println("before selection:", before))
	try.To1(fmt.Println("after signing error:", pending))
	try.To1(fmt.Println("after explicit retry:", completed))
	// Output:
	// before selection: unselected
	// after signing error: pending
	// after explicit retry: completed
}

func TestOwnerStatusLabelsReadOnlyAndKeyOwnership(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	expectedChild := key.Public(try.To1(alice.CBORPublicKey()))
	offered := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	p := newConsumerProvider(
		storage.VaultID{1}, storage.KeyID{7}, make([]byte, 32),
	)
	defer clear(p.secret)
	try.To1(rand.Read(p.secret))
	path := filepath.Join(t.TempDir(), "vault.db")
	ctx := t.Context()
	db := try.To1(storage.OpenBolt(path))
	defer func() { try.Out(db.Close()).Logf() }()
	try.To(db.CreateVault(ctx, p.vault, p.id, p))
	vault := try.To1(db.OpenVault(ctx, p.vault, p.id, p))
	defer func() { try.Out(vault.Close()).Logf() }()

	rootBinding := bytes.Clone(expectedRoot)
	childBinding := bytes.Clone(expectedChild)
	handler := ownerapi.NewStatusHandler(vault, rootBinding, childBinding)
	rootBinding[0] ^= 1
	childBinding[0] ^= 1
	signer := &choiceSigningHandle{Handle: alice}
	before := try.To1(os.ReadFile(path))
	p.mu.Lock()
	remaining := p.remainingEncryptions
	p.mu.Unlock()

	assert.Equal(try.To1(readOwnerStatus(handler)), "unselected")
	assert.Equal(signer.signCalls, 0)
	assert.DeepEqual(try.To1(os.ReadFile(path)), before)
	p.mu.Lock()
	after := p.remainingEncryptions
	p.mu.Unlock()
	assert.Equal(after, remaining)

	cause := errors.New("injected signing error")
	signer.signErr = cause
	failed, err := onboarding.SignAfterStoredChoice(
		vault, signer, expectedRoot, expectedRoot, offered,
	)
	assert.ErrorIs(err, cause)
	assert.SNil(failed)
	assert.Equal(signer.signCalls, 1)
	before = try.To1(os.ReadFile(path))
	p.mu.Lock()
	remaining = p.remainingEncryptions
	p.mu.Unlock()

	assert.Equal(try.To1(readOwnerStatus(handler)), "pending")
	assert.Equal(signer.signCalls, 1)
	assert.DeepEqual(try.To1(os.ReadFile(path)), before)
	p.mu.Lock()
	after = p.remainingEncryptions
	p.mu.Unlock()
	assert.Equal(after, remaining)

	signer.signErr = nil
	acceptance := try.To1(onboarding.SignAfterStoredChoice(
		vault, signer, expectedRoot, expectedRoot, offered,
	))
	try.To(offered.VerifyAcceptance(acceptance))
	assert.Equal(signer.signCalls, 2)
	// Exhaust this fixture only after setup: inspection needs no encryption.
	p.mu.Lock()
	p.remainingEncryptions = 0
	p.mu.Unlock()
	signer.signErr = errors.New("inspection must not sign")
	before = try.To1(os.ReadFile(path))

	assert.Equal(try.To1(readOwnerStatus(handler)), "completed")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(
		http.MethodGet,
		"/owner/status?wallet=other&root=other&child=other&action=retry",
		strings.NewReader(
			`{"root":"other","child":"other","action":"retry"}`,
		),
	))
	assert.Equal(response.Code, http.StatusOK)
	assert.Equal(response.Body.String(), "{\"choice\":\"completed\"}\n")
	assert.Equal(signer.signCalls, 2)
	assert.DeepEqual(try.To1(os.ReadFile(path)), before)
	p.mu.Lock()
	after = p.remainingEncryptions
	p.mu.Unlock()
	assert.Equal(after, uint32(0))
	try.To(vault.Close())
	try.To(db.Close())
}

func TestOwnerStatusInspectionFailures(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	expectedChild := key.Public(try.To1(alice.CBORPublicKey()))
	offered := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	acceptance := try.To1(offered.SignAcceptanceFor(
		alice, expectedRoot, expectedRoot,
	))

	for _, name := range []string{"closed Vault", "orphaned acceptance"} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()

			p := newConsumerProvider(
				storage.VaultID{1}, storage.KeyID{7}, make([]byte, 32),
			)
			defer clear(p.secret)
			try.To1(rand.Read(p.secret))
			path := filepath.Join(t.TempDir(), "vault.db")
			ctx := t.Context()
			db := try.To1(storage.OpenBolt(path))
			defer func() { try.Out(db.Close()).Logf() }()
			try.To(db.CreateVault(ctx, p.vault, p.id, p))
			vault := try.To1(db.OpenVault(ctx, p.vault, p.id, p))
			defer func() { try.Out(vault.Close()).Logf() }()
			handler := ownerapi.NewStatusHandler(
				vault,
				expectedRoot,
				expectedChild,
			)

			if name == "closed Vault" {
				try.To(vault.Close())
			} else {
				// Authorized writes create inconsistent application records;
				// storage authentication is not bypassed or attacked here.
				try.To(vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)

					name := []byte("introduction-choice-demo")
					records := try.To1(tx.EnsureChild(name))
					try.To(records.Put([]byte("acceptance"), acceptance))
					return nil
				}))
			}
			before := try.To1(os.ReadFile(path))
			p.mu.Lock()
			remaining := p.remainingEncryptions
			p.mu.Unlock()

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(
				http.MethodGet, "/owner/status", nil,
			))
			assert.Equal(response.Code, http.StatusInternalServerError)
			assert.Equal(response.Body.String(), "Internal Server Error\n")
			assert.Equal(response.Header().Get("Content-Type"),
				"text/plain; charset=utf-8")
			assert.Equal(response.Header().Get("Cache-Control"), "no-store")
			assert.DeepEqual(try.To1(os.ReadFile(path)), before)
			p.mu.Lock()
			after := p.remainingEncryptions
			p.mu.Unlock()
			assert.Equal(after, remaining)
			try.To(vault.Close())
			try.To(db.Close())
		})
	}
}

func TestOwnerStatusRoutes(t *testing.T) {
	defer assert.PushTester(t)()

	expectedRoot := key.Public(try.To1(key.New().CBORPublicKey()))
	expectedChild := key.Public(try.To1(key.New().CBORPublicKey()))
	p := newConsumerProvider(
		storage.VaultID{1}, storage.KeyID{7}, make([]byte, 32),
	)
	defer clear(p.secret)
	try.To1(rand.Read(p.secret))
	ctx := t.Context()
	db := try.To1(storage.OpenBolt(filepath.Join(t.TempDir(), "vault.db")))
	defer func() { try.Out(db.Close()).Logf() }()
	try.To(db.CreateVault(ctx, p.vault, p.id, p))
	vault := try.To1(db.OpenVault(ctx, p.vault, p.id, p))
	defer func() { try.Out(vault.Close()).Logf() }()
	try.To(vault.Close())
	handler := ownerapi.NewStatusHandler(vault, expectedRoot, expectedChild)

	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, "/intro/offer", http.StatusNotFound},
		{http.MethodPost, "/intro/acceptance", http.StatusNotFound},
		{http.MethodGet, "/owner/status/", http.StatusNotFound},
		{http.MethodGet, "/owner", http.StatusNotFound},
		{http.MethodPost, "/owner/status", http.StatusMethodNotAllowed},
		{http.MethodPut, "/owner/status", http.StatusMethodNotAllowed},
		{http.MethodPatch, "/owner/status", http.StatusMethodNotAllowed},
		{http.MethodDelete, "/owner/status", http.StatusMethodNotAllowed},
		{http.MethodHead, "/owner/status", http.StatusMethodNotAllowed},
		{http.MethodOptions, "/owner/status", http.StatusMethodNotAllowed},
		{http.MethodConnect, "/owner/status", http.StatusMethodNotAllowed},
		{http.MethodTrace, "/owner/status", http.StatusMethodNotAllowed},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			defer assert.PushTester(t)()

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(
				tc.method, tc.path, nil,
			))
			assert.Equal(response.Code, tc.status)
			assert.Equal(
				response.Body.String(),
				http.StatusText(tc.status)+"\n",
			)
			assert.Equal(response.Header().Get("Cache-Control"), "no-store")
			if tc.status == http.StatusMethodNotAllowed {
				assert.Equal(response.Header().Get("Allow"), http.MethodGet)
			} else {
				assert.Equal(response.Header().Get("Allow"), "")
			}
		})
	}
	try.To(db.Close())
}

func TestOwnerStatusWriteFailure(t *testing.T) {
	defer assert.PushTester(t)()

	expectedRoot := key.Public(try.To1(key.New().CBORPublicKey()))
	expectedChild := key.Public(try.To1(key.New().CBORPublicKey()))
	p := newConsumerProvider(
		storage.VaultID{1}, storage.KeyID{7}, make([]byte, 32),
	)
	defer clear(p.secret)
	try.To1(rand.Read(p.secret))
	ctx := t.Context()
	db := try.To1(storage.OpenBolt(filepath.Join(t.TempDir(), "vault.db")))
	defer func() { try.Out(db.Close()).Logf() }()
	try.To(db.CreateVault(ctx, p.vault, p.id, p))
	vault := try.To1(db.OpenVault(ctx, p.vault, p.id, p))
	defer func() { try.Out(vault.Close()).Logf() }()
	handler := ownerapi.NewStatusHandler(vault, expectedRoot, expectedChild)

	for _, status := range []int{http.StatusOK, http.StatusInternalServerError} {
		if status == http.StatusInternalServerError {
			try.To(vault.Close())
		}
		failed := &ownerStatusFailedWriter{
			ResponseRecorder: httptest.NewRecorder(),
		}
		handler.ServeHTTP(failed, httptest.NewRequest(
			http.MethodGet, "/owner/status", nil,
		))
		assert.Equal(failed.Code, status)
		assert.Equal(failed.headerCalls, 1)
		assert.Equal(failed.writeCalls, 1)
		assert.Equal(failed.Header().Get("Cache-Control"), "no-store")
	}
	try.To(vault.Close())
	try.To(db.Close())
}

type ownerStatusFailedWriter struct {
	*httptest.ResponseRecorder
	headerCalls int
	writeCalls  int
}

func (w *ownerStatusFailedWriter) WriteHeader(status int) {
	w.headerCalls++
	w.ResponseRecorder.WriteHeader(status)
}

func (w *ownerStatusFailedWriter) Write([]byte) (int, error) {
	w.writeCalls++
	return 0, errors.New("response write failed")
}

func readOwnerStatus(handler http.Handler) (choice string, err error) {
	defer err2.Handle(&err)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(
		http.MethodGet, "/owner/status", nil,
	))
	assert.Equal(response.Code, http.StatusOK)
	assert.Equal(response.Header().Get("Content-Type"), "application/json")
	assert.Equal(response.Header().Get("Cache-Control"), "no-store")
	var fields map[string]string
	try.To(json.Unmarshal(response.Body.Bytes(), &fields))
	assert.Equal(len(fields), 1)
	choice, found := fields["choice"]
	assert.That(found)
	return choice, nil
}
