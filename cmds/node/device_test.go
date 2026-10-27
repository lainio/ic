package node

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const ownerBootstrapPath = "/owner/device/bootstrap"

func serveDeviceRequest(handler http.Handler, auth, method, path string, body []byte) *httptest.ResponseRecorder {
	var reader io.Reader
	if len(body) != 0 {
		reader = bytes.NewReader(body)
	}
	r := httptest.NewRequest(method, path, reader)
	r.Header.Set("Authorization", auth)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func serveAuthorization(t *testing.T, s *nodeServe) string {
	t.Helper()
	defer assert.PushTester(t)()
	return strings.TrimSpace(strings.TrimPrefix(string(try.To1(os.ReadFile(s.headerFile))), "Authorization: "))
}

func TestServeExplicitDeviceBootstrapRequiresOwnKnown(t *testing.T) {
	defer assert.PushTester(t)()
	f := prepareServeFixture(t)
	choice := saveServeChoice(t, f, "completed")
	s := setupPeerServe(t, f)
	auth := serveAuthorization(t, s)
	request := func(method, path string, body []byte) *httptest.ResponseRecorder {
		return serveDeviceRequest(s.handler, auth, method, path, body)
	}
	bootstrap := func() *httptest.ResponseRecorder {
		return request(http.MethodPost, ownerBootstrapPath, []byte("{}"))
	}
	refused := func() {
		t.Helper()
		before := try.To1(os.ReadFile(filepath.Join(f.dir, "state", "vault.db")))
		w := bootstrap()
		assert.Equal(w.Code, http.StatusConflict)
		assert.Equal(w.Body.String(), "Conflict\n")
		assert.Equal(try.To1(device.InspectLocal(s.store.Vault(), f.root, f.child, nil)), device.Local{})
		assert.DeepEqual(try.To1(os.ReadFile(filepath.Join(f.dir, "state", "vault.db"))), before)
	}
	refused() // Completed local choice and startup alone do not establish Known.
	assert.Equal(request("GET", ownerBootstrapPath, nil).Code, 405)
	assert.Equal(request("GET", "/owner/status", nil).Code, 200)
	for _, token := range []string{"", "Bearer wrong"} {
		assert.Equal(serveDeviceRequest(s.handler, token, "POST", ownerBootstrapPath, []byte("{}")).Code, 401)
	}
	assert.Equal(serveDeviceRequest(s.peerHandler, auth, "POST", ownerBootstrapPath, []byte("{}")).Code, 404)
	peerBefore := serveDeviceRequest(s.peerHandler, auth, "GET", "/peer/introduction", nil)
	assert.Equal(peerBefore.Code, http.StatusOK)
	assert.DeepEqual(peerBefore.Body.Bytes(), try.To1(onboarding.EncodeIntroduction(choice)))
	refused() // GET and peer disclosure did not bootstrap either.

	// Another subject's Known path contains this node as an ancestor, but does
	// not satisfy BootstrapLocal's own-subject guard in the v0.1 projection.
	signer := try.To1(nodeidentity.OpenDirectory(f.dir, f.unlock))
	other := key.New()
	path := f.proposal.Introduce(signer, key.Info{Public: try.To1(other.CBORPublicKey())})
	document := try.To1(onboarding.EncodeIntroduction(onboarding.StoredChoice{
		Proposal: path, Acceptance: try.To1(path.SignAcceptance(other)),
	}))
	assert.Equal(request("POST", "/owner/introductions", document).Code, 200)
	assert.Equal(request("POST", "/owner/introductions/verify", []byte("{}")).Code, 200)
	assert.SLen(try.To1(onboarding.ListKnownIntroductions(s.store.Vault(), f.root)), 1)
	refused()
	exported := request("GET", "/owner/introduction", nil)
	assert.Equal(exported.Code, 200)
	assert.Equal(request("POST", "/owner/introductions", exported.Body.Bytes()).Code, 200)
	refused() // Own Received evidence still needs the separate verify request.
	assert.Equal(request("POST", "/owner/introductions/verify", []byte("{}")).Code, 200)
	assert.Equal(try.To1(device.InspectLocal(s.store.Vault(), f.root, f.child, nil)), device.Local{})
	before := try.To1(deviceUnrelatedRecords(s.store.Vault()))
	w := bootstrap()
	assert.Equal(w.Code, http.StatusOK)
	assert.Equal(w.Body.String(), `{"authorized":true,"usable":true}`)
	assert.Equal(w.Header().Get("Content-Type"), "application/json")
	assert.Equal(w.Header().Get("Cache-Control"), "no-store")
	assert.Equal(try.To1(device.InspectLocal(s.store.Vault(), f.root, f.child, nil)), device.Local{Authorized: true})
	assert.Equal(try.To1(device.InspectLocal(s.store.Vault(), f.root, f.child, signer)), device.Local{Authorized: true, Usable: true})
	assert.DeepEqual(try.To1(deviceUnrelatedRecords(s.store.Vault())), before)
	_, found := try.To2(ads.ReadCurrentLocal(s.store.Vault(), f.root, f.child, time.Now()))
	assert.ThatNot(found)
	assert.DeepEqual(serveDeviceRequest(s.peerHandler, "", "GET", "/peer/introduction", nil).Body.Bytes(), peerBefore.Body.Bytes())
	for _, name := range []string{"vault.db", "usage.db"} {
		file := filepath.Join(f.dir, "state", name)
		beforeRetry := try.To1(os.ReadFile(file))
		// setupPeerServe configures :0 but has not bound a peer listener.
		assert.Equal(request("POST", "/owner/ads/publish", []byte("{}")).Code, 409)
		assert.Equal(bootstrap().Code, 409)
		assert.That(bytes.Equal(try.To1(os.ReadFile(file)), beforeRetry))
	}
	try.To(s.close())

	// Actual service restart restores the same identity and authorization. It
	// reports only the saved choice; current usability still needs a new probe.
	s = setupPeerServe(t, f)
	auth = serveAuthorization(t, s)
	assert.Equal(try.To1(device.InspectLocal(s.store.Vault(), f.root, f.child, nil)), device.Local{Authorized: true})
	assert.DeepEqual(try.To1(deviceUnrelatedRecords(s.store.Vault())), before)
	assertPeerFilesUnchanged(t, f)
	assert.Equal(request("GET", "/owner/status", nil).Body.String(), "{\"choice\":\"completed\"}\n")
	assert.Equal(bootstrap().Code, 409)
	try.To(s.close())
}

// Snapshot the existing domains independently of device.InspectLocal. No ad
// operation is invoked, and no alternative device record format is introduced.
func deviceUnrelatedRecords(vault *storage.Vault) (_ map[string]map[string][]byte, err error) {
	defer err2.Handle(&err, nil)
	result := make(map[string]map[string][]byte)
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		for _, name := range []string{"introduction-choice-demo", "received-introductions-v1", "known-introductions-v1", "local-current-ad-v1"} {
			if !try.To1(tx.HasChild([]byte(name))) {
				continue
			}
			ns := try.To1(tx.Child([]byte(name)))
			result[name] = make(map[string][]byte)
			try.To(ns.Each(func(k, v []byte) error {
				result[name][string(k)] = v
				return nil
			}))
		}
		return nil
	}))
	return result, nil
}

func TestServeShutdownJoinsAdmittedSigning(t *testing.T) {
	for _, operation := range []string{ownerBootstrapPath, ownerPublishPath} {
		t.Run(operation, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := prepareServeFixture(t)
			choice := saveServeChoice(t, f, "completed")
			s := setupPeerServe(t, f)
			try.To2(onboarding.SaveIntroduction(s.store.Vault(), f.root, choice.Proposal.Bytes(), choice.Acceptance))
			try.To1(onboarding.VerifyReceived(s.store.Vault(), f.root))
			auth := serveAuthorization(t, s)
			if operation == ownerPublishPath {
				assert.Equal(serveDeviceRequest(s.handler, auth, "POST", ownerBootstrapPath, []byte("{}")).Code, 200)
			}
			owner, peer := try.To2(bindNodeListeners(t.Context(), "127.0.0.1:0", s.peerAddress))
			listener := &peerObservedListener{Listener: owner, closed: make(chan struct{})}
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			next := s.handler
			s.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				<-release
				next.ServeHTTP(w, r)
			})
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			var result error
			go func() {
				result = runNodeServe(ctx, listener, peer, s, io.Discard)
				close(done)
			}()
			defer func() { cancel(); unblock(); waitNodeServe(t, done) }()
			response := make(chan peerHTTPResult, 1)
			go func() {
				response <- postDeviceHTTP(t.Context(), "http://"+owner.Addr().String()+operation, auth)
			}()
			waitNodeServe(t, entered)
			cancel()
			waitNodeServe(t, listener.closed)
			select {
			case <-done:
				t.Fatal("service closed while signing request was admitted")
			default:
			}
			assert.Equal(try.To1(device.InspectLocal(s.store.Vault(), f.root, f.child, nil)), device.Local{Authorized: operation == ownerPublishPath})
			unblock()
			waitNodeServe(t, done)
			assert.NoError(result)
			got := waitPeerHTTP(t, response)
			assert.NoError(got.err)
			assert.Equal(got.status, http.StatusOK)
			if operation == ownerBootstrapPath {
				assert.Equal(string(got.body), `{"authorized":true,"usable":true}`)
			}
			_, err := device.InspectLocal(s.store.Vault(), f.root, f.child, nil)
			assert.ErrorIs(err, storage.ErrClosed)
			reopened := try.To1(nodevault.OpenForNode(t.Context(), f.dir, f.storageKey, f.root, f.child))
			defer func() { try.Out(reopened.Close()).Logf() }()
			assert.Equal(try.To1(device.InspectLocal(reopened.Vault(), f.root, f.child, nil)), device.Local{Authorized: true})
			current, found := try.To2(ads.ReadCurrentLocal(reopened.Vault(), f.root, f.child, time.Now()))
			assert.Equal(found, operation == ownerPublishPath)
			if found {
				assertPublishedSummary(t, got.body, current, "http://"+peer.Addr().String()+"/peer/introduction")
			}
			try.To(reopened.Close())
		})
	}
}

func postDeviceHTTP(ctx context.Context, url, auth string) (result peerHTTPResult) {
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader("{}"))
	if err != nil {
		return peerHTTPResult{err: err}
	}
	r.Header.Set("Authorization", auth)
	r.Header.Set("Content-Type", "application/json")
	response, err := client.Do(r)
	if err != nil {
		return peerHTTPResult{err: err}
	}
	body, err := io.ReadAll(response.Body)
	return peerHTTPResult{response.StatusCode, body, errors.Join(err, response.Body.Close())}
}
