package intro

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
	"github.com/spf13/cobra"
)

func TestHTTPSavedAliceFlags(t *testing.T) {
	defer assert.PushTester(t)()

	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	rootHex := hex.EncodeToString(try.To1(key.New().CBORPublicKey()))
	observed := &httpDemoEnclave{Secure: key.Enclave}
	key.Enclave = observed
	defer func() { key.Enclave = observed.Secure }()
	cmd := newHTTPDemoRoleCommand("accept")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	cmd.SetContext(ctx)
	var output bytes.Buffer
	cmd.SetOut(&output)
	try.To(cmd.ParseFlags([]string{
		"--url", "http://127.0.0.1:1234", "--root", rootHex,
		"--identity-dir", filepath.Join(parent, "alice"),
		"--unlock-file", filepath.Join(parent, "unlock"),
		"--storage-key-file", filepath.Join(parent, "storage-key"),
		"--owner-listen", "127.0.0.1:0",
	}))

	assert.ErrorIs(cmd.RunE(cmd, nil), context.Canceled)
	assert.Empty(output.String())
	assert.Equal(observed.created, 0)
	assert.SEmpty(try.To1(os.ReadDir(parent)))
}

// Root uses the existing saved-identity fixture. Alice additionally owns state;
// only immutable identity/secret files are compared, without printing secrets.
func prepareHTTPSavedAlice(
	t *testing.T,
) (savedAlicePaths, key.Handle, key.Public) {
	t.Helper()
	defer assert.PushTester(t)()

	rootDir, rootUnlock, expectedRoot := savedHTTPDemoIdentity(t)
	root := try.To1(nodeidentity.OpenDirectory(rootDir, rootUnlock))
	parent := t.TempDir()
	paths := savedAlicePaths{filepath.Join(parent, "alice"),
		filepath.Join(
			parent,
			"alice-unlock",
		), filepath.Join(parent, "alice-storage-key")}
	try.To(os.Mkdir(paths.dir, 0700))
	unlock := make([]byte, 32)
	defer clear(unlock)
	try.To1(rand.Read(unlock))
	try.To(os.WriteFile(paths.unlock, unlock, 0600))
	record := filepath.Join(paths.dir, "identity.json")
	alice := try.To1(nodeidentity.Create(record, unlock))
	child := try.To1(alice.CBORPublicKey())
	assert.That(!bytes.Equal(child, expectedRoot))
	s := try.To1(
		nodevault.CreateForNode(
			t.Context(),
			paths.dir,
			paths.storageKey,
			expectedRoot,
			child,
		),
	)
	try.To(s.Close())
	for _, path := range []string{record, paths.unlock, paths.storageKey} {
		before := try.To1(os.ReadFile(path))
		info := try.To1(os.Stat(path))
		t.Cleanup(func() {
			defer assert.PushTester(t)()
			defer clear(before)

			after := try.To1(os.ReadFile(path))
			defer clear(after)
			assert.That(bytes.Equal(after, before))
			current := try.To1(os.Stat(path))
			assert.That(os.SameFile(info, current))
			assert.Equal(current.Mode(), info.Mode())
			assert.Equal(current.ModTime(), info.ModTime())
		})
	}
	return paths, root, expectedRoot
}

type savedHTTPCall struct {
	request *http.Request
	body    []byte
}

func savedAliceClient(
	t *testing.T,
	peer http.Handler,
	calls *[]savedHTTPCall,
) *http.Client {
	t.Helper()
	client := newHTTPDemoClient()
	t.Cleanup(client.CloseIdleConnections)
	client.Transport = httpDemoRoundTripper(
		func(r *http.Request) (response *http.Response, err error) {
			defer err2.Handle(&err)

			body := try.To1(io.ReadAll(r.Body))
			*calls = append(*calls, savedHTTPCall{r, body})
			r.Body = io.NopCloser(bytes.NewReader(body))
			recorder := httptest.NewRecorder()
			peer.ServeHTTP(recorder, r)
			return recorder.Result(), nil
		},
	)
	return client
}

type savedAliceFailSigner struct {
	key.Handle
	calls int
	err   error
}

func (s *savedAliceFailSigner) Sign([]byte) ([]byte, error) {
	s.calls++
	return nil, s.err
}

func TestHTTPSavedAliceRestart(t *testing.T) {
	defer assert.PushTester(t)()

	paths, root, expectedRoot := prepareHTTPSavedAlice(t)
	peer := newHTTPExchangeHandler(root)
	observed := &httpDemoEnclave{Secure: key.Enclave}
	key.Enclave = observed
	defer func() { key.Enclave = observed.Secure }()
	var firstSignature key.Signature
	var firstChoice onboarding.StoredChoice
	// Only Root's handler survives each exchange; Alice's handle, Store and
	// HTTP client are reloaded. This is in-process composition, not live TCP.
	for attempt := range 2 {
		a := try.To1(openHTTPSavedAlice(t.Context(), paths, expectedRoot))
		defer func() { try.Out(a.close()).Logf() }()
		var calls []savedHTTPCall
		client := savedAliceClient(t, peer, &calls)
		var noSign *savedAliceFailSigner
		if attempt == 1 {
			noSign = &savedAliceFailSigner{
				Handle: a.alice,
				err:    errors.New("retry must not sign"),
			}
			a.alice = noSign
		}
		var output bytes.Buffer
		signature := try.To1(runHTTPSavedAliceOnce(t.Context(), client, a,
			"http://127.0.0.1:1234", time.Second, &output))
		client.CloseIdleConnections()
		assertHTTPSavedClosed(t, a)
		assert.That(
			strings.HasPrefix(
				output.String(),
				fmt.Sprintf("node public key (hex): %x\n", a.child),
			),
		)
		assert.That(
			strings.HasSuffix(
				output.String(),
				"issuer returned HTTP 204: true\n",
			),
		)
		assert.Equal(observed.created, 0)
		if attempt == 0 {
			assert.SLen(calls, 2)
			assert.Equal(calls[0].request.URL.Path, "/intro/offer")
			firstSignature = signature
		} else {
			assert.SLen(calls, 1)
			assert.Equal(noSign.calls, 0)
			assert.DeepEqual(signature, firstSignature)
			assert.That(strings.Contains(output.String(), "using saved introduction: true\n"))
			assert.That(!strings.Contains(output.String(), "proposal received"))
		}
		last := calls[len(calls)-1]
		assert.Equal(last.request.URL.Path, "/intro/acceptance")
		var submitted key.Signature
		try.To(wire.UnmarshalCanonical(&submitted, last.body))
		assert.DeepEqual(submitted, firstSignature)
		for _, call := range calls {
			assert.Empty(call.request.Header.Get("Authorization"))
		}

		check := try.To1(openHTTPSavedAlice(t.Context(), paths, expectedRoot))
		defer func() { try.Out(check.close()).Logf() }()
		choice, found := try.To2(
			onboarding.ReadStoredChoice(
				check.store.Vault(),
				check.root,
				check.child,
			),
		)
		assert.That(found)
		assert.DeepEqual(choice.Acceptance, firstSignature)
		assert.NoError(choice.Proposal.VerifyAcceptance(choice.Acceptance))
		if attempt == 0 {
			firstChoice = choice
		} else {
			assert.DeepEqual(choice.Proposal.Bytes(), firstChoice.Proposal.Bytes())
		}
		try.To(check.close())
	}

	// Restoring Root's identity does not restore its one retained proposal.
	var calls []savedHTTPCall
	client := savedAliceClient(t, newHTTPExchangeHandler(root), &calls)
	a := try.To1(openHTTPSavedAlice(t.Context(), paths, expectedRoot))
	var output bytes.Buffer
	signature, err := runHTTPSavedAliceOnce(t.Context(), client, a,
		"http://127.0.0.1:1234", time.Second, &output)
	assert.Error(err)
	assert.That(strings.Contains(err.Error(), "acceptance returned HTTP 409"))
	assert.SNil(signature)
	assert.SLen(calls, 1)
	assert.Equal(calls[0].request.URL.Path, "/intro/acceptance")
	assert.That(!strings.Contains(output.String(), "issuer returned HTTP 204"))
	check := try.To1(openHTTPSavedAlice(t.Context(), paths, expectedRoot))
	defer func() { try.Out(check.close()).Logf() }()
	choice, found := try.To2(
		onboarding.ReadStoredChoice(
			check.store.Vault(),
			check.root,
			check.child,
		),
	)
	assert.That(found)
	assert.DeepEqual(choice, firstChoice)
	try.To(check.close())
}

func assertHTTPSavedClosed(t *testing.T, a *httpSavedAlice) {
	t.Helper()
	defer assert.PushTester(t)()

	_, _, err := onboarding.ReadStoredChoice(a.store.Vault(), a.root, a.child)
	assert.ErrorIs(err, storage.ErrClosed)
	if a.credentialDir != "" {
		_, err = os.Lstat(a.credentialDir)
		assert.ErrorIs(err, os.ErrNotExist)
	}
}

func TestHTTPSavedAlicePendingAndResponseFailure(t *testing.T) {
	defer assert.PushTester(t)()

	paths, root, expectedRoot := prepareHTTPSavedAlice(t)
	peer := newHTTPExchangeHandler(root)
	var selected onboarding.StoredChoice
	want := errors.New("signing unavailable")
	for attempt := range 3 {
		a := try.To1(openHTTPSavedAlice(t.Context(), paths, expectedRoot))
		var calls []savedHTTPCall
		client := savedAliceClient(t, peer, &calls)
		signer := &savedAliceFailSigner{Handle: a.alice, err: want}
		if attempt < 2 {
			a.alice = signer
		} else {
			// Complete the pending choice, submit it to the real handler, then
			// fail closing the response. The saved result must survive.
			transport := client.Transport
			client.Transport = httpDemoRoundTripper(func(r *http.Request) (response *http.Response, err error) {
				defer err2.Handle(&err)

				response = try.To1(transport.RoundTrip(r))
				response.Body = &httpDemoBody{ReadCloser: response.Body, closeErr: want}
				return response, nil
			})
		}
		var output bytes.Buffer
		signature, err := runHTTPSavedAliceOnce(t.Context(), client, a,
			"http://127.0.0.1:1234", time.Second, &output)
		assert.ErrorIs(err, want)
		assert.SNil(signature)
		assertHTTPSavedClosed(t, a)
		switch attempt {
		case 0:
			assert.SLen(calls, 1)
			assert.Equal(calls[0].request.URL.Path, "/intro/offer")
		case 1:
			// Failed signing of an already selected proposal makes no request.
			assert.SEmpty(calls)
			assert.That(strings.Contains(output.String(), "using saved introduction: true"))
		default:
			assert.SLen(calls, 1)
			assert.Equal(calls[0].request.URL.Path, "/intro/acceptance")
		}
		if attempt < 2 {
			assert.Equal(signer.calls, 1)
		}
		check := try.To1(openHTTPSavedAlice(t.Context(), paths, expectedRoot))
		defer func() { try.Out(check.close()).Logf() }()
		choice, found := try.To2(
			onboarding.ReadStoredChoice(
				check.store.Vault(),
				check.root,
				check.child,
			),
		)
		assert.That(found)
		if attempt == 0 {
			selected = choice
		}
		assert.DeepEqual(choice.Proposal.Bytes(), selected.Proposal.Bytes())
		if attempt < 2 {
			assert.SNil(choice.Acceptance)
		} else {
			assert.NoError(choice.Proposal.VerifyAcceptance(choice.Acceptance))
		}
		try.To(check.close())
	}
}

func TestHTTPSavedAliceInvalidFlags(t *testing.T) {
	defer assert.PushTester(t)()

	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	rootHex := hex.EncodeToString(try.To1(key.New().CBORPublicKey()))
	observed := &httpDemoEnclave{Secure: key.Enclave}
	key.Enclave = observed
	defer func() { key.Enclave = observed.Secure }()
	names := []string{"identity-dir", "unlock-file", "storage-key-file"}
	base := []string{"--url", "http://127.0.0.1:1234", "--root", rootHex}
	var invalid [][]string
	for mask := 1; mask < 7; mask++ {
		var args []string
		for i, name := range names {
			if mask&(1<<i) != 0 {
				args = append(args, "--"+name, filepath.Join(parent, name))
			}
		}
		invalid = append(invalid, args)
	}
	for i := range names {
		var args []string
		for j, name := range names {
			value := filepath.Join(parent, name)
			if i == j {
				value = ""
			}
			args = append(args, "--"+name, value)
		}
		invalid = append(invalid, args)
	}
	for _, args := range invalid {
		cmd := newHTTPDemoRoleCommand("accept")
		cmd.SetContext(t.Context())
		var output bytes.Buffer
		cmd.SetOut(&output)
		try.To(cmd.ParseFlags(append(base[:len(base):len(base)], args...)))
		err := cmd.RunE(cmd, nil)
		assert.Error(err)
		assert.That(
			strings.Contains(err.Error(), "must all") ||
				strings.Contains(err.Error(), "nonempty"),
		)
		assert.Empty(output.String())
		assert.Equal(observed.created, 0)
		assert.SEmpty(try.To1(os.ReadDir(parent)))
	}
	_, saved := try.To2(httpSavedAlicePaths(newHTTPDemoRoleCommand("accept")))
	assert.ThatNot(saved)
	for _, cmd := range []*cobra.Command{
		newHTTPDemoRoleCommand("root"), newHTTPDemoCommand(),
		newExchangeRoleCommand("root"), newExchangeRoleCommand("accept"),
	} {
		assert.Nil(cmd.Flags().Lookup("storage-key-file"))
		assert.Nil(cmd.InheritedFlags().Lookup("storage-key-file"))
	}
}

func TestHTTPSavedAliceLocalFailures(t *testing.T) {
	defer assert.PushTester(t)()

	paths, root, expectedRoot := prepareHTTPSavedAlice(t)
	otherRoot := hex.EncodeToString(try.To1(key.New().CBORPublicKey()))
	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	usagePath := filepath.Join(paths.dir, "state", "usage.db")
	before := try.To1(os.ReadFile(usagePath))
	for _, scenario := range []string{"wrong root", "owner address", "endpoint", "timeout", "root", "same unlock"} {
		cmd := newHTTPDemoRoleCommand("accept")
		cmd.SetContext(t.Context())
		var output bytes.Buffer
		cmd.SetOut(&output)
		args := []string{
			"--identity-dir",
			paths.dir,
			"--unlock-file",
			paths.unlock,
			"--storage-key-file",
			paths.storageKey,
			"--root",
			hex.EncodeToString(expectedRoot),
			"--url",
			"http://127.0.0.1:1234",
			"--owner-listen",
			"127.0.0.1:0",
		}
		var diagnostic string
		switch scenario {
		case "wrong root":
			args = append(args, "--root", otherRoot)
			diagnostic = "binding"
		case "owner address":
			args = append(
				args,
				"--owner-listen",
				":0",
				"--unlock-file",
				"missing",
			)
			diagnostic = "checking --owner-listen"
		case "endpoint":
			args = append(
				args,
				"--url",
				"https://127.0.0.1:1234",
				"--unlock-file",
				"missing",
			)
			diagnostic = "checking --url"
		case "timeout":
			args = append(
				args,
				"--timeout",
				"0s",
				"--unlock-file",
				"missing",
			)
			diagnostic = "--timeout"
		case "root":
			args = append(args, "--root", "xyz", "--unlock-file", "missing")
			diagnostic = "checking --root"
		case "same unlock":
			args = append(args, "--storage-key-file", paths.unlock)
			diagnostic = "must differ"
		}
		try.To(cmd.ParseFlags(args))
		err := cmd.RunE(cmd, nil)
		assert.Error(err)
		assert.That(strings.Contains(err.Error(), diagnostic), err)
		assert.Empty(output.String())
		assert.DeepEqual(try.To1(os.ReadFile(usagePath)), before)
		assert.SEmpty(try.To1(os.ReadDir(parent)))
	}

	// An inconsistent saved choice is not absence and cannot trigger an offer.
	a := try.To1(openHTTPSavedAlice(t.Context(), paths, expectedRoot))
	try.To(a.store.Vault().Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err)

		records := try.To1(tx.EnsureChild([]byte("introduction-choice-demo")))
		return records.Put([]byte("acceptance"), []byte("orphaned-result"))
	}))
	try.To(a.close())
	a = try.To1(openHTTPSavedAlice(t.Context(), paths, expectedRoot))
	var calls []savedHTTPCall
	client := savedAliceClient(t, newHTTPExchangeHandler(root), &calls)
	var output bytes.Buffer
	signature, err := runHTTPSavedAliceOnce(t.Context(), client, a,
		"http://127.0.0.1:1234", time.Second, &output)
	assert.Error(err)
	assert.SNil(signature)
	assert.SEmpty(calls)
	assert.Empty(output.String())
	a = try.To1(openHTTPSavedAlice(t.Context(), paths, expectedRoot))
	defer func() { try.Out(a.close()).Logf() }()
	try.To(a.store.Vault().View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err)

		records := try.To1(tx.Child([]byte("introduction-choice-demo")))
		stored, found := try.To2(records.Get([]byte("acceptance")))
		assert.That(found)
		assert.Equal(string(stored), "orphaned-result")
		_, found = try.To2(records.Get([]byte("selected-proposal")))
		assert.ThatNot(found)
		return nil
	}))
	try.To(a.close())
}

func TestHTTPSavedAliceOwner(t *testing.T) {
	defer assert.PushTester(t)()

	paths, root, expectedRoot := prepareHTTPSavedAlice(t)
	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	a := try.To1(openHTTPSavedAlice(t.Context(), paths, expectedRoot))
	defer func() { try.Out(a.close()).Logf() }()
	try.To(a.setupOwner(t.Context()))
	header := string(try.To1(os.ReadFile(a.headerFile)))
	authorization := strings.TrimSuffix(
		strings.TrimPrefix(header, "Authorization: "),
		"\n",
	)
	assert.Equal(
		try.To1(os.Stat(a.headerFile)).Mode().Perm(),
		os.FileMode(0600),
	)
	assert.Equal(
		try.To1(os.Stat(a.credentialDir)).Mode().Perm(),
		os.FileMode(0700),
	)
	assert.That(
		!strings.HasPrefix(
			a.credentialDir,
			paths.dir+string(os.PathSeparator),
		),
	)
	request := httptest.NewRequest(http.MethodGet, "/owner/status", nil)
	response := httptest.NewRecorder()
	a.handler.ServeHTTP(response, request)
	assert.Equal(response.Code, http.StatusUnauthorized)
	request.Header.Set("Authorization", authorization)
	response = httptest.NewRecorder()
	a.handler.ServeHTTP(response, request)
	assert.Equal(response.Body.String(), "{\"choice\":\"unselected\"}\n")

	listener := &httpDemoListener{
		entered: make(chan struct{}),
		closed:  make(chan struct{}),
	}
	peer := newHTTPExchangeHandler(root)
	var calls []savedHTTPCall
	client := savedAliceClient(
		t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-listener.entered:
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			default:
			}
			peer.ServeHTTP(w, r)
		}),
		&calls,
	)
	ctx, cancel := context.WithCancel(t.Context())
	var output bytes.Buffer
	done := make(chan struct{})
	var result error
	go func() {
		result = runHTTPSavedAliceOwner(ctx, listener, a, client,
			"http://127.0.0.1:1234", time.Second, &output)
		close(done)
	}()
	defer func() {
		cancel()
		waitHTTPDemoRoot(t, done)
	}()
	select {
	case <-listener.entered:
	case <-done:
		t.Fatalf("owner stopped before Serve: %v", result)
	case <-time.After(5 * time.Second):
		t.Fatal("owner Serve did not start")
	}
	assert.NoError(ctx.Err())
	assert.SLen(calls, 2)
	for _, call := range calls {
		assert.Empty(call.request.Header.Get("Authorization"))
		assert.ErrorIs(call.request.Context().Err(), context.Canceled)
	}
	response = httptest.NewRecorder()
	a.handler.ServeHTTP(response, request)
	assert.Equal(response.Code, http.StatusOK)
	assert.Equal(response.Body.String(), "{\"choice\":\"completed\"}\n")
	choice, found := try.To2(
		onboarding.ReadStoredChoice(a.store.Vault(), a.root, a.child),
	)
	assert.That(found)
	var submitted key.Signature
	try.To(wire.UnmarshalCanonical(&submitted, calls[1].body))
	assert.DeepEqual(choice.Acceptance, submitted)

	cancel()
	waitHTTPDemoRoot(t, done)
	assert.NoError(result)
	assert.Equal(listener.closes.Load(), int32(1))
	assertHTTPSavedClosed(t, a)
	assert.SEmpty(try.To1(os.ReadDir(parent)))
	assert.That(
		!strings.Contains(
			output.String(),
			strings.TrimPrefix(authorization, "Bearer "),
		),
	)
	assert.That(
		strings.Contains(
			output.String(),
			"authorization header file: "+a.headerFile,
		),
	)
	secret := try.To1(os.ReadFile(paths.storageKey))
	defer clear(secret)
	assert.That(!strings.Contains(output.String(), hex.EncodeToString(secret)))

	reopened := try.To1(openHTTPSavedAlice(t.Context(), paths, expectedRoot))
	defer func() { try.Out(reopened.close()).Logf() }()
	saved, found := try.To2(
		onboarding.ReadStoredChoice(
			reopened.store.Vault(),
			reopened.root,
			reopened.child,
		),
	)
	assert.That(found)
	assert.DeepEqual(saved, choice)
	try.To(reopened.setupOwner(t.Context()))
	assert.NotEqual(reopened.headerFile, a.headerFile)
	assert.That(string(try.To1(os.ReadFile(reopened.headerFile))) != header)
	try.To(reopened.close())
}

func TestHTTPSavedAliceOwnerFailureCleanup(t *testing.T) {
	defer assert.PushTester(t)()

	paths, root, expectedRoot := prepareHTTPSavedAlice(t)
	a := try.To1(openHTTPSavedAlice(t.Context(), paths, expectedRoot))
	try.To(a.setupOwner(t.Context()))
	want := errors.New("sign unavailable")
	closeFailure := errors.New("listener close failure")
	a.alice = &savedAliceFailSigner{Handle: a.alice, err: want}
	listener := &httpDemoListener{
		entered:  make(chan struct{}),
		closed:   make(chan struct{}),
		closeErr: closeFailure,
	}
	var calls []savedHTTPCall
	client := savedAliceClient(t, newHTTPExchangeHandler(root), &calls)
	var output bytes.Buffer
	err := runHTTPSavedAliceOwner(t.Context(), listener, a, client,
		"http://127.0.0.1:1234", time.Second, &output)
	assert.ErrorIs(err, want)
	assert.ErrorIs(err, closeFailure)
	assertHTTPSavedClosed(t, a)
	assert.Equal(listener.closes.Load(), int32(1))
	select {
	case <-listener.entered:
		t.Fatal("owner served after exchange failure")
	default:
	}
	assert.That(!strings.Contains(output.String(), "owner status URL"))
	reopened := try.To1(openHTTPSavedAlice(t.Context(), paths, expectedRoot))
	defer func() { try.Out(reopened.close()).Logf() }()
	choice, found := try.To2(
		onboarding.ReadStoredChoice(
			reopened.store.Vault(),
			reopened.root,
			reopened.child,
		),
	)
	assert.That(found)
	assert.SNil(choice.Acceptance)
	try.To(reopened.close())
}
