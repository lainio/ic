package node

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/findy-network/findy-agent-auth/acator/enclave"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/cmds"
	coreintro "github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
	"github.com/spf13/cobra"
)

func TestServeRegistration(t *testing.T) {
	defer assert.PushTester(t)()

	registered, args := try.To2(cmds.RootCmd().Find([]string{"node", "serve"}))
	assert.SEmpty(args)
	assert.Equal(registered.Name(), "serve")
	assert.Equal(registered.Parent().Name(), "node")
	assert.That(registered.RunE != nil)
	assert.NoError(registered.ValidateArgs(nil))
	assert.Error(registered.ValidateArgs([]string{"extra"}))
	assert.Equal(
		try.To1(registered.Flags().GetString("listen")),
		"127.0.0.1:0",
	)
	assert.Nil(registered.Flags().Lookup("url"))

	cmd := testCommand("serve")
	var output bytes.Buffer
	cmd.SetOut(&output)
	try.To(cmd.Help())
	for _, text := range []string{
		"Root can be stopped", "status-only", "existing", "--dir",
		"--unlock-file", "--storage-key-file", "--root", "--listen",
		"--header '@HEADER_FILE'", "Ctrl+C", "trusted local host",
	} {
		assert.That(strings.Contains(output.String(), text), text)
	}

	var completion bytes.Buffer
	try.To(newNodeCommand().GenBashCompletion(&completion))
	assert.That(strings.Contains(completion.String(), "_node_serve()"))
}

// Reuse the node initialization fixture. Root exists only here to prepare a
// real proposal; no Root handle or process survives into service setup.
type serveFixture struct {
	dir, unlock, storageKey string
	root, child             key.Public
	proposal                coreintro.Path
}

func prepareServeFixture(t *testing.T) serveFixture {
	t.Helper()
	defer assert.PushTester(t)()

	dir, unlock, _ := initialized(t)
	alice := try.To1(nodeidentity.OpenDirectory(dir, unlock))
	root := key.New()
	f := serveFixture{
		dir: dir, unlock: unlock,
		storageKey: filepath.Join(filepath.Dir(dir), "storage-key"),
		root: try.To1(
			root.CBORPublicKey(),
		), child: try.To1(alice.CBORPublicKey()),
	}
	f.proposal = coreintro.New(key.Info{Public: f.root}).Introduce(
		root, key.Info{Public: f.child},
	)
	s := try.To1(nodevault.CreateForNode(
		t.Context(), f.dir, f.storageKey, f.root, f.child,
	))
	try.To(s.Close())
	for _, path := range []string{
		filepath.Join(dir, "identity.json"), unlock, f.storageKey,
	} {
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
	return f
}

func (f serveFixture) args() []string {
	return append(
		nodeArgs(f.dir, f.unlock),
		"--storage-key-file",
		f.storageKey,
		"--root",
		hex.EncodeToString(f.root),
	)
}

func serveCommand(t *testing.T, f serveFixture) *cobra.Command {
	t.Helper()
	defer assert.PushTester(t)()

	cmd := testCommand("serve")
	cmd.SetContext(t.Context())
	try.To(cmd.ParseFlags(f.args()))
	return cmd
}

// Only fixture preparation may sign. The failed signature leaves a legitimate
// selected-but-pending choice through the accepted onboarding operation.
type serveFailSigner struct {
	key.Handle
	err error
}

func (s serveFailSigner) Sign([]byte) ([]byte, error) { return nil, s.err }

func saveServeChoice(
	t *testing.T,
	f serveFixture,
	state string,
) onboarding.StoredChoice {
	t.Helper()
	defer assert.PushTester(t)()

	s := try.To1(nodevault.OpenForNode(
		t.Context(), f.dir, f.storageKey, f.root, f.child,
	))
	defer func() { try.Out(s.Close()).Logf() }()
	if state != "unselected" {
		signer := try.To1(nodeidentity.OpenDirectory(f.dir, f.unlock))
		want := errors.New("fixture signing unavailable")
		if state == "pending" {
			signer = serveFailSigner{Handle: signer, err: want}
		}
		_, err := onboarding.SignAfterStoredChoice(
			s.Vault(), signer, f.root, f.root, f.proposal,
		)
		if state == "pending" {
			assert.ErrorIs(err, want)
		} else {
			assert.NoError(err)
		}
	}
	choice, found := try.To2(
		onboarding.ReadStoredChoice(s.Vault(), f.root, f.child),
	)
	assert.Equal(found, state != "unselected")
	if state == "completed" {
		assert.NoError(choice.Proposal.VerifyAcceptance(choice.Acceptance))
	}
	try.To(s.Close())
	return choice
}

type serveObservedEnclave struct {
	enclave.Secure
	created int
}

func (e *serveObservedEnclave) NewKeyHandle() (enclave.KeyHandle, error) {
	e.created++
	return nil, errors.New("service must not generate a global key")
}

func TestServeSavedChoices(t *testing.T) {
	defer assert.PushTester(t)()

	f := prepareServeFixture(t)
	observed := &serveObservedEnclave{Secure: key.Enclave}
	key.Enclave = observed
	defer func() { key.Enclave = observed.Secure }()
	var previousHeader string
	// Advance one fixture explicitly between invocations. Service startup and
	// status inspection must preserve each saved choice, including pending.
	for _, state := range []string{"unselected", "pending", "completed"} {
		before := saveServeChoice(t, f, state)
		cmd := serveCommand(t, f)
		try.To(cmd.Flags().Set("listen", "localhost:0"))
		s, address := try.To2(setupNodeServe(t.Context(), cmd))
		defer func() { try.Out(s.close()).Logf() }()
		assert.Equal(address, "127.0.0.1:0")
		assert.DeepEqual(s.child, f.child)
		header := string(try.To1(os.ReadFile(s.headerFile)))
		assert.That(header != previousHeader)
		previousHeader = header
		authorization := strings.TrimSuffix(
			strings.TrimPrefix(header, "Authorization: "),
			"\n",
		)
		assert.Equal(
			try.To1(os.Stat(s.headerFile)).Mode().Perm(),
			os.FileMode(0600),
		)
		assert.Equal(
			try.To1(os.Stat(s.credentialDir)).Mode().Perm(),
			os.FileMode(0700),
		)
		vaultPath := filepath.Join(f.dir, "state", "vault.db")
		contents := try.To1(os.ReadFile(vaultPath))

		for _, tc := range []struct {
			method, path, credential string
			status                   int
		}{
			{http.MethodGet, "/owner/status", "", http.StatusUnauthorized},
			{http.MethodGet, "/owner/status", "Bearer wrong", http.StatusUnauthorized},
			{http.MethodGet, "/owner/status", authorization, http.StatusOK},
			{http.MethodPost, "/intro/offer", authorization, http.StatusNotFound},
			{http.MethodPost, "/intro/acceptance", authorization, http.StatusNotFound},
		} {
			request := httptest.NewRequest(tc.method, tc.path, nil)
			request.Header.Set("Authorization", tc.credential)
			response := httptest.NewRecorder()
			s.handler.ServeHTTP(response, request)
			assert.Equal(response.Code, tc.status)
			if tc.status == http.StatusOK {
				assert.Equal(
					response.Body.String(),
					"{\"choice\":\""+state+"\"}\n",
				)
			}
		}
		assert.DeepEqual(try.To1(os.ReadFile(vaultPath)), contents)
		try.To(s.close())
		assertServeClosed(t, s, f, before)
		assert.Equal(observed.created, 0)
	}
}

func assertServeClosed(t *testing.T, s *nodeServe, f serveFixture,
	before onboarding.StoredChoice,
) {
	t.Helper()
	defer assert.PushTester(t)()

	_, err := os.Stat(s.credentialDir)
	assert.ErrorIs(err, os.ErrNotExist)
	_, _, err = onboarding.ReadStoredChoice(s.store.Vault(), f.root, f.child)
	assert.ErrorIs(err, storage.ErrClosed)
	reopened := try.To1(nodevault.OpenForNode(
		t.Context(), f.dir, f.storageKey, f.root, f.child,
	))
	defer func() { try.Out(reopened.Close()).Logf() }()
	after, found := try.To2(
		onboarding.ReadStoredChoice(reopened.Vault(), f.root, f.child),
	)
	assert.Equal(found, before.Proposal != nil)
	assert.DeepEqual(after, before)
	try.To(reopened.Close())
}

func TestServeValidationBeforeResources(t *testing.T) {
	defer assert.PushTester(t)()

	f := prepareServeFixture(t)
	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	usagePath := filepath.Join(f.dir, "state", "usage.db")
	before := try.To1(os.ReadFile(usagePath))
	for i := range 4 {
		for _, value := range []string{"missing", "", " "} {
			args := f.args()
			if value == "missing" {
				args = append(args[:2*i], args[2*i+2:]...)
			} else {
				args[2*i+1] = value
			}
			cmd := testCommand("serve")
			cmd.SetContext(t.Context())
			cmd.SetOut(io.Discard)
			assert.Error(invoke(cmd, args))
		}
	}
	for _, tc := range []struct {
		name, value, diagnostic string
	}{
		{"listen", "0.0.0.0:0", "checking --listen"},
		{"root", "xyz", "nonempty hex"},
		{"root", strings.Repeat("01", 16*1024+1), "exceeds 16 KiB"},
		{"storage-key-file", f.unlock, "must differ"},
		{"storage-key-file", filepath.Join(f.dir, "key"), "outside"},
	} {
		cmd := serveCommand(t, f)
		try.To(cmd.Flags().Set(tc.name, tc.value))
		err := cmd.RunE(cmd, nil)
		assert.Error(err)
		assert.That(strings.Contains(err.Error(), tc.diagnostic), err)
	}
	cmd := serveCommand(t, f)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	cmd.SetContext(ctx)
	assert.ErrorIs(cmd.RunE(cmd, nil), context.Canceled)
	assert.Error(cmd.RunE(cmd, []string{"extra"}))
	assert.DeepEqual(try.To1(os.ReadFile(usagePath)), before)
	assert.SEmpty(try.To1(os.ReadDir(parent)))
}

func TestServeMissingStateAndWrongBinding(t *testing.T) {
	defer assert.PushTester(t)()

	dir, unlock, _ := initialized(t)
	keyFile := filepath.Join(filepath.Dir(dir), "storage-key")
	secret := bytes.Repeat([]byte{42}, 32)
	try.To(os.WriteFile(keyFile, secret, 0600))
	identity := try.To1(os.ReadFile(filepath.Join(dir, "identity.json")))
	cmd := testCommand("serve")
	cmd.SetContext(t.Context())
	var output bytes.Buffer
	cmd.SetOut(&output)
	assert.ErrorIs(invoke(cmd, append(nodeArgs(dir, unlock),
		"--storage-key-file", keyFile, "--root", "01")), os.ErrNotExist)
	_, err := os.Lstat(filepath.Join(dir, "state"))
	assert.ErrorIs(err, os.ErrNotExist)
	assert.That(bytes.Equal(try.To1(os.ReadFile(keyFile)), secret))
	assert.That(
		bytes.Equal(
			try.To1(os.ReadFile(filepath.Join(dir, "identity.json"))),
			identity,
		),
	)
	assert.Equal(try.To1(os.ReadDir(dir))[0].Name(), "identity.json")
	assert.SLen(try.To1(os.ReadFile(unlock)), 32)
	assert.Empty(output.String())

	f := prepareServeFixture(t)
	cmd = serveCommand(t, f)
	cmd.SetOut(&output)
	try.To(cmd.Flags().Set("root", "01"))
	err = cmd.RunE(cmd, nil)
	assert.Error(err)
	assert.That(strings.Contains(err.Error(), "binding"), err)
	assert.Empty(output.String())
	// A failed open releases its usage lock and preserves the original binding.
	s := try.To1(
		nodevault.OpenForNode(
			t.Context(),
			f.dir,
			f.storageKey,
			f.root,
			f.child,
		),
	)
	try.To(s.Close())
}

func TestServeCredentialSetupFailureReleasesStore(t *testing.T) {
	defer assert.PushTester(t)()

	f := prepareServeFixture(t)
	parent := t.TempDir()
	t.Setenv("TMPDIR", filepath.Join(parent, "missing"))
	s, _, err := setupNodeServe(t.Context(), serveCommand(t, f))
	assert.ErrorIs(err, os.ErrNotExist)
	assert.Nil(s)
	assert.SEmpty(try.To1(os.ReadDir(parent)))

	reopened := try.To1(nodevault.OpenForNode(
		t.Context(), f.dir, f.storageKey, f.root, f.child,
	))
	try.To(reopened.Close())
}

// Already-bound listener stand-in: no socket, DNS lookup, or outbound request.
type serveListener struct {
	entered, closed chan struct{}
	closes          atomic.Int32
	acceptErr       error
	closeErr        error
}

func (l *serveListener) Accept() (net.Conn, error) {
	close(l.entered)
	if l.acceptErr != nil {
		return nil, l.acceptErr
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *serveListener) Close() error {
	if l.closes.Add(1) == 1 {
		close(l.closed)
		return l.closeErr
	}
	return net.ErrClosed
}

func (*serveListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}

func TestServeLifecycle(t *testing.T) {
	defer assert.PushTester(t)()

	f := prepareServeFixture(t)
	before := saveServeChoice(t, f, "completed")
	for _, scenario := range []string{"cancel", "serve", "output and close"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()

			s, _ := try.To2(setupNodeServe(t.Context(), serveCommand(t, f)))
			defer func() { try.Out(s.close()).Logf() }()
			listener := &serveListener{
				entered: make(chan struct{}), closed: make(chan struct{}),
			}
			want := errors.New("service lifecycle failure")
			closeFailure := errors.New("listener close failure")
			var output bytes.Buffer
			var out io.Writer = &output
			switch scenario {
			case "serve":
				listener.acceptErr = want
			case "output and close":
				out = failingWriter{want}
				listener.closeErr = closeFailure
			default:
				want = nil
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			done := make(chan struct{})
			var result error
			go func() {
				result = runNodeServe(ctx, listener, s, out)
				close(done)
			}()
			defer func() {
				cancel()
				waitNodeServe(t, done)
			}()
			if scenario == "cancel" {
				select {
				case <-listener.entered:
					cancel()
				case <-ctx.Done():
					t.Fatal("Serve did not start")
				}
			}
			waitNodeServe(t, done)
			if want == nil {
				assert.NoError(result)
			} else {
				assert.ErrorIs(result, want)
			}
			if scenario == "output and close" {
				assert.ErrorIs(result, closeFailure)
				assert.Empty(output.String())
			} else {
				assert.Equal(output.String(), fmt.Sprintf(
					"node public key (hex): %x\n"+
						"owner status URL: http://127.0.0.1:1234/owner/status\n"+
						"authorization header file: %s\nstop with Ctrl+C\n",
					f.child, s.headerFile))
			}
			assert.Equal(listener.closes.Load(), int32(1))
			assertServeClosed(t, s, f, before)
		})
	}
}

func waitNodeServe(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(7 * time.Second):
		t.Fatal("service failed to stop within the shutdown bound")
	}
}
