package intro

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	coreintro "github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/key"
	"github.com/spf13/cobra"
)

func TestHTTPDemoSavedExchange(t *testing.T) {
	defer assert.PushTester(t)()

	dir, unlock, expectedRoot := savedHTTPDemoIdentity(t)
	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	// All fixture generation precedes observation; each exchange gets a new Alice.
	alices := []key.Handle{key.New(), key.New()}
	observed := &httpDemoEnclave{Secure: key.Enclave}
	key.Enclave = observed
	defer func() { key.Enclave = observed.Secure }()

	for _, alice := range alices {
		cmd := newHTTPDemoRoleCommand("root")
		cmd.SetContext(t.Context())
		try.To(cmd.ParseFlags([]string{
			"--identity-dir", dir, "--unlock-file", unlock,
		}))
		root := try.To1(selectHTTPDemoRoot(cmd))
		assert.DeepEqual(try.To1(root.CBORPublicKey()), []byte(expectedRoot))
		handler := newHTTPExchangeHandler(root)
		info := try.To1(exchangePublicInfo(alice))

		offer := postHTTPExchange(t.Context(), handler, "/intro/offer",
			wire.TryMarshal(info))
		assert.Equal(offer.Code, http.StatusOK)
		proposal := try.To1(coreintro.ParsePath(offer.Body.Bytes()))
		assert.NoError(proposal.ProveFromRoot(expectedRoot))
		for _, edge := range proposal {
			assert.SEmpty(edge.Body.Child.ID)
		}
		signature := try.To1(saveExchangeAcceptance(
			t.Context(), alice, expectedRoot, offer.Body.Bytes(), io.Discard,
		))
		assert.NoError(proposal.VerifyAcceptance(signature))
		accepted := postHTTPExchange(t.Context(), handler, "/intro/acceptance",
			wire.TryMarshal(signature))
		assert.Equal(accepted.Code, http.StatusNoContent)
		assert.Equal(observed.created, 0)
		assert.SEmpty(try.To1(os.ReadDir(parent)))
		// Discard this handle and handler; the next iteration issues a new offer.
	}
}

func TestHTTPDemoSavedFlagsAndFreshDefault(t *testing.T) {
	defer assert.PushTester(t)()

	root := newHTTPDemoRoleCommand("root")
	for _, name := range []string{"identity-dir", "unlock-file"} {
		assert.NotNil(root.LocalFlags().Lookup(name))
		assert.Nil(root.PersistentFlags().Lookup(name))
		for _, cmd := range []*cobra.Command{
			newHTTPDemoCommand(), newHTTPDemoRoleCommand("accept"),
			newExchangeRoleCommand("root"), newExchangeRoleCommand("accept"),
		} {
			assert.Nil(cmd.Flags().Lookup(name))
			assert.Nil(cmd.InheritedFlags().Lookup(name))
			assert.Error(cmd.ParseFlags([]string{"--" + name, "unused"}))
		}
	}
	assert.NoError(root.ValidateRequiredFlags())
	root.SetContext(t.Context())
	observed := &httpDemoEnclave{Secure: key.Enclave}
	key.Enclave = observed
	defer func() { key.Enclave = observed.Secure }()

	first := try.To1(selectHTTPDemoRoot(root))
	second := try.To1(selectHTTPDemoRoot(root))
	assert.Equal(observed.created, 2)
	assert.ThatNot(bytes.Equal(try.To1(first.CBORPublicKey()),
		try.To1(second.CBORPublicKey())))
}

func TestHTTPDemoSavedInvalidBeforeResources(t *testing.T) {
	defer assert.PushTester(t)()

	dir, unlock, _ := savedHTTPDemoIdentity(t)
	otherDir, otherUnlock, _ := savedHTTPDemoIdentity(t)
	emptyDir := filepath.Join(t.TempDir(), "empty")
	try.To(os.Mkdir(emptyDir, 0700))
	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	observed := &httpDemoEnclave{Secure: key.Enclave}
	key.Enclave = observed
	defer func() { key.Enclave = observed.Secure }()

	for _, tc := range []struct {
		name, diagnostic string
		args             []string
		canceled         bool
	}{
		{"directory only", "both", []string{"--identity-dir", dir}, false},
		{"unlock only", "both", []string{"--unlock-file", unlock}, false},
		{"empty directory only", "both", []string{"--identity-dir="}, false},
		{"empty unlock only", "both", []string{"--unlock-file="}, false},
		{"empty directory", "nonempty", []string{
			"--identity-dir=", "--unlock-file", unlock,
		}, false},
		{"empty unlock", "nonempty", []string{
			"--identity-dir", dir, "--unlock-file=",
		}, false},
		{"both empty", "nonempty", []string{
			"--identity-dir=", "--unlock-file=",
		}, false},
		{"blank paths", "nonempty", []string{
			"--identity-dir", " ", "--unlock-file", "\t",
		}, false},
		{"missing directory", "no such file", []string{
			"--identity-dir", filepath.Join(parent, "missing"),
			"--unlock-file", unlock,
		}, false},
		{"missing unlock", "no such file", []string{
			"--identity-dir", dir,
			"--unlock-file", filepath.Join(parent, "missing"),
		}, false},
		{"missing record", "no such file", []string{
			"--identity-dir", emptyDir, "--unlock-file", unlock,
		}, false},
		{"wrong unlock", "", []string{
			"--identity-dir", dir, "--unlock-file", otherUnlock,
		}, false},
		{"invalid listen before loading", "checking --listen", []string{
			"--identity-dir", dir, "--unlock-file", otherUnlock,
			"--listen", ":0",
		}, false},
		{"canceled saved", "", []string{
			"--identity-dir", dir, "--unlock-file", unlock,
		}, true},
		{"canceled before loading", "", []string{
			"--identity-dir", otherDir, "--unlock-file", unlock,
		}, true},
		{"canceled fresh", "", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			cmd := newHTTPDemoRoleCommand("root")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			cmd.SetContext(ctx)
			var output, stderr bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&stderr)
			try.To(cmd.ParseFlags(tc.args))

			// Exercise invalid RunE directly without legacy Cobra initializers.
			err := cmd.RunE(cmd, nil)
			assert.Error(err)
			if tc.canceled {
				assert.ErrorIs(err, context.Canceled)
			} else if tc.diagnostic != "" {
				assert.That(strings.Contains(err.Error(), tc.diagnostic), err)
			}
			assert.Empty(output.String())
			assert.Empty(stderr.String())
			assert.Equal(observed.created, 0)
			assert.SEmpty(try.To1(os.ReadDir(parent)))
			assert.SEmpty(try.To1(os.ReadDir(emptyDir)))
			if tc.name != "invalid listen before loading" {
				handle, err := selectHTTPDemoRoot(cmd)
				assert.Error(err)
				assert.INil(handle)
				assert.Equal(observed.created, 0)
			}
		})
	}
}

func TestHTTPDemoSavedReadinessAndShutdown(t *testing.T) {
	defer assert.PushTester(t)()

	dir, unlock, public := savedHTTPDemoIdentity(t)
	cmd := newHTTPDemoRoleCommand("root")
	cmd.SetContext(t.Context())
	try.To(cmd.ParseFlags([]string{
		"--identity-dir", dir, "--unlock-file", unlock,
	}))
	root := try.To1(selectHTTPDemoRoot(cmd))
	listener := &httpDemoListener{
		entered: make(chan struct{}), closed: make(chan struct{}),
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	var output bytes.Buffer
	done := make(chan struct{})
	var result error
	go func() {
		result = runHTTPDemoRoot(ctx, listener, root, &output)
		close(done)
	}()
	defer func() {
		cancel()
		waitHTTPDemoRoot(t, done)
	}()
	select {
	case <-listener.entered:
	case <-done:
		t.Fatalf("Root stopped before Serve: %v", result)
	case <-ctx.Done():
		t.Fatal("Root did not start Serve")
	}

	cancel()
	waitHTTPDemoRoot(t, done)
	assert.NoError(result)
	assert.Equal(listener.closes.Load(), int32(1))
	assert.Equal(output.String(), "root public key (hex): "+
		hex.EncodeToString(public)+"\nHTTP endpoint: http://127.0.0.1:1234\n"+
		"ready for Alice\nstop with Ctrl+C\n")
}

// Create through the accepted identity API and check files after all test work,
// including runner shutdown. Secret comparisons never print their operands.
func savedHTTPDemoIdentity(t *testing.T) (
	dir, unlockPath string, public key.Public,
) {
	t.Helper()
	defer assert.PushTester(t)()

	parent := t.TempDir()
	dir = filepath.Join(parent, "node")
	unlockPath = filepath.Join(parent, "unlock")
	try.To(os.Mkdir(dir, 0700))
	unlock := make([]byte, 32)
	defer clear(unlock)
	try.To1(rand.Read(unlock))
	try.To(os.WriteFile(unlockPath, unlock, 0600))
	recordPath := filepath.Join(dir, "identity.json")
	handle := try.To1(nodeidentity.Create(recordPath, unlock))
	public = try.To1(handle.CBORPublicKey())

	for _, path := range []string{recordPath, unlockPath} {
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
	for _, path := range []string{dir, parent} {
		before := try.To1(os.ReadDir(path))
		t.Cleanup(func() {
			defer assert.PushTester(t)()

			assert.DeepEqual(try.To1(os.ReadDir(path)), before)
		})
	}
	return dir, unlockPath, public
}
