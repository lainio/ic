package pw_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
)

const bobDenyCrashMode = "IC_TEST_BOB_DENY_CRASH_9A302DBC4F6E4A5F8CDB70E67A724671"

// Only paths and independently pinned public identities cross the process
// boundary. The child opens the existing secret source itself.
type bobDenyCrashConfig struct {
	Token, Dir, StorageKey string
	Root, Local, Peer      key.Public
}

func TestBobDenySurvivesAbruptProcessDeath(t *testing.T) {
	defer assert.PushTester(t)()
	if token := os.Getenv(bobDenyCrashMode); token != "" {
		bobDenyCrashChild(t, token)
		return
	}

	f := newRedemption(t, true)
	assert.Equal(f.invoke().Code, 200)
	// Drain every HTTP handler before inspecting records or releasing Bob's
	// Store. The fixture's later Close cleanup is idempotent.
	f.server.Close()
	assert.NoError(f.failure)
	assert.Equal(len(f.requests), 1)
	assert.Equal(len(f.responses), 1)
	alice := exchangeHeldState(t, f.a.store.Vault())
	bob := exchangeHeldState(t, f.b.store.Vault())
	for _, records := range []map[string]map[string][]byte{alice, bob} {
		assert.SNotEmpty(records["root"]["local-pw-accepted-v1"])
		assert.SNotEmpty(records["root"]["local-pw-held-v1"])
		assert.SNil(records["root"][deniedPolicyKey])
	}
	invitation, found := try.To2(pw.ReadInvitation(f.b.store.Vault(),
		f.root, f.b.public))
	assert.That(found)
	assert.Equal(invitation.State, pw.InvitationConsumed)
	var accepted observedUseReceipt // Same v1 request/response array.
	try.To(wire.UnmarshalCanonical(&accepted,
		bob["root"]["local-pw-accepted-v1"]))
	assert.Equal(accepted.Version, 1)
	assert.DeepEqual(accepted.Request, f.requests[0])
	assert.DeepEqual(accepted.Request, alice["root"]["local-pw-attempt-v1"])
	assert.DeepEqual(bob["root"]["local-pw-accepted-v1"],
		alice["root"]["local-pw-accepted-v1"])
	var sent struct {
		Version    int
		Acceptance []byte
	}
	try.To(json.Unmarshal(f.responses[0], &sent))
	assert.Equal(sent.Version, 1)
	assert.DeepEqual(accepted.Response, sent.Acceptance)
	endpoint := f.server.URL + "/peer/introduction"
	assert.DeepEqual(try.To1(pw.BobReply(f.b.store.Vault(), f.root,
		f.b.public, f.b.signer, endpoint, accepted.Request)), accepted.Response)

	files := f.snapshot(t)
	try.To(f.b.store.Close()) // Release both file locks before the child opens.
	killBobAfterDenyCommit(t, bobDenyCrashConfig{
		Token: rand.Text(), Dir: f.b.dir, StorageKey: f.b.storageKey,
		Root: f.root, Local: f.b.public, Peer: f.a.public,
	})
	// Assign only after a successful open: fixture cleanup must still have
	// its valid, already-closed Store if opening fails.
	reopened := try.To1(nodevault.OpenForNode(t.Context(), f.b.dir,
		f.b.storageKey, f.root, f.b.public))
	f.b.store = reopened
	assert.That(try.To1(policy.IsDenied(reopened.Vault(), f.root,
		f.b.public, f.a.public)))
	after := exchangeHeldState(t, reopened.Vault())
	denied := after["root"][deniedPolicyKey]
	assert.SNotEmpty(denied)
	delete(after["root"], deniedPolicyKey)
	// Includes the exact consumed invitation, accepted signed request/result,
	// retained holding, introductions, devices, ads and unrelated records.
	assert.DeepEqual(after, bob)
	bob["root"][deniedPolicyKey] = denied
	assert.DeepEqual(exchangeHeldState(t, f.a.store.Vault()), alice)
	afterFiles := f.snapshot(t)
	// Reopening reserves usage capacity; compare logical Bob records above.
	// Every Alice file and Bob's saved identity must remain byte-identical.
	for _, name := range []string{"vault.db", "usage.db"} {
		delete(files, filepath.Join(f.b.dir, "state", name))
		delete(afterFiles, filepath.Join(f.b.dir, "state", name))
	}
	assert.DeepEqual(afterFiles, files)

	var signed pw.SignedAccepted
	try.To(wire.UnmarshalCanonical(&signed, accepted.Response))
	digest := key.HashTagged(pw.AcceptedPurpose,
		try.To1(wire.Marshal(signed.Payload)))
	signs := len(f.b.signer.signed())
	beforeRetry := f.snapshot(t)
	response, err := pw.BobReply(reopened.Vault(), f.root, f.b.public,
		f.b.signer, endpoint, accepted.Request)
	assert.Equal(err, pw.ErrEstablishment)
	assert.SNil(response)
	// BobReply makes one discarded usability probe, never another acceptance.
	messages := f.b.signer.signed()[signs:]
	assert.Equal(len(messages), 1)
	assert.ThatNot(bytes.Equal(messages[0], digest[:]))
	assert.DeepEqual(f.snapshot(t), beforeRetry) // No durable write or seal.
	assert.DeepEqual(exchangeHeldState(t, reopened.Vault()), bob)
	assert.DeepEqual(exchangeHeldState(t, f.a.store.Vault()), alice)
}

func killBobAfterDenyCommit(t *testing.T, config bobDenyCrashConfig) {
	t.Helper()
	defer assert.PushTester(t)()
	executable := try.To1(os.Executable())
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	reader, writer := try.To2(os.Pipe())
	defer func() {
		_ = reader.Close()
		_ = writer.Close() // May already be closed after Start.
	}()
	child := exec.CommandContext(ctx, executable,
		"-test.run=^TestBobDenySurvivesAbruptProcessDeath$",
		"-test.count=1", "-test.timeout=30s")
	child.WaitDelay = time.Second
	child.Env = append(os.Environ(), bobDenyCrashMode+"="+config.Token)
	child.Stdin = bytes.NewReader(try.To1(json.Marshal(config)))
	child.ExtraFiles = []*os.File{writer} // Dedicated readiness pipe, fd 3.
	// Leave stdout/stderr discarded: only the narrow marker and exit state
	// cross back, never provider diagnostics or fixture credentials.
	try.To(child.Start())
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = child.Wait()
		close(done)
	}()
	defer func() {
		_ = child.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Deny child was not reaped within cleanup deadline")
		}
	}()
	try.To(writer.Close()) // Only the child's copy may keep the pipe open.

	marker := "bob-deny-committed:" + config.Token + "\n"
	type readiness struct {
		message []byte
		err     error
	}
	ready := make(chan readiness, 1)
	go func() {
		message, err := io.ReadAll(io.LimitReader(reader, int64(len(marker)+1)))
		ready <- readiness{message, err}
	}()
	select {
	case result := <-ready:
		assert.NoError(result.err)
		assert.Equal(string(result.message), marker)
	case <-done:
		t.Fatalf("Deny child exited before readiness: %v", waitErr)
	case <-ctx.Done():
		t.Fatal("timed out waiting for committed Deny")
	}
	select {
	case <-done:
		t.Fatalf("Deny child exited before SIGKILL: %v", waitErr)
	default:
	}
	assert.NoError(ctx.Err())
	try.To(child.Process.Signal(syscall.SIGKILL))
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("timed out reaping killed Deny child")
	}
	assert.NoError(ctx.Err()) // A deadline kill must never count as success.
	var exit *exec.ExitError
	assert.That(errors.As(waitErr, &exit))
	status, ok := exit.Sys().(syscall.WaitStatus)
	assert.That(ok)
	assert.That(status.Signaled())
	assert.Equal(status.Signal(), syscall.SIGKILL)
}

func bobDenyCrashChild(t *testing.T, token string) {
	t.Helper()
	defer assert.PushTester(t)()
	var config bobDenyCrashConfig
	try.To(json.NewDecoder(io.LimitReader(os.Stdin, 16<<10)).Decode(&config))
	assert.That(config.Token == token && len(token) >= 26)
	ready := os.NewFile(3, "bob-deny-readiness")
	assert.NotNil(ready)
	store := try.To1(nodevault.OpenForNode(t.Context(), config.Dir,
		config.StorageKey, config.Root, config.Local))
	// True means this one local update committed. No Close, deferred Close,
	// owner route or other policy operation runs in this process.
	assert.That(try.To1(policy.DenyLocal(store.Vault(), config.Root,
		config.Local, config.Peer)))
	try.To1(io.WriteString(ready, "bob-deny-committed:"+token+"\n"))
	try.To(ready.Close())
	<-t.Context().Done() // Park with the Vault open until the parent's SIGKILL.
	runtime.KeepAlive(store)
	t.Fatal("Deny child resumed without SIGKILL")
}
