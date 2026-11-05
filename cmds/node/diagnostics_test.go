package node

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/onboarding"
)

// Launch the actual CLI: this checks Cobra/pflag + standard glog flags and
// logtostderr together, without changing this test process's global flags.
func TestServePWDiagnosticsCLI(t *testing.T) {
	defer assert.PushTester(t)()
	binary := filepath.Join(t.TempDir(), "tdc")
	build := exec.CommandContext(t.Context(), "go", "build", "-mod=readonly",
		"-o", binary, "../../cmd/tdc")
	assert.NoError(build.Run())
	f := prepareServeFixture(t)
	choice := saveServeChoice(t, f, "completed")
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	args := append([]string{"--v=1", "node", "serve"}, f.args()...)
	cmd := exec.CommandContext(ctx, binary, args...)
	stdout := try.To1(cmd.StdoutPipe())
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	try.To(cmd.Start())
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	type startup struct {
		lines []string
		err   error
	}
	started := make(chan startup, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
			if scanner.Text() == "stop with Ctrl+C" {
				break
			}
		}
		started <- startup{lines, scanner.Err()}
	}()
	var lines []string
	select {
	case result := <-started:
		assert.NoError(result.err)
		lines = result.lines
	case <-ctx.Done():
		t.Fatal("CLI did not start within deadline")
	}
	assert.Equal(len(lines), 4)
	assert.Equal(lines[0], "node public key (hex): "+hex.EncodeToString(f.child))
	statusURL, ok := strings.CutPrefix(lines[1], "owner status URL: ")
	assert.That(ok)
	headerFile, ok := strings.CutPrefix(lines[2], "authorization header file: ")
	assert.That(ok)
	auth := strings.TrimSpace(strings.TrimPrefix(
		string(try.To1(os.ReadFile(headerFile))), "Authorization: "))
	base := strings.TrimSuffix(statusURL, "/owner/status")
	post := func(path string, body []byte, status int) {
		t.Helper()
		result := postPeerProofHTTP(ctx, base+path, auth, body, false)
		assert.NoError(result.err)
		assert.Equal(result.status, status)
	}
	post(ownerBootstrapPath, []byte("{}"), 409)
	post("/owner/introductions", try.To1(onboarding.EncodeIntroduction(choice)), 200)
	post("/owner/introductions/verify", []byte("{}"), 200)
	post(ownerBootstrapPath, []byte("{}"), 200)
	post(ownerBootstrapPath, []byte("{}"), 409)
	try.To(cmd.Process.Signal(os.Interrupt))
	err := cmd.Wait()
	waited = true
	assert.NoError(err)
	logs := diagnostics.String()
	for _, event := range []string{
		"stage=authorization result=refused reason=own_introduction_not_known",
		"stage=authorization result=committed",
		"stage=signer result=usable",
		"stage=authorization result=refused reason=already_authorized",
	} {
		assert.That(strings.Contains(logs,
			"intro_pw op=device_bootstrap side=local "+event), event)
	}
	for _, sensitive := range []string{auth, headerFile, f.unlock, f.storageKey,
		hex.EncodeToString(f.child), hex.EncodeToString(f.root)} {
		assert.ThatNot(strings.Contains(logs, sensitive),
			"sensitive fixture material in diagnostic output")
	}
}
