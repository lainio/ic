package node

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/cmds"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/spf13/cobra"
)

func TestRegistrationAndArguments(t *testing.T) {
	defer assert.PushTester(t)()

	for _, name := range []string{"init", "info"} {
		registered, args := try.To2(
			cmds.RootCmd().Find([]string{"node", name}),
		)
		assert.SEmpty(args)
		assert.Equal(registered.Use, name)
		assert.Equal(registered.Parent().Name(), "node")
		assert.That(registered.RunE != nil)

		base := t.TempDir()
		dir, unlock := filepath.Join(
			base,
			"node",
		), filepath.Join(
			base,
			"unlock",
		)
		for _, args := range [][]string{
			nil,
			{"--dir", dir},
			{"--unlock-file", unlock},
			{"--dir", "", "--unlock-file", unlock},
			{"--dir", dir, "--unlock-file", " "},
			{"--dir", dir, "--unlock-file", unlock, "extra"},
			{"--dir", dir, "--unlock-file", unlock, "--force"},
		} {
			cmd := testCommand(name)
			var output bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&output)
			assert.Error(invoke(cmd, args))
			assert.Empty(output.String())
			assert.SEmpty(try.To1(os.ReadDir(base)))
		}
	}
}

func TestInitInfo(t *testing.T) {
	defer assert.PushTester(t)()

	dir, unlockPath, firstOutput := initialized(t)
	recordPath := filepath.Join(dir, "identity.json")
	before := try.To1(os.ReadFile(recordPath))
	unlock := try.To1(os.ReadFile(unlockPath))
	defer clear(unlock)
	assert.SLen(unlock, 32)
	for _, path := range []string{recordPath, unlockPath} {
		assert.Equal(try.To1(os.Stat(path)).Mode().Perm(), os.FileMode(0600))
	}
	assert.Equal(try.To1(os.Stat(dir)).Mode().Perm(), os.FileMode(0700))
	handle := try.To1(nodeidentity.Open(recordPath, unlock))
	public := try.To1(handle.CBORPublicKey())
	want := fmt.Sprintf("node public key (hex): %x\n", public)
	assert.Equal(firstOutput, want)

	for range 2 {
		cmd := testCommand("info")
		var output, stderr bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(&stderr)
		assert.NoError(invoke(cmd, nodeArgs(dir, unlockPath)))
		assert.Equal(output.String(), want)
		assert.Empty(stderr.String())
	}
	assert.That(bytes.Equal(try.To1(os.ReadFile(recordPath)), before))
	assert.That(bytes.Equal(try.To1(os.ReadFile(unlockPath)), unlock))

	var stored struct {
		Wrapped []byte `json:"wrapped_handle"`
	}
	try.To(json.Unmarshal(before, &stored))
	for _, secret := range [][]byte{unlock, stored.Wrapped} {
		for _, representation := range []string{
			string(secret), hex.EncodeToString(secret),
			base64.StdEncoding.EncodeToString(secret),
		} {
			assert.That(!strings.Contains(firstOutput, representation))
		}
	}

	cmd := testCommand("init")
	var output bytes.Buffer
	cmd.SetOut(&output)
	assert.ErrorIs(invoke(cmd, nodeArgs(dir, unlockPath)), os.ErrExist)
	assert.Empty(output.String())
	assert.That(bytes.Equal(try.To1(os.ReadFile(recordPath)), before))
	assert.That(bytes.Equal(try.To1(os.ReadFile(unlockPath)), unlock))
}

func TestInitPathConflicts(t *testing.T) {
	for _, name := range []string{
		"existing directory", "existing unlock", "inside", "same path",
		"missing node parent", "missing unlock parent", "file parent",
		"node symlink", "unlock symlink", "aliased inside",
	} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()

			base := t.TempDir()
			dir := filepath.Join(base, "node")
			unlock := filepath.Join(base, "unlock")
			switch name {
			case "existing directory":
				try.To(os.Mkdir(dir, 0700))
			case "existing unlock":
				try.To(os.WriteFile(unlock, []byte("existing"), 0600))
			case "inside":
				unlock = filepath.Join(dir, "unlock")
			case "same path":
				unlock = dir
			case "missing node parent":
				dir = filepath.Join(base, "missing", "node")
			case "missing unlock parent":
				unlock = filepath.Join(base, "missing", "unlock")
			case "file parent":
				try.To(os.WriteFile(filepath.Join(base, "file"), nil, 0600))
				unlock = filepath.Join(base, "file", "unlock")
			case "node symlink":
				try.To(os.Symlink(filepath.Join(base, "absent"), dir))
			case "unlock symlink":
				try.To(os.Symlink(filepath.Join(base, "absent"), unlock))
			case "aliased inside":
				try.To(os.Mkdir(dir, 0700))
				alias := filepath.Join(base, "alias")
				try.To(os.Symlink(dir, alias))
				unlock = filepath.Join(alias, "unlock")
			}
			entriesBefore := try.To1(os.ReadDir(base))
			cmd := testCommand("init")
			var output bytes.Buffer
			cmd.SetOut(&output)

			assert.Error(invoke(cmd, nodeArgs(dir, unlock)))
			assert.Empty(output.String())
			assert.DeepEqual(try.To1(os.ReadDir(base)), entriesBefore)
			_, err := os.Lstat(filepath.Join(dir, "identity.json"))
			assert.ErrorIs(err, os.ErrNotExist)
			if name == "existing unlock" {
				assert.Equal(
					string(try.To1(os.ReadFile(unlock))),
					"existing",
				)
			}
		})
	}
}

func TestInfoNeverInitializes(t *testing.T) {
	for _, missing := range []string{"directory", "unlock", "record"} {
		t.Run(missing, func(t *testing.T) {
			defer assert.PushTester(t)()

			base := t.TempDir()
			dir, unlock := filepath.Join(
				base,
				"node",
			), filepath.Join(
				base,
				"unlock",
			)
			if missing != "directory" {
				try.To(os.Mkdir(dir, 0700))
			}
			if missing == "record" {
				try.To(os.WriteFile(unlock, make([]byte, 32), 0600))
			}
			cmd := testCommand("info")
			var output bytes.Buffer
			cmd.SetOut(&output)
			assert.ErrorIs(
				invoke(cmd, nodeArgs(dir, unlock)),
				os.ErrNotExist,
			)
			assert.Empty(output.String())
			_, err := os.Lstat(filepath.Join(dir, "identity.json"))
			assert.ErrorIs(err, os.ErrNotExist)
			if missing == "directory" {
				assert.SEmpty(try.To1(os.ReadDir(base)))
			} else {
				assert.SEmpty(try.To1(os.ReadDir(dir)))
			}
		})
	}
}

func TestInfoRejectsUnsafeFiles(t *testing.T) {
	for _, name := range []string{
		"directory mode", "unlock mode", "record mode", "directory symlink",
		"unlock symlink", "record symlink", "unlock directory", "unlock fifo",
		"record directory", "record fifo", "short unlock", "long unlock",
		"wrong unlock", "corrupt record",
	} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()

			dir, unlock, _ := initialized(t)
			recordPath := filepath.Join(dir, "identity.json")
			before := try.To1(os.ReadFile(recordPath))
			switch name {
			case "directory mode":
				try.To(os.Chmod(dir, 0750))
			case "unlock mode":
				try.To(os.Chmod(unlock, 0644))
			case "record mode":
				try.To(os.Chmod(recordPath, 0640))
			case "directory symlink", "unlock symlink", "record symlink":
				path := map[string]string{
					"directory symlink": dir, "unlock symlink": unlock,
					"record symlink": recordPath,
				}[name]
				try.To(os.Rename(path, path+"-target"))
				try.To(os.Symlink(path+"-target", path))
			case "unlock directory",
				"unlock fifo",
				"record directory",
				"record fifo":
				path := unlock
				if strings.HasPrefix(name, "record") {
					path = recordPath
				}
				try.To(os.Remove(path))
				if strings.HasSuffix(name, "directory") {
					try.To(os.Mkdir(path, 0700))
				} else {
					try.To(syscall.Mkfifo(path, 0600))
				}
			case "short unlock":
				try.To(os.WriteFile(unlock, make([]byte, 31), 0600))
			case "long unlock":
				try.To(os.WriteFile(unlock, make([]byte, 4096), 0600))
			case "wrong unlock":
				data := try.To1(os.ReadFile(unlock))
				data[0] ^= 1
				try.To(os.WriteFile(unlock, data, 0600))
				clear(data)
			case "corrupt record":
				before = []byte(`{"secret-private-field":true}`)
				try.To(os.WriteFile(recordPath, before, 0600))
			}
			cmd := testCommand("info")
			var output, stderr bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&stderr)
			err := invoke(cmd, nodeArgs(dir, unlock))
			assert.Error(err)
			assert.Empty(output.String())
			assert.Empty(stderr.String())
			assert.That(
				!strings.Contains(err.Error(), "secret-private-field"),
			)
			if name != "record directory" && name != "record fifo" {
				assert.That(
					bytes.Equal(try.To1(os.ReadFile(recordPath)), before),
				)
			}
		})
	}
}

func TestOutputFailurePreservesIdentity(t *testing.T) {
	defer assert.PushTester(t)()

	base := t.TempDir()
	dir, unlock := filepath.Join(base, "node"), filepath.Join(base, "unlock")
	want := errors.New("output unavailable")
	for _, name := range []string{"init", "info"} {
		cmd := testCommand(name)
		cmd.SetOut(failingWriter{want})
		assert.ErrorIs(invoke(cmd, nodeArgs(dir, unlock)), want)
		assert.SNotEmpty(
			try.To1(os.ReadFile(filepath.Join(dir, "identity.json"))),
		)
		assert.SLen(try.To1(os.ReadFile(unlock)), 32)
	}
	cmd := testCommand("info")
	var output bytes.Buffer
	cmd.SetOut(&output)
	assert.NoError(invoke(cmd, nodeArgs(dir, unlock)))
	assert.That(strings.HasPrefix(output.String(), "node public key (hex): "))
}

func initialized(t *testing.T) (dir, unlock, output string) {
	t.Helper()
	defer assert.PushTester(t)()

	base := t.TempDir()
	dir, unlock = filepath.Join(base, "node"), filepath.Join(base, "unlock")
	cmd := testCommand("init")
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	assert.NoError(invoke(cmd, nodeArgs(dir, unlock)))
	assert.Empty(stderr.String())
	return dir, unlock, stdout.String()
}

func testCommand(name string) *cobra.Command {
	cmd, _ := try.To2(newNodeCommand().Find([]string{name}))
	return cmd
}

func nodeArgs(dir, unlock string) []string {
	return []string{"--dir", dir, "--unlock-file", unlock}
}

// Exercise fresh callbacks without process-global legacy Cobra initializers.
func invoke(cmd *cobra.Command, args []string) (err error) {
	defer err2.Handle(&err)

	try.To(cmd.ParseFlags(args))
	try.To(cmd.ValidateArgs(cmd.Flags().Args()))
	try.To(cmd.ValidateRequiredFlags())
	try.To(cmd.RunE(cmd, cmd.Flags().Args()))
	return nil
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }
