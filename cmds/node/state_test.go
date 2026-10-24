package node

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/cmds"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/lainio/ic/internal/onboarding"
)

func TestInitState(t *testing.T) {
	defer assert.PushTester(t)()

	dir, unlockPath, publicOutput := initialized(t)
	keyFile := filepath.Join(filepath.Dir(dir), "storage-key")
	identity := try.To1(os.ReadFile(filepath.Join(dir, "identity.json")))
	unlock := try.To1(os.ReadFile(unlockPath))
	defer clear(unlock)
	args := append(
		nodeArgs(dir, unlockPath),
		"--storage-key-file",
		keyFile,
		"--root",
		"0123",
	)
	cmd := testCommand("init-state")
	cmd.SetContext(t.Context())
	var output bytes.Buffer
	cmd.SetOut(&output)
	try.To(invoke(cmd, args))
	assert.Equal(
		output.String(),
		publicOutput+"local state initialized: true\n",
	)
	secret := try.To1(os.ReadFile(keyFile))
	defer clear(secret)
	assert.SLen(secret, 32)
	assert.That(!bytes.Equal(secret, unlock))
	assert.Equal(try.To1(os.Stat(keyFile)).Mode().Perm(), os.FileMode(0600))
	handle := try.To1(nodeidentity.OpenDirectory(dir, unlockPath))
	child := try.To1(handle.CBORPublicKey())
	s := try.To1(
		nodevault.OpenForNode(
			t.Context(),
			dir,
			keyFile,
			[]byte{1, 35},
			child,
		),
	)
	defer func() { try.Out(s.Close()).Logf() }()
	_, found := try.To2(
		onboarding.ReadStoredChoice(s.Vault(), []byte{1, 35}, child),
	)
	assert.ThatNot(found)
	try.To(s.Close())

	output.Reset()
	err := invoke(cmd, args)
	assert.ErrorIs(err, os.ErrExist)
	assert.Empty(output.String())
	assert.That(
		bytes.Equal(
			try.To1(os.ReadFile(filepath.Join(dir, "identity.json"))),
			identity,
		),
	)
	assert.That(bytes.Equal(try.To1(os.ReadFile(unlockPath)), unlock))
	assert.That(bytes.Equal(try.To1(os.ReadFile(keyFile)), secret))
	for _, private := range [][]byte{unlock, secret, handle.ID()} {
		for _, representation := range []string{
			string(private), hex.EncodeToString(private), base64.StdEncoding.EncodeToString(private),
		} {
			assert.That(
				!strings.Contains(
					publicOutput+output.String()+err.Error(),
					representation,
				),
			)
		}
	}
}

func TestInitStateArguments(t *testing.T) {
	defer assert.PushTester(t)()

	registered, args := try.To2(
		cmds.RootCmd().Find([]string{"node", "init-state"}),
	)
	assert.SEmpty(args)
	assert.Equal(registered.Name(), "init-state")
	assert.Nil(registered.Flags().Lookup("force"))
	parent := t.TempDir()
	values := []string{
		filepath.Join(parent, "alice"),
		filepath.Join(parent, "unlock"),
		filepath.Join(parent, "key"),
		"01",
	}
	names := []string{"dir", "unlock-file", "storage-key-file", "root"}
	for i, name := range names {
		for _, empty := range []bool{false, true} {
			t.Run(
				name+"/"+map[bool]string{false: "missing", true: "empty"}[empty],
				func(t *testing.T) {
					defer assert.PushTester(t)()

					var args []string
					for j, flag := range names {
						if i != j {
							args = append(args, "--"+flag, values[j])
						} else if empty {
							args = append(args, "--"+flag, " ")
						}
					}
					cmd := testCommand("init-state")
					cmd.SetContext(t.Context())
					var output bytes.Buffer
					cmd.SetOut(&output)
					assert.Error(invoke(cmd, args))
					assert.Empty(output.String())
					assert.SEmpty(try.To1(os.ReadDir(parent)))
				},
			)
		}
	}
	assert.Error(registered.ValidateArgs([]string{"extra"}))
}

func TestInitStateRefusesBeforeCreation(t *testing.T) {
	for _, scenario := range []string{
		"missing identity", "malformed root", "oversized root", "inside key",
		"same unlock", "aliased unlock", "unsafe identity", "existing key",
	} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()

			dir, unlock, _ := initialized(t)
			keyFile := filepath.Join(filepath.Dir(dir), "storage-key")
			root := "01"
			switch scenario {
			case "missing identity":
				try.To(os.Remove(filepath.Join(dir, "identity.json")))
			case "malformed root":
				root = "not-hex"
			case "oversized root":
				root = strings.Repeat("01", 16*1024+1)
			case "inside key":
				keyFile = filepath.Join(dir, "storage-key")
			case "same unlock":
				keyFile = unlock
			case "aliased unlock":
				alias := filepath.Join(t.TempDir(), "parent")
				try.To(os.Symlink(filepath.Dir(unlock), alias))
				keyFile = filepath.Join(alias, filepath.Base(unlock))
			case "unsafe identity":
				try.To(os.Chmod(dir, 0750))
			case "existing key":
				try.To(
					os.WriteFile(
						keyFile,
						[]byte("private-existing-key"),
						0600,
					),
				)
			}
			before := try.To1(os.ReadDir(filepath.Dir(dir)))
			unlockBefore := try.To1(os.ReadFile(unlock))
			defer clear(unlockBefore)
			cmd := testCommand("init-state")
			cmd.SetContext(t.Context())
			var output bytes.Buffer
			cmd.SetOut(&output)
			err := invoke(
				cmd,
				append(
					nodeArgs(dir, unlock),
					"--storage-key-file",
					keyFile,
					"--root",
					root,
				),
			)
			assert.Error(err)
			assert.Empty(output.String())
			assert.That(
				!strings.Contains(err.Error(), "private-existing-key"),
			)
			assert.That(
				bytes.Equal(try.To1(os.ReadFile(unlock)), unlockBefore),
			)
			assert.DeepEqual(try.To1(os.ReadDir(filepath.Dir(dir))), before)
			_, err = os.Lstat(filepath.Join(dir, "state"))
			assert.ErrorIs(err, os.ErrNotExist)
		})
	}
}

func TestInitStateOutputFailureRetainsState(t *testing.T) {
	defer assert.PushTester(t)()

	dir, unlock, _ := initialized(t)
	keyFile := filepath.Join(filepath.Dir(dir), "storage-key")
	cmd := testCommand("init-state")
	cmd.SetContext(t.Context())
	want := errors.New("output unavailable")
	cmd.SetOut(failingWriter{want})
	assert.ErrorIs(
		invoke(
			cmd,
			append(
				nodeArgs(dir, unlock),
				"--storage-key-file",
				keyFile,
				"--root",
				"01",
			),
		),
		want,
	)
	handle := try.To1(nodeidentity.OpenDirectory(dir, unlock))
	s := try.To1(
		nodevault.OpenForNode(
			t.Context(),
			dir,
			keyFile,
			[]byte{1},
			try.To1(handle.CBORPublicKey()),
		),
	)
	try.To(s.Close())
}
