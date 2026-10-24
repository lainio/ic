package nodevault

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/onboarding"
)

func TestLocalNodeStore(t *testing.T) {
	defer assert.PushTester(t)()

	f := try.To1(prepareFixture(t.TempDir()))
	defer clear(f.secret)
	dir := filepath.Join(f.dir, "alice")
	keyFile := filepath.Join(f.dir, "local-key")
	b := f.binding
	s := try.To1(CreateForNode(t.Context(), dir, keyFile, b.Root, b.Child))
	defer func() { try.Out(s.Close()).Logf() }()
	secret := try.To1(os.ReadFile(keyFile))
	defer clear(secret)
	unlock := try.To1(os.ReadFile(filepath.Join(f.dir, "unlock")))
	defer clear(unlock)
	assert.SLen(secret, 32)
	assert.That(!bytes.Equal(secret, unlock))
	assert.That(!bytes.Equal(secret, f.secret))
	assert.That(bytes.Equal(s.provider.secret, secret))
	assert.DeepEqual(s.provider.binding, b)
	assert.Equal(try.To1(os.Stat(keyFile)).Mode().Perm(), os.FileMode(0600))
	state := filepath.Join(dir, "state")
	assert.Equal(try.To1(os.Stat(state)).Mode().Perm(), os.FileMode(0700))
	for _, name := range []string{"vault.db", "usage.db"} {
		assert.Equal(
			try.To1(os.Stat(filepath.Join(state, name))).Mode().Perm(),
			os.FileMode(0600),
		)
	}
	try.To(s.Close())

	reopened := try.To1(
		OpenForNode(t.Context(), dir, keyFile, b.Root, b.Child),
	)
	defer func() { try.Out(reopened.Close()).Logf() }()
	_, found := try.To2(
		onboarding.ReadStoredChoice(reopened.Vault(), b.Root, b.Child),
	)
	assert.ThatNot(found)
	try.To(reopened.Close())
	before := try.To1(os.ReadFile(filepath.Join(state, "usage.db")))

	rejected, err := CreateForNode(t.Context(), dir, keyFile, b.Root, b.Child)
	assert.ErrorIs(err, os.ErrExist)
	assert.Nil(rejected)
	assert.That(!strings.Contains(err.Error(), hex.EncodeToString(secret)))
	assert.That(bytes.Equal(try.To1(os.ReadFile(keyFile)), secret))
	assert.DeepEqual(
		try.To1(os.ReadFile(filepath.Join(state, "usage.db"))),
		before,
	)
	// Existing state must be checked before creating even a new secret file.
	otherKey := filepath.Join(f.dir, "other-key")
	rejected, err = CreateForNode(t.Context(), dir, otherKey, b.Root, b.Child)
	assert.ErrorIs(err, os.ErrExist)
	assert.Nil(rejected)
	_, err = os.Lstat(otherKey)
	assert.ErrorIs(err, os.ErrNotExist)
}

func TestLocalNodePreparationChecks(t *testing.T) {
	for _, scenario := range []string{
		"inside", "aliased inside", "existing key", "key symlink",
		"state symlink", "private node", "missing parent", "empty binding",
	} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()

			parent := t.TempDir()
			dir, keyFile := filepath.Join(
				parent,
				"alice",
			), filepath.Join(
				parent,
				"key",
			)
			try.To(os.Mkdir(dir, 0700))
			root, child := []byte("expected root"), []byte("expected child")
			switch scenario {
			case "inside":
				keyFile = filepath.Join(dir, "key")
			case "aliased inside":
				alias := filepath.Join(parent, "alias")
				try.To(os.Symlink(dir, alias))
				keyFile = filepath.Join(alias, "key")
			case "existing key":
				try.To(os.WriteFile(keyFile, []byte("existing"), 0600))
			case "key symlink":
				try.To(os.Symlink(filepath.Join(parent, "absent"), keyFile))
			case "state symlink":
				try.To(
					os.Symlink(
						filepath.Join(parent, "absent"),
						filepath.Join(dir, "state"),
					),
				)
			case "private node":
				try.To(os.Chmod(dir, 0750))
			case "missing parent":
				keyFile = filepath.Join(parent, "missing", "key")
			case "empty binding":
				root = nil
			}
			before := try.To1(os.ReadDir(parent))
			nodeBefore := try.To1(os.ReadDir(dir))

			s, err := CreateForNode(t.Context(), dir, keyFile, root, child)
			assert.Error(err)
			assert.Nil(s)
			assert.DeepEqual(try.To1(os.ReadDir(parent)), before)
			assert.DeepEqual(try.To1(os.ReadDir(dir)), nodeBefore)
		})
	}
}

func TestLocalNodeOpenRequiresSecret(t *testing.T) {
	for _, scenario := range []string{"missing", "wrong", "short", "long", "public", "symlink"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()

			parent := t.TempDir()
			dir, keyFile := filepath.Join(
				parent,
				"alice",
			), filepath.Join(
				parent,
				"key",
			)
			try.To(os.Mkdir(dir, 0700))
			root, child := []byte("expected root"), []byte("expected child")
			s := try.To1(
				CreateForNode(t.Context(), dir, keyFile, root, child),
			)
			try.To(s.Close())
			secret := try.To1(os.ReadFile(keyFile))
			defer clear(secret)
			before := try.To1(
				databaseRecords(filepath.Join(dir, "state", "vault.db")),
			)
			usage := try.To1(
				os.ReadFile(filepath.Join(dir, "state", "usage.db")),
			)
			badKey := filepath.Join(parent, "bad-key")
			switch scenario {
			case "missing":
			case "wrong":
				try.To(
					os.WriteFile(
						badKey,
						bytes.Repeat([]byte{42}, 32),
						0600,
					),
				)
			case "short":
				try.To(os.WriteFile(badKey, secret[:31], 0600))
			case "long":
				try.To(
					os.WriteFile(
						badKey,
						bytes.Repeat([]byte{42}, 33),
						0600,
					),
				)
			case "public":
				try.To(os.WriteFile(badKey, secret, 0644))
			case "symlink":
				try.To(os.Symlink(keyFile, badKey))
			}

			rejected, err := OpenForNode(
				t.Context(),
				dir,
				badKey,
				root,
				child,
			)
			assert.Error(err)
			assert.Nil(rejected)
			assert.That(
				!strings.Contains(err.Error(), hex.EncodeToString(secret)),
			)
			assert.DeepEqual(
				try.To1(
					databaseRecords(
						filepath.Join(dir, "state", "vault.db"),
					),
				),
				before,
			)
			assert.DeepEqual(
				try.To1(
					os.ReadFile(filepath.Join(dir, "state", "usage.db")),
				),
				usage,
			)
			assert.That(bytes.Equal(try.To1(os.ReadFile(keyFile)), secret))
			if scenario == "missing" {
				_, err = os.Lstat(badKey)
				assert.ErrorIs(err, os.ErrNotExist)
			}
			reopened := try.To1(
				OpenForNode(t.Context(), dir, keyFile, root, child),
			)
			try.To(reopened.Close())
		})
	}
}
