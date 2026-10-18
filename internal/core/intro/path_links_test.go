package intro_test

import (
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/key"
)

func TestPathLinksWrongPredecessor(t *testing.T) {
	for _, name := range []string{"first descendant", "later descendant"} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()

			root, alice := key.New(), key.New()
			path := intro.New(key.InfoFromHandle(root)).Introduce(
				root, key.InfoFromHandle(alice),
			)
			parent := root
			if name == "later descendant" {
				path = path.Introduce(alice, key.InfoFromHandle(key.New()))
				parent = alice
			}
			parentPublic := try.To1(parent.CBORPublicKey())
			assert.NoError(path.Prove())

			encoded := path.Bytes()
			modified := intro.NewPathFromData(encoded)
			last := &modified[len(modified)-1]
			last.Body.Prev[0] ^= 1
			last.ParentSig = try.T1(parent.Sign(last.ExcludeBytes()))(
				"signing wrong predecessor",
			)

			assert.That(last.VerifySignature(parentPublic))
			err := modified.Prove()
			assert.Error(err, "correctly signed wrong predecessor must fail")
			assert.ErrorIs(err, intro.ErrBrokenPath)

			backupCalls := 0
			err = modified.ProveWithGetBKID(func(int) key.Public {
				backupCalls++
				return nil
			})
			assert.Equal(backupCalls, 0)
			assert.Error(err)
			assert.ErrorIs(err, intro.ErrBrokenPath)
			assert.DeepEqual(path.Bytes(), encoded)
		})
	}
}

func TestPathLinksRoundTrip(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	rootPath := intro.New(key.InfoFromHandle(root))
	alicePath := rootPath.Introduce(root, key.InfoFromHandle(alice))
	path := alicePath.Introduce(alice, key.InfoFromHandle(bob))
	encoded := path.Bytes()
	decoded := intro.NewPathFromData(encoded)

	assert.NoError(decoded.Prove())
	assert.DeepEqual(decoded.Bytes(), encoded)
	assert.DeepEqual(path.Bytes(), encoded)
}

func TestPathLinksSignedPrefixSplice(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	rootInfo, aliceInfo := key.InfoFromHandle(root), key.InfoFromHandle(alice)
	rootPath := intro.New(rootInfo)
	alicePath := rootPath.Introduce(root, aliceInfo, intro.WithPosition(1))
	otherPrefix := rootPath.Introduce(root, aliceInfo, intro.WithPosition(2))
	path := alicePath.Introduce(alice, key.InfoFromHandle(bob))
	assert.NoError(path.Prove())
	assert.NoError(otherPrefix.Prove())

	spliced := intro.NewPathFromData(path.Bytes())
	spliced[1] = otherPrefix[1]
	assert.DeepEqual(spliced[1].Public(), path[1].Public())
	assert.NotEqual(
		spliced[1].Body.Options.Position, path[1].Body.Options.Position,
	)
	assert.Equal(spliced[2].Body.Prev,
		key.HashTagged("v1/signed-hash", path[1].Bytes()))
	assert.NotEqual(spliced[2].Body.Prev,
		key.HashTagged("v1/signed-hash", spliced[1].Bytes()))

	assert.That(path[1].VerifySignature(rootInfo.Public))
	assert.That(spliced[1].VerifySignature(rootInfo.Public))
	assert.That(spliced[2].VerifySignature(aliceInfo.Public))
	err := spliced.Prove()
	assert.Error(err)
	assert.ErrorIs(err, intro.ErrBrokenPath)
}

func TestPathLinksEmpty(t *testing.T) {
	for _, tc := range []struct {
		name string
		path intro.Path
	}{
		{"nil", nil},
		{"empty", intro.Path{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			encoded := tc.path.Bytes()
			err := tc.path.Prove()
			assert.Error(err)
			assert.ErrorIs(err, intro.ErrWrongAnchor)

			backupCalls := 0
			err = tc.path.ProveWithGetBKID(func(int) key.Public {
				backupCalls++
				return nil
			})
			assert.Equal(backupCalls, 0)
			assert.Error(err)
			assert.ErrorIs(err, intro.ErrWrongAnchor)
			assert.DeepEqual(tc.path.Bytes(), encoded)
		})
	}
}
