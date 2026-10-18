package intro_test

import (
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/key"
)

func TestPathCyclesReturnToRoot(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	rootInfo := key.InfoFromHandle(root)
	expectedRoot := key.Public(try.T1(root.CBORPublicKey())(
		"reading the independently selected root public key",
	))
	expectedBefore := append(key.Public(nil), expectedRoot...)
	aliceInfo := key.InfoFromHandle(alice)

	alicePath := intro.New(rootInfo).Introduce(root, aliceInfo)
	path := alicePath.Introduce(alice, rootInfo)
	encoded := path.Bytes()

	assert.That(path.FirstEdge().Public().Equal(expectedRoot))
	assertPathCyclesEvidence(t, path)
	assert.That(path.LastEdge().Public().Equal(path.FirstEdge().Public()))
	assert.ThatNot(path.LastEdge().Public().Equal(aliceInfo.Public))

	for _, tc := range []struct {
		name string
		path intro.Path
	}{
		{"constructed", path},
		{"decoded", intro.NewPathFromData(encoded)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			err := tc.path.ProveFromRoot(expectedRoot)
			assert.Error(err,
				"a correctly signed return to the expected root must fail")
			assert.ErrorIs(err, intro.ErrCycleOrDuplicate)
			assert.ErrorIsNot(err, intro.ErrBrokenPath)

			err = tc.path.Prove()
			assert.Error(err)
			assert.ErrorIs(err, intro.ErrCycleOrDuplicate)
			assert.ErrorIsNot(err, intro.ErrBrokenPath)

			backupCalls := 0
			err = tc.path.ProveWithGetBKID(func(int) key.Public {
				backupCalls++
				return nil
			})
			assert.Equal(backupCalls, 0)
			assert.Error(err)
			assert.ErrorIs(err, intro.ErrCycleOrDuplicate)
			assert.ErrorIsNot(err, intro.ErrBrokenPath)
			assert.DeepEqual(tc.path.Bytes(), encoded)
		})
	}
	assert.DeepEqual(path.Bytes(), encoded)
	assert.DeepEqual(expectedRoot, expectedBefore)
}

func TestPathCyclesRootWithDifferentChildID(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	rootInfo := key.InfoFromHandle(root)
	expectedRoot := rootInfo.Public
	repeatedRoot := rootInfo
	repeatedRoot.ID = append(key.ID(nil), rootInfo.ID...)
	repeatedRoot.ID[0] ^= 1

	alicePath := intro.New(rootInfo).Introduce(root, key.InfoFromHandle(alice))
	path := alicePath.Introduce(alice, repeatedRoot)
	encoded := path.Bytes()

	assert.DeepEqual(path.LastEdge().Public(), expectedRoot)
	assert.ThatNot(path.LastEdge().ID().Equal(path.FirstEdge().ID()))
	assertPathCyclesEvidence(t, path)

	err := path.ProveFromRoot(expectedRoot)
	assert.Error(err)
	assert.ErrorIs(err, intro.ErrCycleOrDuplicate)
	assert.ErrorIsNot(err, intro.ErrBrokenPath)
	assert.DeepEqual(path.Bytes(), encoded)
}

func TestPathCyclesBoundaries(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := key.InfoFromHandle(root).Public
	for _, tc := range []struct {
		name string
		keys []key.Handle
		want error
	}{
		{"R only", []key.Handle{root}, nil},
		{"R -> Alice -> Bob", []key.Handle{root, alice, bob}, nil},
		{"R -> R", []key.Handle{root, root}, intro.ErrBrokenPath},
		{
			"R -> Alice -> Alice", []key.Handle{root, alice, alice},
			intro.ErrBrokenPath,
		},
		{
			"R -> Alice -> Bob -> Alice", []key.Handle{root, alice, bob, alice},
			intro.ErrCycleOrDuplicate,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			path := intro.New(key.InfoFromHandle(tc.keys[0]))
			for i, child := range tc.keys[1:] {
				path = path.Introduce(tc.keys[i], key.InfoFromHandle(child))
			}
			encoded := path.Bytes()
			assertPathCyclesEvidence(t, path)

			err := path.ProveFromRoot(expectedRoot)
			if tc.want == nil {
				assert.NoError(err)
			} else {
				assert.Error(err)
				assert.ErrorIs(err, tc.want)
				if tc.want == intro.ErrBrokenPath {
					assert.ErrorIsNot(err, intro.ErrCycleOrDuplicate)
				} else {
					assert.ErrorIsNot(err, intro.ErrBrokenPath)
				}
			}
			assert.DeepEqual(path.Bytes(), encoded)
		})
	}
}

func assertPathCyclesEvidence(t *testing.T, path intro.Path) {
	t.Helper()

	for i, edge := range path[1:] {
		assert.Equal(edge.Body.Options.BackupKeyIndex, 0)
		assert.That(edge.VerifySignature(path[i].Public()))
		assert.Equal(edge.Body.Prev,
			key.HashTagged("v1/signed-hash", path[i].Bytes()))
	}
}
