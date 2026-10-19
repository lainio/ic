package intro_test

import (
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/key"
)

// Receipt and individual proof do not decide application-level acceptance.
func TestInboxConflictingParents(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	aliceInfo, bobInfo := key.InfoFromHandle(alice), key.InfoFromHandle(bob)
	assert.ThatNot(expectedRoot.Equal(aliceInfo.Public))
	assert.ThatNot(expectedRoot.Equal(bobInfo.Public))
	assert.ThatNot(aliceInfo.Public.Equal(bobInfo.Public))

	rootPath := intro.New(key.InfoFromHandle(root))
	direct := rootPath.Introduce(root, aliceInfo)
	bobPath := rootPath.Introduce(root, bobInfo)
	indirect := bobPath.Introduce(bob, aliceInfo)

	assert.SLen(direct, 2)
	assert.SLen(indirect, 3)
	assert.DeepEqual(direct[0].Public(), expectedRoot)
	assert.DeepEqual(indirect[0].Public(), expectedRoot)
	assert.NoError(direct.ProveFromRoot(expectedRoot))
	assert.NoError(indirect.ProveFromRoot(expectedRoot))

	directChild := direct[len(direct)-1].Body.Child
	indirectChild := indirect[len(indirect)-1].Body.Child
	assert.DeepEqual(directChild, aliceInfo)
	assert.DeepEqual(indirectChild, aliceInfo)
	directParent := direct[len(direct)-2].Public()
	indirectParent := indirect[len(indirect)-2].Public()
	assert.DeepEqual(directParent, expectedRoot)
	assert.DeepEqual(indirectParent, bobInfo.Public)
	assert.ThatNot(directParent.Equal(indirectParent))

	for _, tc := range []struct {
		name string
		want []intro.Path
	}{
		{"direct first", []intro.Path{direct, indirect}},
		{"indirect first", []intro.Path{indirect, direct}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			encoded := [][]byte{tc.want[0].Bytes(), tc.want[1].Bytes()}
			var inbox intro.Inbox
			for _, data := range encoded {
				assert.NoError(inbox.ReceivePath(data))
			}
			received := inbox.Paths()
			assert.DeepEqual(received, tc.want)

			for _, path := range received {
				assert.NoError(path.ProveFromRoot(expectedRoot))
			}
			assert.DeepEqual(received, tc.want)
			assert.DeepEqual(inbox.Paths(), tc.want)

			for _, data := range encoded {
				assert.NoError(inbox.ReceivePath(data))
			}
			assert.DeepEqual(inbox.Paths(), tc.want)
		})
	}
}
