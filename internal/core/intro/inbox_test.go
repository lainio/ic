package intro_test

import (
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
)

func TestInboxReceivePath(t *testing.T) {
	defer assert.PushTester(t)()

	var inbox intro.Inbox
	assert.SLen(inbox.Paths(), 0)
	root, alice := key.New(), key.New()
	expectedRoot := try.To1(root.CBORPublicKey())
	genuine := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	forged := try.To1(intro.ParsePath(genuine.Bytes()))
	forged[1].Body.Options.Position++
	want := []intro.Path{forged, genuine}

	assert.NoError(inbox.ReceivePath(forged.Bytes()))
	assert.NoError(inbox.ReceivePath(genuine.Bytes()))
	received := inbox.Paths()
	assert.DeepEqual(received, want)

	assert.ErrorIs(
		received[0].ProveFromRoot(expectedRoot), intro.ErrBadSignature,
	)
	assert.NoError(received[1].ProveFromRoot(expectedRoot))
	assert.DeepEqual(received, want)
	assert.DeepEqual(inbox.Paths(), want)
}

func TestInboxExactDuplicates(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	path := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	contentVariant := path.Clone()
	contentVariant[1].Body.Options.AllowRouting = true
	signatureVariant := path.Clone()
	signatureVariant[1].ParentSig[0] ^= 1

	var inbox intro.Inbox
	for _, received := range []intro.Path{
		path, path, contentVariant, path, signatureVariant,
		contentVariant, signatureVariant,
	} {
		assert.NoError(inbox.ReceivePath(received.Bytes()))
	}
	assert.DeepEqual(inbox.Paths(), []intro.Path{
		path, contentVariant, signatureVariant,
	})
}

func TestInboxRejectedInput(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	path := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	encoded := path.Bytes()
	assert.SLonger(encoded, 0)
	assert.Equal(encoded[0], byte(0x82))
	alternate := append([]byte{0x98, 0x02}, encoded[1:]...)
	var inbox intro.Inbox
	assert.NoError(inbox.ReceivePath(encoded))
	want := []intro.Path{path}

	assert.ErrorIs(inbox.ReceivePath(alternate), wire.ErrNonCanonicalCBOR)
	assert.DeepEqual(inbox.Paths(), want)

	assert.Error(inbox.ReceivePath(encoded[:len(encoded)-1]))
	assert.DeepEqual(inbox.Paths(), want)

	assert.Error(inbox.ReceivePath(nil))
	assert.DeepEqual(inbox.Paths(), want)
}

func TestInboxEmptyPath(t *testing.T) {
	defer assert.PushTester(t)()

	var inbox intro.Inbox
	empty := intro.Path{}.Bytes()
	assert.NoError(inbox.ReceivePath(empty))
	assert.SLen(inbox.Paths(), 0)

	root, alice := key.New(), key.New()
	path := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	assert.NoError(inbox.ReceivePath(path.Bytes()))
	assert.NoError(inbox.ReceivePath(empty))
	assert.DeepEqual(inbox.Paths(), []intro.Path{path})
}

func TestInboxOwnership(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	path := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	encoded := path.Bytes()
	want := []intro.Path{path}
	var inbox intro.Inbox
	assert.NoError(inbox.ReceivePath(encoded))

	for i := range encoded {
		encoded[i] ^= 0xff
	}
	received := inbox.Paths()
	assert.DeepEqual(received, want)

	for i := range received[0] {
		edge := &received[0][i]
		edge.Body.Child.Public[0] ^= 1
		edge.Body.Child.ID[0] ^= 1
		edge.Body.Prev[0] ^= 1
		edge.Body.Options.Position++
	}
	received[0][1].ParentSig[0] ^= 1
	assert.DeepEqual(inbox.Paths(), want)

	received[0][0] = intro.Edge{}
	assert.DeepEqual(inbox.Paths(), want)

	received[0] = nil
	assert.DeepEqual(inbox.Paths(), want)
}

func TestInboxIndependentReceivers(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	path := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	var first, second intro.Inbox
	assert.NoError(first.ReceivePath(path.Bytes()))
	assert.DeepEqual(first.Paths(), []intro.Path{path})
	assert.SLen(second.Paths(), 0)

	variant := path.Clone()
	variant[1].Body.Options.Position++
	assert.NoError(second.ReceivePath(variant.Bytes()))
	assert.DeepEqual(second.Paths(), []intro.Path{variant})
	assert.DeepEqual(first.Paths(), []intro.Path{path})
}
