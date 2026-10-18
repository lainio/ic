package intro_test

import (
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
)

func TestSignedRepresentationRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options intro.Options
	}{
		{name: "default options"},
		{
			name: "all options",
			options: intro.Options{
				Position:       2,
				BackupKeyIndex: 3,
				Rotation:       true,
				AllowRouting:   true,
				Resolver:       true,
				Endpoint:       "fixture.invalid:443",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			root, alice, bob := key.New(), key.New(), key.New()
			rootInfo := key.InfoFromHandle(root)
			aliceInfo := key.InfoFromHandle(alice)
			bobInfo := key.InfoFromHandle(bob)
			withOptions := func(o *intro.Options) { *o = tc.options }

			rootPath := intro.New(rootInfo)
			rootBytes := rootPath.Bytes()
			alicePath := rootPath.Introduce(root, aliceInfo, withOptions)
			assert.DeepEqual(rootPath.Bytes(), rootBytes)
			assert.SLen(rootPath, 1)

			aliceBytes := alicePath.Bytes()
			path := alicePath.Introduce(alice, bobInfo, withOptions)
			assert.DeepEqual(alicePath.Bytes(), aliceBytes)
			assert.SLen(alicePath, 2)

			encoded := path.Bytes()
			decodedPath := intro.NewPathFromData(encoded)
			assert.SLen(decodedPath, 3)
			assert.DeepEqual(decodedPath, path)
			// Re-encode our own deterministic output, not arbitrary wire input.
			assert.DeepEqual(decodedPath.Bytes(), encoded)

			parents := []key.Public{rootInfo.Public, aliceInfo.Public}
			children := []key.Info{aliceInfo, bobInfo}
			for i, parent := range parents {
				edge := path[i+1]
				body := intro.EdgeBody{
					Version: intro.EdgeVersion,
					Prev: key.HashTagged(
						"v1/signed-hash", path[i].Bytes(),
					),
					Child:   children[i],
					Options: tc.options,
				}
				// The signed representation is a full Edge with nil ParentSig,
				// not EdgeBody alone. Construct it independently of ExcludeBytes.
				unsigned := try.To1(wire.Marshal(intro.Edge{
					Body: body, ParentSig: nil,
				}))
				assert.DeepEqual(edge.Body, body)
				assert.DeepEqual(edge.ExcludeBytes(), unsigned)
				assert.That(edge.ParentSig.Verify(parent, unsigned))
				assert.That(edge.VerifySignature(parent))

				edgeBytes := edge.Bytes()
				decodedEdge := intro.NewEdgeFromData(edgeBytes)
				assert.DeepEqual(decodedEdge, edge)
				assert.DeepEqual(decodedEdge.Bytes(), edgeBytes)
				assert.That(decodedEdge.VerifySignature(parent))
				assert.That(decodedPath[i+1].VerifySignature(parent))
			}
		})
	}
}

func TestSignedBodyCoverage(t *testing.T) {
	defer assert.PushTester(t)()

	parent := key.New()
	parentInfo := key.InfoFromHandle(parent)
	wrongParent := key.InfoFromHandle(key.New()).Public
	parentPath := intro.New(parentInfo)

	// These options exercise signed bytes, not legacy option policy.
	path := parentPath.Introduce(
		parent, key.InfoFromHandle(key.New()),
		intro.WithPosition(1), intro.WithBackupKeyIndex(2),
		intro.WithRotation(), intro.WithAllowRouting(true),
		intro.WithEndpoint("fixture.invalid:443", true),
	)
	edge := path.LastEdge()
	encoded := edge.Bytes()
	assert.That(edge.VerifySignature(parentInfo.Public))

	for _, tc := range []struct {
		name   string
		mutate func(*intro.Edge)
	}{
		{"Version", func(e *intro.Edge) { e.Body.Version++ }},
		{"Prev", func(e *intro.Edge) { e.Body.Prev[0] ^= 1 }},
		{"Child.ID", func(e *intro.Edge) { e.Body.Child.ID[0] ^= 1 }},
		{"Child.Public", func(e *intro.Edge) {
			e.Body.Child.Public[len(e.Body.Child.Public)-1] ^= 1
		}},
		{"Position", func(e *intro.Edge) { e.Body.Options.Position++ }},
		{"BackupKeyIndex", func(e *intro.Edge) {
			e.Body.Options.BackupKeyIndex++
		}},
		{"Rotation", func(e *intro.Edge) {
			e.Body.Options.Rotation = !e.Body.Options.Rotation
		}},
		{"AllowRouting", func(e *intro.Edge) {
			e.Body.Options.AllowRouting = !e.Body.Options.AllowRouting
		}},
		{"Resolver", func(e *intro.Edge) {
			e.Body.Options.Resolver = !e.Body.Options.Resolver
		}},
		{"Endpoint", func(e *intro.Edge) {
			e.Body.Options.Endpoint = "changed.invalid:443"
		}},
		{"changed signature", func(e *intro.Edge) {
			e.ParentSig[len(e.ParentSig)-1] ^= 1
		}},
		{"absent signature", func(e *intro.Edge) { e.ParentSig = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			modified := intro.NewEdgeFromData(encoded)
			assert.That(modified.VerifySignature(parentInfo.Public))

			tc.mutate(&modified)
			assert.ThatNot(modified.VerifySignature(parentInfo.Public))
		})
	}

	t.Run("wrong parent key", func(t *testing.T) {
		defer assert.PushTester(t)()

		decoded := intro.NewEdgeFromData(encoded)
		assert.That(decoded.VerifySignature(parentInfo.Public))
		assert.ThatNot(decoded.VerifySignature(wrongParent))
	})
	assert.DeepEqual(edge.Bytes(), encoded)
	assert.That(edge.VerifySignature(parentInfo.Public))
}

func TestSignedDecodingIsNotVerification(t *testing.T) {
	defer assert.PushTester(t)()

	parent := key.New()
	parentInfo := key.InfoFromHandle(parent)
	path := intro.New(parentInfo).Introduce(
		parent, key.InfoFromHandle(key.New()), intro.WithPosition(1),
	)
	edge := path.LastEdge()
	encoded := edge.Bytes()
	assert.That(edge.VerifySignature(parentInfo.Public))

	t.Run("altered body", func(t *testing.T) {
		defer assert.PushTester(t)()

		modified := intro.NewEdgeFromData(encoded)
		modified.Body.Options.Position++
		var decoded intro.Edge
		try.T(
			wire.Unmarshal(&decoded, modified.Bytes()),
		)(
			"decoding altered edge",
		)

		assert.DeepEqual(decoded.Body, modified.Body)
		assert.DeepEqual(decoded.ParentSig, edge.ParentSig)
		assert.ThatNot(decoded.VerifySignature(parentInfo.Public))
		assert.DeepEqual(edge.Bytes(), encoded)
	})
	t.Run("truncated edge", func(t *testing.T) {
		defer assert.PushTester(t)()

		var decoded intro.Edge
		assert.Error(wire.Unmarshal(&decoded, encoded[:len(encoded)-1]))
	})
}
