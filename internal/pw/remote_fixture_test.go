package pw_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/ownerapi"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const challengePath, acceptPath = "/peer/pw/challenge", "/peer/pw/accept"

// Restored software signers and separately bound, reopened encrypted stores.
// Tests wrap only the listener, never the production client's transport.
type exchangeNode struct {
	dir, storageKey string
	public          key.Public
	signer          *observedSigner
	store           *nodevault.Store
}

type observedSigner struct {
	key.Handle
	mu       sync.Mutex
	messages [][]byte
	fail     bool
}

func (s *observedSigner) Sign(message []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = append(s.messages, bytes.Clone(message))
	if s.fail {
		return nil, errors.New("private provider diagnostic")
	}
	return s.Handle.Sign(message)
}

func (s *observedSigner) signed() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.messages...)
}

func newExchangeNode(t *testing.T) *exchangeNode {
	t.Helper()
	defer assert.PushTester(t)()
	dir := t.TempDir()
	try.To(os.Chmod(dir, 0700))
	unlock := make([]byte, 32)
	try.To1(rand.Read(unlock))
	defer clear(unlock)
	path := filepath.Join(dir, "identity.json")
	try.To1(nodeidentity.Create(path, unlock))
	handle := try.To1(nodeidentity.Open(path, unlock))
	return &exchangeNode{dir: dir,
		storageKey: filepath.Join(t.TempDir(), "storage.key"),
		public:     try.To1(handle.CBORPublicKey()),
		signer:     &observedSigner{Handle: handle}}
}

func (n *exchangeNode) open(t *testing.T, root key.Public) {
	t.Helper()
	defer assert.PushTester(t)()
	s := try.To1(nodevault.CreateForNode(t.Context(), n.dir, n.storageKey,
		root, n.public))
	try.To(s.Close())
	n.store = try.To1(nodevault.OpenForNode(t.Context(), n.dir, n.storageKey,
		root, n.public))
	t.Cleanup(func() { assert.NoError(n.store.Close()) })
}

type exchangeFixture struct {
	root      key.Public
	a, b      *exchangeNode // requester, acceptor
	server    *httptest.Server
	owner     http.Handler
	ownerAuth string
	ad        []byte
}

func newExchange(t *testing.T,
	wrap func(http.Handler) http.Handler,
) *exchangeFixture {
	t.Helper()
	return newExchangeWithAuthorization(t, wrap, true)
}

func newExchangeWithAuthorization(t *testing.T,
	wrap func(http.Handler) http.Handler, authorizeRequester bool,
) *exchangeFixture {
	t.Helper()
	defer assert.PushTester(t)()
	r, a, b := newExchangeNode(t), newExchangeNode(t), newExchangeNode(t)
	f := &exchangeFixture{root: r.public, a: a, b: b}
	a.open(t, r.public)
	b.open(t, r.public)
	base := intro.New(key.Info{Public: r.public})
	for _, n := range []*exchangeNode{a, b} {
		path := base.Introduce(r.signer, key.Info{Public: n.public})
		for _, reader := range []*exchangeNode{a, b} {
			var signature key.Signature
			if n == reader {
				signature = try.To1(onboarding.SignAfterStoredChoice(
					reader.store.Vault(), n.signer, r.public, r.public, path))
			} else {
				signature = try.To1(path.SignAcceptance(n.signer))
			}
			try.To2(onboarding.SaveIntroduction(reader.store.Vault(),
				r.public, path.Bytes(), signature))
		}
	}
	for _, n := range []*exchangeNode{a, b} {
		assert.Equal(try.To1(onboarding.VerifyReceived(n.store.Vault(),
			r.public)), 2)
		if n != a || authorizeRequester {
			try.To1(device.BootstrapLocal(n.store.Vault(), r.public, n.public,
				n.signer))
		}
	}
	f.server = httptest.NewUnstartedServer(nil)
	endpoint := "http://" + f.server.Listener.Addr().String() +
		"/peer/introduction"
	f.ad = try.To1(wire.Marshal(try.To1(ads.PublishLocal(b.store.Vault(),
		r.public, b.public, b.signer, endpoint, time.Now()))))
	owner, credential, bind := try.To3(
		ownerapi.NewAcceptanceCredentials(t.Context(),
			b.store.Vault(), r.public, b.public, b.signer, t.TempDir()),
	)
	f.owner = owner
	f.ownerAuth = strings.TrimSpace(strings.TrimPrefix(
		string(try.To1(os.ReadFile(credential))), "Authorization:"))
	proveAd, accept := bind(f.server.Listener)
	next := peerapi.NewProofHandler(b.store.Vault(), r.public, b.public,
		endpoint, proveAd)
	handler := peerapi.NewAcceptanceHandler(b.store.Vault(), r.public,
		b.public, endpoint, accept, next)
	if wrap != nil {
		handler = wrap(handler)
	}
	f.server.Config.Handler = handler
	f.server.Start()
	t.Cleanup(f.server.Close)
	try.To1(ads.ReceiveClaim(a.store.Vault(), r.public, b.public, f.ad))
	try.To1(ads.VerifyReceivedRemote(t.Context(), a.store.Vault(), r.public,
		a.public, b.public))
	return f
}

func (f *exchangeFixture) request(ctx context.Context) error {
	return pw.RequestRemoteAcceptance(ctx, f.a.store.Vault(), f.root,
		f.a.public, f.b.public, f.a.signer)
}

// Include encrypted records, durable usage counters and saved identities.
func (f *exchangeFixture) snapshot(t *testing.T) map[string][]byte {
	t.Helper()
	defer assert.PushTester(t)()
	files := make(map[string][]byte)
	for _, n := range []*exchangeNode{f.a, f.b} {
		try.To(filepath.WalkDir(n.dir, func(path string, entry fs.DirEntry,
			err error,
		) error {
			if err != nil {
				return err
			}
			if !entry.IsDir() {
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				files[path] = data
			}
			return nil
		}))
	}
	return files
}

func deleteExchangeRecord(t *testing.T, v *storage.Vault,
	namespace string, name []byte,
) {
	t.Helper()
	defer assert.PushTester(t)()
	try.To(v.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		if namespace == "" {
			return tx.Delete(name)
		}
		return try.To1(tx.ChildForUpdate([]byte(namespace))).Delete(name)
	}))
}

func putExchangeRecord(t *testing.T, v *storage.Vault,
	namespace string, name, record []byte,
) {
	t.Helper()
	defer assert.PushTester(t)()
	try.To(v.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		if namespace == "" {
			return tx.Put(name, record)
		}
		return try.To1(tx.EnsureChild([]byte(namespace))).Put(name, record)
	}))
}
