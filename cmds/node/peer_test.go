package node

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func setupPeerServe(t *testing.T, f serveFixture) *nodeServe {
	t.Helper()
	defer assert.PushTester(t)()

	cmd := serveCommand(t, f)
	try.To(cmd.Flags().Set("peer-listen", "localhost:0"))
	s, _ := try.To2(setupNodeServe(t.Context(), cmd))
	t.Cleanup(func() { try.Out(s.close()).Logf() })
	assert.Equal(s.peerAddress, "127.0.0.1:0")
	assert.INotNil(s.peerHandler)
	return s
}

func TestPeerOwnCompletedIntroduction(t *testing.T) {
	defer assert.PushTester(t)()

	f := prepareServeFixture(t)
	choice := saveServeChoice(t, f, "completed")
	s := setupPeerServe(t, f)
	// Keep another subject in Known and a third only in Received. Neither may
	// be disclosed or promoted by peer GET, and neither is the local choice.
	parent := try.To1(nodeidentity.OpenDirectory(f.dir, f.unlock))
	for i := range 2 {
		other := key.New()
		path := f.proposal.Introduce(parent, key.Info{Public: try.To1(other.CBORPublicKey())})
		try.To2(onboarding.SaveIntroduction(s.store.Vault(), f.root,
			path.Bytes(), try.To1(path.SignAcceptance(other))))
		if i == 0 {
			assert.Equal(try.To1(onboarding.VerifyReceived(s.store.Vault(), f.root)), 1)
		}
	}
	known := try.To1(onboarding.ListKnownIntroductions(s.store.Vault(), f.root))
	assert.SLen(known, 1)
	assert.SLen(try.To1(onboarding.ListIntroductions(s.store.Vault(), f.root)), 2)
	assertPeerFilesUnchanged(t, f)
	root, child := bytes.Clone(f.root), bytes.Clone(f.child)
	handler := peerapi.NewHandler(s.store.Vault(), root, child)
	clear(root)
	clear(child) // Configuration was copied, never selected by a request.
	for range 3 {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/peer/introduction", nil))
		assert.Equal(response.Code, http.StatusOK)
		assert.Equal(response.Header().Get("Cache-Control"), "no-store")
		assert.Equal(response.Header().Get("Content-Type"), "application/json")
		assert.Empty(response.Header().Get("Access-Control-Allow-Origin"))
		var document struct {
			Version    int
			Proposal   []byte
			Acceptance []byte
		}
		try.To(json.Unmarshal(response.Body.Bytes(), &document))
		assert.Equal(document.Version, 1)
		assert.DeepEqual(document.Proposal, choice.Proposal.Bytes())
		assert.DeepEqual(document.Acceptance, []byte(choice.Acceptance))
		path := try.To1(intro.ParsePath(document.Proposal))
		assert.NoError(path.ProveFromRoot(f.root))
		assert.NoError(path.VerifyAcceptance(document.Acceptance))
		assert.DeepEqual(path.LeafPubKey(), f.child)
	}
	assert.DeepEqual(try.To1(onboarding.ListKnownIntroductions(s.store.Vault(), f.root)), known)
}

func assertPeerFilesUnchanged(t *testing.T, f serveFixture) {
	t.Helper()
	defer assert.PushTester(t)()

	for _, name := range []string{"vault.db", "usage.db"} {
		path := filepath.Join(f.dir, "state", name)
		before := try.To1(os.ReadFile(path))
		t.Cleanup(func() {
			defer assert.PushTester(t)()
			assert.DeepEqual(try.To1(os.ReadFile(path)), before)
		})
	}
}

func TestPeerRouteBoundary(t *testing.T) {
	defer assert.PushTester(t)()

	f := prepareServeFixture(t)
	s := setupPeerServe(t, f)
	header := string(try.To1(os.ReadFile(s.headerFile)))
	authorization := strings.TrimSpace(strings.TrimPrefix(header, "Authorization: "))
	// Nil Vault proves routing, methods and selectors are rejected before reads.
	peer := peerapi.NewHandler(nil, f.root, f.child)
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/owner/status", "", 404},
		{"GET", "/owner/introduction", "", 404},
		{"POST", "/owner/introduction/check", "{}", 404},
		{"POST", "/owner/introductions", "{}", 404},
		{"GET", "/owner/introductions", "", 404},
		{"POST", "/intro/acceptance", "{}", 404},
		{"GET", "/intro/offer", "", 404},
		{"GET", "/", "", 404},
		{"GET", "/peer/introduction/", "", 404},
		{"GET", "/peer/../owner/status", "", 404},
		{"HEAD", "/peer/introduction", "", 405},
		{"POST", "/peer/introduction", "{}", 405},
		{"PUT", "/peer/introduction", "{}", 405},
		{"DELETE", "/peer/introduction", "", 405},
		{"OPTIONS", "/peer/introduction", "", 405},
		{"GET", "/peer/introduction?root=other&child=other&accept=true&change=true", "", 400},
		{"GET", "/peer/introduction?public-key=other", "", 400},
		{"GET", "/peer/introduction", `{"child":"other"}`, 400},
	} {
		for _, token := range []string{"", authorization} {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Authorization", token)
			w := httptest.NewRecorder()
			peer.ServeHTTP(w, r)
			assert.Equal(w.Code, tc.status)
			assert.Equal(w.Body.String(), http.StatusText(tc.status)+"\n")
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
		}
	}
	for _, path := range []string{"/owner/introduction", "/owner/introductions"} {
		w := httptest.NewRecorder()
		s.handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")))
		assert.Equal(w.Code, http.StatusUnauthorized)
	}
	r := httptest.NewRequest(http.MethodGet, "/peer/introduction", nil)
	r.Header.Set("Authorization", authorization)
	w := httptest.NewRecorder()
	s.handler.ServeHTTP(w, r)
	assert.Equal(w.Code, http.StatusNotFound)
}

func TestPeerSavedChoiceRefusals(t *testing.T) {
	for _, scenario := range []string{
		"unselected", "pending", "orphaned", "bad acceptance", "noncanonical", "bad proof",
		"wrong root", "wrong child", "closed", "oversize",
		"root ID", "parent ID", "child ID", "root backup", "parent backup", "child backup",
		"root rotation", "parent rotation", "child rotation",
	} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()

			f := prepareServeFixtureWithPath(t, func(root key.Handle, child key.Public) intro.Path {
				parent := key.New()
				infos := []key.Info{{Public: try.To1(root.CBORPublicKey())},
					{Public: try.To1(parent.CBORPublicKey())}, {Public: child}}
				opts := make([][]intro.Opts, 3)
				for i, name := range []string{"root", "parent", "child"} {
					switch scenario {
					case name + " ID":
						infos[i].ID = []byte("private handle")
					case name + " backup":
						opts[i] = []intro.Opts{intro.WithBackupKeyIndex(1)}
					case name + " rotation":
						opts[i] = []intro.Opts{intro.WithRotation()}
					}
				}
				if scenario == "oversize" {
					opts[2] = []intro.Opts{intro.WithEndpoint(strings.Repeat("x", 100*1024), false)}
				}
				return intro.New(infos[0], opts[0]...).Introduce(root, infos[1], opts[1]...).
					Introduce(parent, infos[2], opts[2]...)
			})
			s := setupPeerServe(t, f)
			acceptance := try.To1(f.proposal.SignAcceptance(try.To1(nodeidentity.OpenDirectory(f.dir, f.unlock))))
			assert.NoError(f.proposal.VerifyAcceptance(acceptance))
			proposal := f.proposal.Bytes()
			if scenario == "oversize" {
				// Raw evidence fits; base64 plus the JSON envelope exceeds 128 KiB.
				assert.That(len(proposal) < onboarding.MaxIntroductionBytes)
			}
			switch scenario {
			case "unselected":
				proposal, acceptance = nil, nil
			case "pending":
				acceptance = nil
			case "orphaned":
				proposal = nil
			case "bad acceptance":
				acceptance = []byte("invalid")
			case "noncanonical":
				proposal = append([]byte{0x98, 0x03}, proposal[1:]...)
			case "bad proof":
				f.proposal[1].Body.Options.Position++
				proposal = f.proposal.Bytes()
			case "wrong root":
				s.peerHandler = peerapi.NewHandler(s.store.Vault(), []byte("other root"), f.child)
			case "wrong child":
				s.peerHandler = peerapi.NewHandler(s.store.Vault(), f.root, []byte("other child"))
			}
			try.To(s.store.Vault().Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				records := try.To1(tx.EnsureChild([]byte("introduction-choice-demo")))
				if proposal != nil {
					try.To(records.Put([]byte("selected-proposal"), proposal))
				}
				if acceptance != nil {
					try.To(records.Put([]byte("acceptance"), acceptance))
				}
				return nil
			}))
			assertPeerFilesUnchanged(t, f)
			if scenario == "closed" {
				try.To(s.store.Close())
			}
			w := httptest.NewRecorder()
			s.peerHandler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/peer/introduction", nil))
			want := http.StatusInternalServerError
			if scenario == "unselected" || scenario == "pending" {
				want = http.StatusConflict
			}
			assert.Equal(w.Code, want)
			assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
		})
	}
}
