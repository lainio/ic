package node

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
)

func TestServeOwnerFetchPeerIntroduction(t *testing.T) {
	defer assert.PushTester(t)()

	alice := prepareServeFixture(t)
	saveServeChoice(t, alice, "completed")
	sender := setupPeerServe(t, alice)
	server := httptest.NewServer(sender.peerHandler)
	defer server.Close()
	dir, unlock, _ := initialized(t)
	handle := try.To1(nodeidentity.OpenDirectory(dir, unlock))
	bob := serveFixture{
		dir: dir, unlock: unlock, storageKey: filepath.Join(filepath.Dir(dir), "storage-key"),
		root: alice.root, child: try.To1(handle.CBORPublicKey()),
	}
	store := try.To1(nodevault.CreateForNode(t.Context(), bob.dir, bob.storageKey, bob.root, bob.child))
	try.To(store.Close())
	receiver, _ := try.To2(setupNodeServe(t.Context(), serveCommand(t, bob)))
	defer func() { try.Out(receiver.close()).Logf() }()
	assert.INil(receiver.peerHandler) // Fetch needs no opt-in receiver peer listener.
	authorization := strings.TrimSpace(strings.TrimPrefix(
		string(try.To1(os.ReadFile(receiver.headerFile))), "Authorization: ",
	))
	for _, created := range []bool{true, false} {
		r := httptest.NewRequest(http.MethodPost, "/owner/introductions/fetch",
			strings.NewReader(`{"peer_url":"`+server.URL+`/peer/introduction"}`))
		r.Header.Set("Authorization", authorization)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		receiver.handler.ServeHTTP(w, r)
		assert.Equal(w.Code, http.StatusOK)
		var result map[string]any
		try.To(json.Unmarshal(w.Body.Bytes(), &result))
		assert.DeepEqual(result, map[string]any{
			"subject_public_key_hex": hex.EncodeToString(alice.child), "is_self": false, "created": created,
		})
	}
	assert.DeepEqual(try.To1(onboarding.ListIntroductions(receiver.store.Vault(), bob.root)), []key.Public{alice.child})
	assert.SEmpty(try.To1(onboarding.ListKnownIntroductions(receiver.store.Vault(), bob.root)))
	_, found := try.To2(onboarding.ReadStoredChoice(receiver.store.Vault(), bob.root, bob.child))
	assert.ThatNot(found)
}
