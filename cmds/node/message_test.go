package node

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestServeMessageOnlyOptInPeer(t *testing.T) {
	defer assert.PushTester(t)()
	alice, bob := newVerificationPair(t, true)
	const path = "/peer/pw/message"
	const body = `{"version":1,"envelope":"AQ=="}`
	before := try.To1(firstUseState(bob.service.store.Vault()))
	for _, auth := range []string{"", alice.auth, bob.auth} {
		result := postPeerProofHTTP(t.Context(), bob.owner.URL+path,
			auth, []byte(body), false)
		assert.NoError(result.err)
		assert.Equal(result.status, 404)
		// Inspect headers directly as well: even an unauthenticated owner
		// request for this peer-only path must not get a bearer challenge.
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Authorization", auth)
		w := httptest.NewRecorder()
		bob.service.handler.ServeHTTP(w, r)
		assert.Equal(w.Code, 404)
		assert.Equal(w.Header().Get("WWW-Authenticate"), "")
		assert.Equal(w.Header().Get("Cache-Control"), "no-store")
	}
	result := postPeerProofHTTP(t.Context(), bob.peer.URL+path, "",
		[]byte(body), false)
	assert.NoError(result.err)
	assert.Equal(result.status, 409) // Route exists; invalid domain envelope.
	assert.Equal(string(result.body), "Conflict\n")
	for _, peerPath := range []string{"/owner/pw/message", "/peer/pw/establish",
		"/peer/pw/first-use"} {
		result = postPeerProofHTTP(t.Context(), bob.peer.URL+peerPath, "",
			[]byte(`{}`), false)
		assert.NoError(result.err)
		want := http.StatusBadRequest
		if peerPath == "/owner/pw/message" {
			want = http.StatusNotFound
		}
		assert.Equal(result.status, want)
	}
	assert.DeepEqual(try.To1(firstUseState(bob.service.store.Vault())), before)
	bob.owner.Close()
	bob.peer.Close()
	try.To(bob.service.close())
	disabled := startVerificationNode(t, bob.fixture, false)
	assert.INil(disabled.service.peerHandler)
	for _, auth := range []string{"", disabled.auth} {
		result = postPeerProofHTTP(t.Context(), disabled.owner.URL+path, auth,
			[]byte(body), false)
		assert.NoError(result.err)
		assert.Equal(result.status, 404)
	}
	assert.DeepEqual(
		try.To1(firstUseState(disabled.service.store.Vault())),
		before,
	)
}
