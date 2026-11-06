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
	for _, auth := range []string{"", alice.auth, bob.auth} {
		for _, method := range []string{"GET", "POST", "HEAD"} {
			r := httptest.NewRequest(method, "/owner/pw/message/inbox", nil)
			r.Header.Set("Authorization", auth)
			w := httptest.NewRecorder()
			bob.service.peerHandler.ServeHTTP(w, r)
			assert.Equal(w.Code, 404)
			assert.Equal(w.Header().Get("WWW-Authenticate"), "")
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
		}
	}
	for _, peerPath := range []string{"/owner/pw/message", "/owner/pw/message/send", "/peer/pw/establish",
		"/peer/pw/first-use"} {
		result = postPeerProofHTTP(t.Context(), bob.peer.URL+peerPath, "",
			[]byte(`{}`), false)
		assert.NoError(result.err)
		want := http.StatusBadRequest
		if strings.HasPrefix(peerPath, "/owner/") {
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
	// Historical inbox reads need no peer listener. Missing first-use history
	// is a fixed refusal, even though no message has been committed here.
	for _, auth := range []string{"", disabled.auth} {
		r := httptest.NewRequest("GET", "/owner/pw/message/inbox", nil)
		r.Header.Set("Authorization", auth)
		w := httptest.NewRecorder()
		disabled.service.handler.ServeHTTP(w, r)
		want := 401
		if auth != "" {
			want = 409
		}
		assert.Equal(w.Code, want)
		assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
	}
	// The operational send route exists even without this node's peer listener.
	// No message history was prepared, so valid owner input is locally refused.
	const sendPath = "/owner/pw/message/send"
	const sendBody = `{"text":"one","peer_message_url":"http://127.0.0.1:1/peer/pw/message"}`
	for _, auth := range []string{"", disabled.auth} {
		result = postPeerProofHTTP(t.Context(), disabled.owner.URL+sendPath,
			auth, []byte(sendBody), false)
		assert.NoError(result.err)
		want := 401
		if auth != "" {
			want = 409
		}
		assert.Equal(result.status, want)
	}
	assert.DeepEqual(
		try.To1(firstUseState(disabled.service.store.Vault())),
		before,
	)
}
