package ownerapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/peerapi"
)

func TestMessageCapabilityRequiresPeerBinding(t *testing.T) {
	defer assert.PushTester(t)()
	h, _, bind := try.To3(NewFirstUseCredentials(t.Context(),
		nil, nil, nil, nil, t.TempDir()))
	target := h.(*authenticatedStatusHandler).next.(*firstUseHandler)
	_, err := target.receiveMessageLocal(1, []byte{1})
	assert.Error(err)
	prove, accept, establish, use, receive := bind(nil)
	assert.That(prove == nil && accept == nil && establish == nil &&
		use == nil && receive == nil)
	s := httptest.NewUnstartedServer(nil)
	defer s.Close()
	prove, accept, establish, use, receive = bind(s.Listener)
	assert.That(prove == nil && accept == nil && establish == nil && use == nil)
	assert.That(
		receive == nil,
	) // Nil binding permanently disables the capability.
	w := deviceRequest(
		peerapi.NewMessageHandler(receive, http.NotFoundHandler()),
		"",
		"POST",
		"/peer/pw/message",
		`{"version":1,"envelope":"AQ=="}`,
	)
	assert.Equal(w.Code, 404)

	old, file, _ := try.To3(NewEstablishmentCredentials(t.Context(),
		nil, nil, nil, nil, t.TempDir()))
	auth := strings.TrimSpace(strings.TrimPrefix(
		string(try.To1(os.ReadFile(file))), "Authorization:"))
	assert.Equal(
		deviceRequest(old, auth, "POST", "/peer/pw/message", "{}").Code,
		404,
	)
}

func TestMessageCapabilityUsesExistingMutationLock(t *testing.T) {
	defer assert.PushTester(t)()
	h, _, bind := try.To3(NewFirstUseCredentials(t.Context(),
		nil, nil, nil, nil, t.TempDir()))
	target := h.(*authenticatedStatusHandler).next.(*firstUseHandler)
	s := httptest.NewUnstartedServer(nil)
	defer s.Close()
	prove, accept, establish, use, receive := bind(s.Listener)
	assert.That(prove != nil && accept != nil && establish != nil &&
		use != nil && receive != nil)
	target.mutations.Lock()
	locked := true
	defer func() {
		if locked {
			target.mutations.Unlock()
		}
	}()
	started, done := make(chan struct{}), make(chan error, 1)
	go func() {
		close(started)
		_, err := receive(1, []byte{1})
		done <- err
	}()
	<-started
	select {
	case <-done:
		t.Fatal("message capability bypassed owner mutation lock")
	case <-time.After(25 * time.Millisecond):
	}
	target.mutations.Unlock()
	locked = false
	select {
	case err := <-done:
		assert.Error(err)
	case <-time.After(5 * time.Second):
		t.Fatal("message capability did not release owner lock")
	}
	assert.That(target.mutations.TryLock())
	target.mutations.Unlock()
}
