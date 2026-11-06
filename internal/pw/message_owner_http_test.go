package pw_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/ownerapi"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
)

const ownerMessageSendPath = "/owner/pw/message/send"
const ownerMessageSuccess = `{"local_acknowledgement_saved":true}`

type ownerMessageFixture struct {
	*firstUseExchange
	sender, receiver     *exchangeNode
	owner, receiverOwner http.Handler
	auth, receiverAuth   string
	server               *httptest.Server
	peer                 http.Handler
	posts                atomic.Int32
	done                 chan messageSendResult
	mode                 string
	after                func() error
}

func newOwnerMessage(t *testing.T, bobFirst bool) *ownerMessageFixture {
	t.Helper()
	defer assert.PushTester(t)()
	f := &ownerMessageFixture{firstUseExchange: newFirstUseExchange(t),
		done: make(chan messageSendResult, 1)}
	status, _ := try.To2(f.post(t.Context(), ownerUsePath, []byte("{}")))
	assert.Equal(status, 200)
	f.sender, f.receiver = f.a, f.b
	if bobFirst {
		f.sender, f.receiver = f.b, f.a
	}
	before := f.snapshot(t)
	s := f.sender
	h, file, bind := try.To3(ownerapi.NewFirstUseCredentials(t.Context(),
		s.store.Vault(), f.root, s.public, s.signer, t.TempDir()))
	bind(nil) // Sending requires no local peer listener, in either role.
	f.owner, f.auth = h, ownerMessageAuth(t, file)
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(f.serveMessage))
	t.Cleanup(f.server.Close)
	r := f.receiver
	h, file, bind = try.To3(ownerapi.NewFirstUseCredentials(t.Context(),
		r.store.Vault(), f.root, r.public, r.signer, t.TempDir()))
	prove, accept, establish, use, receive := bind(f.server.Listener)
	assert.That(prove != nil && accept != nil && establish != nil &&
		use != nil && receive != nil)
	f.receiverOwner, f.receiverAuth = h, ownerMessageAuth(t, file)
	f.peer = peerapi.NewMessageHandler(receive, http.NotFoundHandler())
	f.server.Start()
	assert.DeepEqual(f.snapshot(t), before)
	return f
}

func ownerMessageAuth(t *testing.T, file string) string {
	t.Helper()
	defer assert.PushTester(t)()
	return strings.TrimSpace(strings.TrimPrefix(
		string(try.To1(os.ReadFile(file))), "Authorization:"))
}

func (f *ownerMessageFixture) serveMessage(w http.ResponseWriter,
	r *http.Request,
) {
	f.posts.Add(1)
	captured := httptest.NewRecorder()
	f.peer.ServeHTTP(captured, r)
	var err error
	if f.after != nil {
		err = f.after()
	}
	if f.mode == "lost" {
		conn, _, hijackErr := w.(http.Hijacker).Hijack()
		err = errors.Join(err, hijackErr)
		if hijackErr == nil {
			err = errors.Join(err, conn.Close())
		}
	} else {
		body := captured.Body.Bytes()
		switch f.mode {
		case "malformed":
			body = []byte(`{"version":1,"receipt":"/w=="}`)
		case "forged":
			var doc struct {
				Version int    `json:"version"`
				Receipt []byte `json:"receipt"`
			}
			if decodeErr := json.Unmarshal(body, &doc); decodeErr != nil {
				err = errors.Join(err, decodeErr)
			} else if len(doc.Receipt) == 0 {
				err = errors.New("fixture receipt absent")
			} else {
				doc.Receipt[len(doc.Receipt)-1] ^= 1
				body, err = json.Marshal(doc)
			}
		}
		maps.Copy(w.Header(), captured.Header())
		w.WriteHeader(captured.Code)
		_, writeErr := w.Write(body)
		err = errors.Join(err, writeErr)
	}
	f.done <- messageSendResult{captured, err}
}

func (f *ownerMessageFixture) send(t *testing.T, text string,
	w http.ResponseWriter,
) {
	t.Helper()
	defer assert.PushTester(t)()
	body := try.To1(json.Marshal(map[string]string{
		"text": text, "peer_message_url": f.server.URL + peerMessagePath,
	}))
	r := httptest.NewRequestWithContext(t.Context(), "POST",
		ownerMessageSendPath, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", f.auth)
	f.owner.ServeHTTP(w, r)
}

func (f *ownerMessageFixture) checkCommit(t *testing.T,
	senderBefore, receiverBefore map[string]map[string][]byte, ack bool,
) {
	t.Helper()
	defer assert.PushTester(t)()
	got := <-f.done
	try.To(got.err)
	assert.Equal(got.response.Code, 200)
	var doc struct{ Receipt []byte }
	try.To(json.Unmarshal(got.response.Body.Bytes(), &doc))
	try.To1(pw.VerifySavedMessageReceiptForTest(f.sender.store.Vault(),
		f.root, f.sender.public, doc.Receipt))
	sender := pw.MessageStateForTest(t, f.sender.store.Vault())
	for _, name := range []string{"local-pw-message-outgoing-v1",
		"local-pw-message-envelope-v1", messageSentKey} {
		assert.SNotEmpty(sender["root"][name])
		senderBefore["root"][name] = sender["root"][name]
	}
	envelope := sender["root"]["local-pw-message-envelope-v1"]
	var signed struct {
		_         struct{} `cbor:",toarray"`
		Version   uint8
		Message   []byte
		Signature key.Signature
	}
	try.To(wire.UnmarshalCanonical(&signed, envelope))
	assert.DeepEqual(signed.Message,
		sender["root"]["local-pw-message-outgoing-v1"])
	digest := key.HashTagged("pw-message-auth/v1", signed.Message)
	assert.That(signed.Signature.Verify(f.sender.public, digest[:]))
	receiverBefore["root"][messageInboxKey] = try.To1(wire.Marshal(struct {
		_        struct{} `cbor:",toarray"`
		Version  uint8
		Envelope []byte
	}{Version: 1, Envelope: envelope}))
	if ack {
		senderBefore["root"][messageACKKey] = try.To1(wire.Marshal(struct {
			_       struct{} `cbor:",toarray"`
			Version uint8
			Receipt []byte
		}{Version: 1, Receipt: doc.Receipt}))
	} else {
		assert.SNil(sender["root"][messageACKKey])
	}
	// Compare all known namespaces: no Trust, PWOpen or unrelated changes.
	assert.DeepEqual(sender, senderBefore)
	assert.DeepEqual(pw.MessageStateForTest(t, f.receiver.store.Vault()),
		receiverBefore)
}

func ownerMessageMutation(h http.Handler, auth, path, body string) error {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", auth)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		return errors.New("owner mutation refused")
	}
	return nil
}

func TestOwnerMessageHTTPEitherFirstAndExactRetry(t *testing.T) {
	for _, bobFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(bobFirst), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOwnerMessage(t, bobFirst)
			before := f.snapshot(t)
			signs := len(f.sender.signer.signed())
			r := httptest.NewRequest("GET", "/owner/status", nil)
			r.Header.Set("Authorization", f.auth)
			read := httptest.NewRecorder()
			f.owner.ServeHTTP(read, r)
			assert.Equal(read.Code, 200)
			assert.DeepEqual(f.snapshot(t), before)
			assert.Equal(len(f.sender.signer.signed()), signs)
			assert.Equal(f.posts.Load(), 0)
			a := pw.MessageStateForTest(t, f.sender.store.Vault())
			b := pw.MessageStateForTest(t, f.receiver.store.Vault())
			f.after = func() error {
				// These existing mutations take each service's one owner lock.
				// Both must finish while the sending HTTP call is still in flight.
				return errors.Join(ownerMessageMutation(f.owner, f.auth,
					"/owner/introductions/verify", "{}"),
					ownerMessageMutation(f.receiverOwner, f.receiverAuth,
						"/owner/introductions/verify", "{}"))
			}
			w := &messageHTTPWriter{ResponseRecorder: httptest.NewRecorder(),
				fail: true, beforeWrite: func() {
					assert.SNotEmpty(try.To1(readUseRecord(
						f.sender.store.Vault(), messageACKKey)))
					try.To(ownerMessageMutation(f.owner, f.auth,
						"/owner/introductions/verify", "{}"))
				}}
			text := strings.Repeat("é", 512) // Exactly 1024 UTF-8 bytes.
			f.send(t, text, w)
			assert.Equal(w.Code, 200)
			assert.Equal(w.Body.String(), ownerMessageSuccess)
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
			assert.Equal(w.Header().Get("Content-Type"), "application/json")
			f.checkCommit(t, a, b, true)
			before = f.snapshot(t)
			retry := httptest.NewRecorder()
			f.send(t, text, retry) // Explicit retry after lost owner response.
			try.To((<-f.done).err)
			assert.Equal(retry.Code, 200)
			assert.Equal(retry.Body.String(), ownerMessageSuccess)
			assert.DeepEqual(f.snapshot(t), before) // No seal on either Vault.
			assert.Equal(f.posts.Load(), 2)
			conflict := httptest.NewRecorder()
			f.send(t, "different text", conflict)
			assert.Equal(conflict.Code, 409)
			assert.Equal(f.posts.Load(), 2)
			assert.DeepEqual(f.snapshot(t), before)
		})
	}
}

func TestOwnerMessageHTTPLostOrInvalidReplyExplicitRetry(t *testing.T) {
	for _, mode := range []string{"lost", "malformed", "forged"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOwnerMessage(t, false)
			f.mode = mode
			a := pw.MessageStateForTest(t, f.sender.store.Vault())
			b := pw.MessageStateForTest(t, f.receiver.store.Vault())
			w := httptest.NewRecorder()
			f.send(t, "retained", w)
			assert.Equal(w.Code, 502)
			assert.Equal(w.Body.String(), "Bad Gateway\n")
			f.checkCommit(t, a, b, false)
			assert.Equal(f.posts.Load(), 1)
			f.mode = ""
			w = httptest.NewRecorder()
			f.send(t, "retained", w)
			assert.Equal(w.Code, 200)
			f.checkCommit(t, a, b, true)
			assert.Equal(f.posts.Load(), 2)
		})
	}
}

func TestOwnerMessageHTTPLateACKAfterSenderPolicyChange(t *testing.T) {
	for _, mode := range []string{"deny", "delete"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOwnerMessage(t, true)
			var afterPolicy map[string]map[string][]byte
			// Capture storage on the test goroutine while the peer waits.
			entered, release := make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			f.after = func() error { close(entered); <-release; return nil }
			done := make(chan *httptest.ResponseRecorder, 1)
			body := []byte(`{"text":"history","peer_message_url":"` +
				f.server.URL + peerMessagePath + `"}`)
			go func() {
				r := httptest.NewRequestWithContext(t.Context(), "POST",
					ownerMessageSendPath, bytes.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Authorization", f.auth)
				w := httptest.NewRecorder()
				f.owner.ServeHTTP(w, r)
				done <- w
			}()
			<-entered
			path, policyBody := "/owner/pw/holding/delete", "{}"
			if mode == "deny" {
				path = "/owner/policy/deny"
				policyBody = `{"peer_public_key_hex":"` +
					hex.EncodeToString(f.receiver.public) + `"}`
			}
			mutationErr := ownerMessageMutation(
				f.owner,
				f.auth,
				path,
				policyBody,
			)
			afterPolicy = pw.MessageStateForTest(t, f.sender.store.Vault())
			b := pw.MessageStateForTest(t, f.receiver.store.Vault())
			close(release)
			try.To(mutationErr)
			w := <-done
			assert.Equal(w.Code, 200)
			f.checkCommit(t, afterPolicy, b, true)
			before := f.snapshot(t)
			for _, text := range []string{"history", "new"} {
				w = httptest.NewRecorder()
				f.send(t, text, w)
				assert.Equal(w.Code, 409)
			}
			assert.Equal(f.posts.Load(), 1)
			assert.DeepEqual(f.snapshot(t), before)
		})
	}
}

func TestOwnerMessageHTTPReceiverPolicyRefusesRetryRetainsInbox(t *testing.T) {
	for _, mode := range []string{"deny", "delete"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOwnerMessage(t, false)
			f.mode = "lost"
			w := httptest.NewRecorder()
			f.send(t, "once", w)
			try.To((<-f.done).err)
			assert.Equal(w.Code, 502)
			assert.SNotEmpty(try.To1(readUseRecord(f.receiver.store.Vault(),
				messageInboxKey)))
			path, body := "/owner/pw/holding/delete", "{}"
			if mode == "deny" {
				path = "/owner/policy/deny"
				body = `{"peer_public_key_hex":"` +
					hex.EncodeToString(f.sender.public) + `"}`
			}
			try.To(
				ownerMessageMutation(
					f.receiverOwner,
					f.receiverAuth,
					path,
					body,
				),
			)
			before := f.snapshot(t)
			f.mode = ""
			w = httptest.NewRecorder()
			f.send(t, "once", w)
			got := <-f.done
			try.To(got.err)
			assert.Equal(got.response.Code, 409)
			assert.Equal(w.Code, 502)
			assert.Equal(f.posts.Load(), 2)
			assert.DeepEqual(f.snapshot(t), before)
			assert.SNil(
				try.To1(readUseRecord(f.sender.store.Vault(), messageACKKey)),
			)
		})
	}
}

func TestOwnerMessageHTTPACKVaultFailureRetainsIndependentCommits(
	t *testing.T,
) {
	defer assert.PushTester(t)()
	f := newOwnerMessage(t, false)
	a := pw.MessageStateForTest(t, f.sender.store.Vault())
	b := pw.MessageStateForTest(t, f.receiver.store.Vault())
	// Deliberately lose sender storage availability after the real receiver
	// commit and signature, before ACK observation. No production failure hook.
	f.after = f.sender.store.Close
	w := httptest.NewRecorder()
	f.send(t, "retained", w)
	assert.Equal(w.Code, 502)
	assert.Equal(w.Body.String(), "Bad Gateway\n")
	assert.Equal(f.posts.Load(), 1)
	f.server.Close()
	f.reopen(t)
	f.checkCommit(t, a, b, false)
}
