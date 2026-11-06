package pw_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/ownerapi"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
)

const peerMessagePath = "/peer/pw/message"
const messageInboxKey = "local-pw-message-inbox-v1"

type messageHTTPFixture struct {
	*firstUseExchange
	sender, receiver *exchangeNode
	raw, body        []byte
	owner, peer      http.Handler
	auth             string
	calls            int
}

func newMessageHTTP(t *testing.T, bobFirst bool) *messageHTTPFixture {
	t.Helper()
	defer assert.PushTester(t)()
	f := &messageHTTPFixture{firstUseExchange: newFirstUseExchange(t)}
	status, _ := try.To2(f.post(t.Context(), ownerUsePath, []byte("{}")))
	assert.Equal(status, 200)
	f.sender, f.receiver = f.a, f.b
	if bobFirst {
		f.sender, f.receiver = f.b, f.a
	}
	s := f.sender
	try.To1(pw.CreateOutgoingForTest(s.store.Vault(), f.root,
		s.public, s.signer, strings.Repeat("é", 512)))
	f.raw = try.To1(pw.PrepareMessageEnvelopeForTest(s.store.Vault(),
		f.root, s.public, s.signer))
	f.body = try.To1(json.Marshal(struct {
		Version  int    `json:"version"`
		Envelope []byte `json:"envelope"`
	}{1, f.raw}))
	assert.DeepEqual(f.raw, try.To1(readUseRecord(s.store.Vault(),
		"local-pw-message-envelope-v1")))
	for _, n := range []*exchangeNode{s, f.receiver} {
		assert.SNil(try.To1(readUseRecord(n.store.Vault(), messageInboxKey)))
		assert.SNil(
			try.To1(readUseRecord(n.store.Vault(), "local-pw-message-ack-v1")),
		)
	}
	f.bindMessage(t, f.receiver.signer)
	return f
}

func (f *messageHTTPFixture) bindMessage(t *testing.T, signer key.Handle) {
	t.Helper()
	defer assert.PushTester(t)()
	before := f.snapshot(t)
	n := f.receiver
	owner, file, bind := try.To3(ownerapi.NewFirstUseCredentials(t.Context(),
		n.store.Vault(), f.root, n.public, signer, t.TempDir()))
	listener := httptest.NewUnstartedServer(nil)
	t.Cleanup(listener.Close)
	prove, accept, establish, use, receive := bind(listener.Listener)
	assert.That(prove != nil && accept != nil && establish != nil &&
		use != nil && receive != nil)
	f.owner = owner
	f.auth = strings.TrimSpace(strings.TrimPrefix(
		string(try.To1(os.ReadFile(file))), "Authorization:"))
	f.peer = peerapi.NewMessageHandler(func(raw []byte) ([]byte, error) {
		f.calls++
		return receive(raw)
	}, http.NotFoundHandler())
	assert.DeepEqual(f.snapshot(t), before) // No startup writes.
}

func (f *messageHTTPFixture) request(w http.ResponseWriter) {
	r := httptest.NewRequest("POST", peerMessagePath, bytes.NewReader(f.body))
	r.Header.Set("Content-Type", "application/json")
	f.peer.ServeHTTP(w, r)
}

func (f *messageHTTPFixture) checkReceipt(
	t *testing.T,
	w *httptest.ResponseRecorder,
) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	assert.Equal(w.Code, 200)
	assert.Equal(w.Header().Get("Content-Type"), "application/json")
	assert.Equal(w.Header().Get("Cache-Control"), "no-store")
	assert.That(w.Body.Len() <= 2*1024)
	var doc struct {
		Version int    `json:"version"`
		Receipt []byte `json:"receipt"`
	}
	try.To(json.Unmarshal(w.Body.Bytes(), &doc))
	assert.Equal(doc.Version, 1)
	assert.DeepEqual(w.Body.Bytes(), try.To1(json.Marshal(doc)))
	return try.To1(pw.VerifySavedMessageReceiptForTest(f.sender.store.Vault(),
		f.root, f.sender.public, doc.Receipt))
}

type messageHTTPWriter struct {
	*httptest.ResponseRecorder
	beforeWrite func()
	fail        bool
	writes      int
}

func (w *messageHTTPWriter) WriteHeader(code int) {
	w.beforeWrite()
	w.ResponseRecorder.WriteHeader(code)
}

func (w *messageHTTPWriter) Write(data []byte) (int, error) {
	w.beforeWrite()
	w.writes++
	n, err := w.ResponseRecorder.Write(
		data,
	) // Inspect even deliberately lost bytes.
	if w.fail {
		return 0, errors.New("lost HTTP reply")
	}
	return n, err
}

func TestMessageHTTPEitherSenderFirstLostReplyAndReopen(t *testing.T) {
	for _, bobFirst := range []bool{false, true} {
		for _, mode := range []string{"delivered", "lost", "deny", "delete"} {
			t.Run(fmt.Sprint(bobFirst, "/", mode), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newMessageHTTP(t, bobFirst)
				before := f.snapshot(t)
				records := pw.MessageStateForTest(t, f.receiver.store.Vault())
				sender := pw.MessageStateForTest(t, f.sender.store.Vault())
				inbox := try.To1(wire.Marshal(struct {
					_        struct{} `cbor:",toarray"`
					Version  uint8
					Envelope []byte
				}{Version: 1, Envelope: f.raw}))
				w := &messageHTTPWriter{
					ResponseRecorder: httptest.NewRecorder(),
					fail:             mode != "delivered",
					beforeWrite: func() {
						assert.DeepEqual(
							try.To1(readUseRecord(f.receiver.store.Vault(),
								messageInboxKey)),
							inbox,
						)
						// A real owner mutation shares the capability's lock. It must
						// finish before the response writer proceeds (no nested lock).
						r := httptest.NewRequest(
							"POST",
							"/owner/introductions/verify",
							strings.NewReader("{}"),
						)
						r.Header.Set("Content-Type", "application/json")
						r.Header.Set("Authorization", f.auth)
						ownerResult := httptest.NewRecorder()
						f.owner.ServeHTTP(ownerResult, r)
						assert.Equal(ownerResult.Code, 200)
					},
				}
				f.request(w)
				payload := f.checkReceipt(t, w.ResponseRecorder)
				assert.Equal(f.calls, 1)
				assert.Equal(w.writes, 1)
				records["root"][messageInboxKey] = inbox
				assert.DeepEqual(
					pw.MessageStateForTest(t, f.receiver.store.Vault()),
					records,
				)
				assert.DeepEqual(
					pw.MessageStateForTest(t, f.sender.store.Vault()),
					sender,
				)
				after := f.snapshot(t)
				for _, name := range []string{"vault.db", "usage.db"} {
					delete(before, filepath.Join(f.receiver.dir, "state", name))
					delete(after, filepath.Join(f.receiver.dir, "state", name))
				}
				assert.DeepEqual(after, before)
				f.reopen(t)
				f.bindMessage(t, f.receiver.signer)
				assert.DeepEqual(
					pw.MessageStateForTest(t, f.receiver.store.Vault()),
					records,
				)
				switch mode {
				case "deny":
					denyExchangePeer(
						t,
						f.exchangeFixture,
						f.receiver,
						f.sender.public,
						true,
					)
				case "delete":
					deleteExchangeHolding(t, f.exchangeFixture, f.receiver)
				}
				before = f.snapshot(t)
				retry := httptest.NewRecorder()
				f.request(
					retry,
				) // The sole explicit retry, including after loss.
				assert.Equal(f.calls, 2)
				if mode == "deny" || mode == "delete" {
					assert.Equal(retry.Code, 409)
					assert.Equal(retry.Body.String(), "Conflict\n")
				} else {
					assert.DeepEqual(f.checkReceipt(t, retry), payload)
				}
				assert.DeepEqual(
					f.snapshot(t),
					before,
				) // No seal or bookkeeping.
				assert.DeepEqual(try.To1(readUseRecord(f.receiver.store.Vault(),
					messageInboxKey)), inbox)
				assert.DeepEqual(
					pw.MessageStateForTest(t, f.sender.store.Vault()),
					sender,
				)
			})
		}
	}
}

type messageFailSigner struct {
	key.Handle
	calls int
}

func (s *messageFailSigner) Sign(data []byte) ([]byte, error) {
	s.calls++
	if s.calls == 3 { // Admission probe, receipt probe, receipt signature.
		return nil, errors.New("secret receipt signing diagnostic")
	}
	return s.Handle.Sign(data)
}

func TestMessageHTTPSigningFailureRetainsInbox(t *testing.T) {
	defer assert.PushTester(t)()
	f := newMessageHTTP(t, true)
	signer := &messageFailSigner{Handle: f.receiver.signer}
	f.bindMessage(t, signer)
	sender := pw.MessageStateForTest(t, f.sender.store.Vault())
	w := httptest.NewRecorder()
	f.request(w)
	assert.Equal(w.Code, 409)
	assert.Equal(w.Body.String(), "Conflict\n")
	assert.Equal(f.calls, 1)
	assert.Equal(signer.calls, 3)
	inbox := try.To1(readUseRecord(f.receiver.store.Vault(), messageInboxKey))
	assert.SNotEmpty(inbox)
	f.reopen(t)
	assert.DeepEqual(
		try.To1(readUseRecord(f.receiver.store.Vault(), messageInboxKey)),
		inbox,
	)
	assert.DeepEqual(pw.MessageStateForTest(t, f.sender.store.Vault()), sender)
}

func TestMessageHTTPRejectsInternalReceiptMismatch(t *testing.T) {
	defer assert.PushTester(t)()
	f := newMessageHTTP(t, false)
	w := httptest.NewRecorder()
	f.request(w)
	f.checkReceipt(t, w)
	var doc struct{ Receipt []byte }
	try.To(json.Unmarshal(w.Body.Bytes(), &doc))
	before := f.snapshot(t)
	for _, mode := range []string{"signature", "envelope", "mutated input"} {
		response := bytes.Clone(doc.Receipt)
		if mode == "signature" {
			response[len(response)-1] ^= 1
		}
		f.peer = peerapi.NewMessageHandler(func(raw []byte) ([]byte, error) {
			if mode == "mutated input" {
				copy(raw, f.raw)
			}
			return response, nil
		}, http.NotFoundHandler())
		if mode != "signature" {
			changed := bytes.Clone(f.raw)
			changed[len(changed)-1] ^= 1
			f.body = try.To1(json.Marshal(struct {
				Version  int    `json:"version"`
				Envelope []byte `json:"envelope"`
			}{1, changed}))
		}
		w = httptest.NewRecorder()
		f.request(w)
		assert.Equal(w.Code, 500)
		assert.Equal(w.Body.String(), "Internal Server Error\n")
	}
	assert.DeepEqual(f.snapshot(t), before)
}

func TestMessageHTTPRejectsBadSignatureHistoryAndChangedEnvelope(t *testing.T) {
	defer assert.PushTester(t)()
	f := newMessageHTTP(t, true)
	invalid := pw.MessageWireCasesForTest(t, f.raw,
		f.sender.signer, f.receiver.signer)
	original := bytes.Clone(f.body)
	for _, repeat := range []bool{false, true} {
		if repeat {
			f.body = original
			w := httptest.NewRecorder()
			f.request(w)
			f.checkReceipt(t, w)
		}
		before := f.snapshot(t)
		for _, name := range []string{"signature", "wrong signer", "signed/role",
			"signed/accepted digest", "signed/root", "mutated/changed body",
			"signed/changed body"} {
			if name == "signed/changed body" && !repeat {
				continue
			}
			f.body = try.To1(json.Marshal(struct {
				Version  int    `json:"version"`
				Envelope []byte `json:"envelope"`
			}{1, invalid[name]}))
			w := httptest.NewRecorder()
			f.request(w)
			assert.Equal(w.Code, 409, name)
			assert.Equal(w.Body.String(), "Conflict\n")
		}
		assert.DeepEqual(f.snapshot(t), before)
	}
}

type messageBlockingSigner struct {
	key.Handle
	step, calls      int
	entered, release chan struct{}
}

func (s *messageBlockingSigner) Sign(data []byte) ([]byte, error) {
	s.calls++
	if s.calls == s.step {
		close(s.entered)
		<-s.release
	}
	return s.Handle.Sign(data)
}

func TestMessageHTTPSerializesAdmitThroughFinalProbeWithOwnerDeny(
	t *testing.T,
) {
	for index := range 4 {
		t.Run(fmt.Sprint(index+1), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newMessageHTTP(t, true)
			signer := &messageBlockingSigner{Handle: f.receiver.signer,
				step: index + 1, entered: make(chan struct{}), release: make(chan struct{})}
			defer func() {
				select {
				case <-signer.release:
				default:
					close(signer.release)
				}
			}()
			f.bindMessage(t, signer)
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				w := httptest.NewRecorder()
				f.request(w)
				done <- w
			}()
			select {
			case <-signer.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("message did not reach signer")
			}
			denied := make(chan *httptest.ResponseRecorder, 1)
			started := make(chan struct{})
			go func() {
				r := httptest.NewRequest("POST", ownerDenyPath,
					strings.NewReader(`{"peer_public_key_hex":"`+
						hex.EncodeToString(f.sender.public)+`"}`))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Authorization", f.auth)
				w := httptest.NewRecorder()
				close(started)
				f.owner.ServeHTTP(w, r)
				denied <- w
			}()
			<-started
			select {
			case <-denied:
				t.Fatal("owner Deny bypassed in-progress message operation")
			case <-time.After(25 * time.Millisecond):
			}
			close(signer.release)
			select {
			case w := <-done:
				f.checkReceipt(t, w)
			case <-time.After(5 * time.Second):
				t.Fatal("message did not finish")
			}
			select {
			case w := <-denied:
				assert.Equal(w.Code, 200)
			case <-time.After(5 * time.Second):
				t.Fatal("owner Deny did not finish")
			}
			before := f.snapshot(t)
			w := httptest.NewRecorder()
			f.request(w)
			assert.Equal(w.Code, 409)
			assert.DeepEqual(f.snapshot(t), before)
		})
	}
}

func TestMessageHTTPDroppedConnectionRetainsCommitWithoutRetry(t *testing.T) {
	defer assert.PushTester(t)()
	f := newMessageHTTP(t, false)
	sender := pw.MessageStateForTest(t, f.sender.store.Vault())
	type result struct {
		w   *httptest.ResponseRecorder
		err error
	}
	done := make(chan result, 1)
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			captured := httptest.NewRecorder()
			f.peer.ServeHTTP(captured, r)
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				err = conn.Close() // Drop even the status, after the real callback.
			}
			done <- result{captured, err}
		}),
	)
	defer server.Close()
	_, _, err := useHTTP(t.Context(), server.URL+peerMessagePath, "", f.body)
	assert.Error(err)
	got := <-done
	assert.NoError(got.err)
	f.checkReceipt(t, got.w)
	assert.Equal(f.calls, 1)
	inbox := try.To1(readUseRecord(f.receiver.store.Vault(), messageInboxKey))
	assert.SNotEmpty(inbox)
	f.reopen(t)
	assert.DeepEqual(
		try.To1(readUseRecord(f.receiver.store.Vault(), messageInboxKey)),
		inbox,
	)
	assert.DeepEqual(pw.MessageStateForTest(t, f.sender.store.Vault()), sender)
}
