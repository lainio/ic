package pw_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/internal/pw"
)

const messageSentKey = "local-pw-message-sent-v1"
const messageACKKey = "local-pw-message-ack-v1"

type messageSendResult struct {
	response *httptest.ResponseRecorder
	err      error
}

// Capture the real Go-06 handler's response, optionally losing it only AFTER
// its receiver-local commit. Worker errors/assertions belong to the test thread.
func messageSendServer(f *messageHTTPFixture, owner *sync.Mutex, drop bool,
) (*httptest.Server, <-chan messageSendResult) {
	done := make(chan messageSendResult, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request,
	) {
		// The sending caller must have released its owner lock before HTTP.
		owner.Lock()
		_ = owner.TryLock() // remove the warning of the empty block
		owner.Unlock()      // But we must and can relese the lock
		captured := httptest.NewRecorder()
		f.peer.ServeHTTP(captured, r)
		var err error
		if drop {
			conn, _, hijackErr := w.(http.Hijacker).Hijack()
			err = hijackErr
			if err == nil {
				err = conn.Close()
			}
		} else {
			maps.Copy(w.Header(), captured.Header())
			w.WriteHeader(captured.Code)
			_, err = w.Write(captured.Body.Bytes())
		}
		done <- messageSendResult{captured, err}
	}))
	return server, done
}

func saveHTTPTransmit(t *testing.T, f *messageHTTPFixture,
	owner *sync.Mutex,
) pw.SavedMessageTransmitForTest {
	t.Helper()
	defer assert.PushTester(t)()
	owner.Lock()
	defer owner.Unlock()
	n := f.sender
	return try.To1(pw.SaveMessageTransmitForTest(n.store.Vault(), f.root,
		n.public, n.signer))
}

func TestMessageSendHTTPEitherFirstLostReplyLateACKAndReopen(t *testing.T) {
	for _, bobFirst := range []bool{false, true} {
		for _, mode := range []string{"delivered", "lost", "deny", "delete"} {
			t.Run(fmt.Sprint(bobFirst, "/", mode), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newMessageHTTP(t, bobFirst)
				var owner sync.Mutex
				senderBefore := pw.MessageStateForTest(
					t,
					f.sender.store.Vault(),
				)
				receiverBefore := pw.MessageStateForTest(
					t,
					f.receiver.store.Vault(),
				)
				assert.SNil(
					receiverBefore["root"]["local-pw-message-outgoing-v1"],
				)
				assert.SNil(senderBefore["root"][messageInboxKey])
				saved := saveHTTPTransmit(t, f, &owner)
				sent := try.To1(
					readUseRecord(f.sender.store.Vault(), messageSentKey),
				)
				assert.SNotEmpty(sent)
				senderBefore["root"][messageSentKey] = sent
				assert.DeepEqual(
					pw.MessageStateForTest(t, f.sender.store.Vault()),
					senderBefore,
				)
				assert.DeepEqual(
					pw.MessageStateForTest(t, f.receiver.store.Vault()),
					receiverBefore,
				)

				// Local policy may change after authorization but before dispatch.
				// It cannot recall this snapshot; it MUST refuse another attempt.
				owner.Lock()
				switch mode {
				case "deny":
					denyExchangePeer(t, f.exchangeFixture, f.sender,
						f.receiver.public, true)
				case "delete":
					deleteExchangeHolding(t, f.exchangeFixture, f.sender)
				}
				owner.Unlock()
				senderBefore = pw.MessageStateForTest(t, f.sender.store.Vault())
				server, done := messageSendServer(f, &owner, mode == "lost")
				t.Cleanup(server.Close)
				receipt, err := pw.SendMessageOnceForTest(t.Context(), saved,
					server.URL+peerMessagePath)
				got := <-done
				try.To(got.err)
				payload := f.checkReceipt(t, got.response)
				assert.Equal(f.calls, 1)
				if mode == "lost" {
					assert.Equal(err, pw.MessageOutcomeUnknownForTest)
					assert.SNil(receipt)
				} else {
					try.To(err)
					assert.DeepEqual(try.To1(pw.VerifySavedMessageReceiptForTest(
						f.sender.store.Vault(), f.root, f.sender.public, receipt)), payload)
				}
				inbox := try.To1(wire.Marshal(struct {
					_        struct{} `cbor:",toarray"`
					Version  uint8
					Envelope []byte
				}{Version: 1, Envelope: f.raw}))
				receiverBefore["root"][messageInboxKey] = inbox
				assert.DeepEqual(
					pw.MessageStateForTest(t, f.receiver.store.Vault()),
					receiverBefore,
				)
				assert.DeepEqual(
					pw.MessageStateForTest(t, f.sender.store.Vault()),
					senderBefore,
				)
				assert.SNil(senderBefore["root"][messageACKKey])
				server.Close()
				f.reopen(t)
				f.bindMessage(t, f.receiver.signer)
				assert.DeepEqual(
					pw.MessageStateForTest(t, f.sender.store.Vault()),
					senderBefore,
				)
				assert.DeepEqual(
					pw.MessageStateForTest(t, f.receiver.store.Vault()),
					receiverBefore,
				)
				beforeRetry := f.snapshot(t)
				if mode == "deny" || mode == "delete" {
					owner.Lock()
					_, err = pw.SaveMessageTransmitForTest(
						f.sender.store.Vault(),
						f.root,
						f.sender.public,
						f.sender.signer,
					)
					owner.Unlock()
					assert.Error(err)
					assert.Equal(f.calls, 1)
				} else {
					again := saveHTTPTransmit(t, f, &owner)
					assert.Equal(again, saved)
					server, done = messageSendServer(f, &owner, false)
					t.Cleanup(server.Close)
					second := try.To1(pw.SendMessageOnceForTest(t.Context(), again,
						server.URL+peerMessagePath))
					got = <-done
					try.To(got.err)
					assert.DeepEqual(f.checkReceipt(t, got.response), payload)
					assert.Equal(f.calls, 2)
					// Receipt signatures may vary; exact envelope/ID never do.
					assert.ThatNot(bytes.Equal(second, receipt))
					receipt = second
					server.Close()
				}
				assert.DeepEqual(
					f.snapshot(t),
					beforeRetry,
				) // No seal on either node.

				// HTTP alone left ACK absent. Observation is a separate owner
				// action, including after sender Deny/Delete and lost-response retry.
				owner.Lock()
				changed, err := pw.ObserveMessageReceiptForTest(
					f.sender.store.Vault(),
					f.root,
					f.sender.public,
					receipt,
				)
				owner.Unlock()
				try.To(err)
				assert.That(changed)
				senderBefore["root"][messageACKKey] = try.To1(
					wire.Marshal(struct {
						_       struct{} `cbor:",toarray"`
						Version uint8
						Receipt []byte
					}{Version: 1, Receipt: receipt}),
				)
				assert.DeepEqual(
					pw.MessageStateForTest(t, f.sender.store.Vault()),
					senderBefore,
				)
				assert.DeepEqual(
					pw.MessageStateForTest(t, f.receiver.store.Vault()),
					receiverBefore,
				)
			})
		}
	}
}

func TestMessageSendHTTPPreparationFailureNeverDispatches(t *testing.T) {
	for _, repeat := range []bool{false, true} {
		for _, guard := range []string{"deny", "delete"} {
			t.Run(fmt.Sprint(repeat, "/", guard), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newMessageHTTP(t, repeat) // Exercise both roles.
				var owner sync.Mutex
				if repeat {
					_ = saveHTTPTransmit(t, f, &owner)
				}
				switch guard {
				case "deny":
					denyExchangePeer(
						t,
						f.exchangeFixture,
						f.sender,
						f.receiver.public,
						true,
					)
				case "delete":
					deleteExchangeHolding(t, f.exchangeFixture, f.sender)
				}
				before := f.snapshot(t)
				var calls atomic.Int64
				server := httptest.NewServer(
					http.HandlerFunc(func(http.ResponseWriter,
						*http.Request,
					) {
						calls.Add(1)
					}),
				)
				defer server.Close()
				owner.Lock()
				saved, err := pw.SaveMessageTransmitForTest(
					f.sender.store.Vault(),
					f.root,
					f.sender.public,
					f.sender.signer,
				)
				owner.Unlock()
				assert.Error(err)
				assert.Equal(saved, pw.SavedMessageTransmitForTest{})
				// Even accidental dispatch of a failed result is rejected locally.
				receipt, err := pw.SendMessageOnceForTest(t.Context(), saved,
					server.URL+peerMessagePath)
				assert.Equal(err, pw.MessageNotDispatchedForTest)
				assert.SNil(receipt)
				assert.Equal(calls.Load(), 0)
				assert.DeepEqual(f.snapshot(t), before)
			})
		}
	}
}

func TestMessageSendHTTPWrongReceiverAndForgedSuccess(t *testing.T) {
	defer assert.PushTester(t)()
	f := newMessageHTTP(t, true)
	var owner sync.Mutex
	saved := saveHTTPTransmit(t, f, &owner)
	before := f.snapshot(t)
	f.peer = peerapi.NewMessageHandler(func(_ int, raw []byte) ([]byte, error) {
		// A safe loopback address may still point at the wrong node.
		owner.Lock()
		defer owner.Unlock()
		return pw.AcceptMessageAndReceipt(f.sender.store.Vault(), f.root,
			f.sender.public, f.sender.signer, raw)
	}, http.NotFoundHandler())
	server, done := messageSendServer(f, &owner, false)
	receipt, err := pw.SendMessageOnceForTest(
		t.Context(),
		saved,
		server.URL+peerMessagePath,
	)
	got := <-done
	try.To(got.err)
	assert.Equal(got.response.Code, http.StatusConflict)
	assert.Equal(err, pw.MessageOutcomeUnknownForTest)
	assert.SNil(receipt)
	server.Close()
	assert.DeepEqual(f.snapshot(t), before)

	// Obtain an authentic receipt, then forge its signature while retaining the
	// exact payload. Both malformed CBOR and forged signed CBOR remain untrusted.
	f.bindMessage(t, f.receiver.signer)
	w := httptest.NewRecorder()
	f.request(w)
	f.checkReceipt(t, w)
	var doc struct {
		Version int    `json:"version"`
		Receipt []byte `json:"receipt"`
	}
	try.To(json.Unmarshal(w.Body.Bytes(), &doc))
	doc.Receipt[len(doc.Receipt)-1] ^= 1
	before = f.snapshot(t)
	for _, bad := range [][]byte{{0xff}, doc.Receipt} {
		body := try.To1(json.Marshal(struct {
			Version int    `json:"version"`
			Receipt []byte `json:"receipt"`
		}{1, bad}))
		var calls atomic.Int64
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
			_ *http.Request,
		) {
			calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write(body)
		}))
		t.Cleanup(server.Close)
		saved = saveHTTPTransmit(t, f, &owner) // Explicit fresh authorization.
		receipt = try.To1(pw.SendMessageOnceForTest(t.Context(), saved,
			server.URL+peerMessagePath))
		assert.DeepEqual(receipt, bad)
		assert.Equal(calls.Load(), 1)
		assert.DeepEqual(f.snapshot(t), before)
		owner.Lock()
		changed, err := pw.ObserveMessageReceiptForTest(f.sender.store.Vault(),
			f.root, f.sender.public, receipt)
		owner.Unlock()
		assert.Error(err)
		assert.ThatNot(changed)
		assert.DeepEqual(f.snapshot(t), before)
		server.Close()
	}
}
