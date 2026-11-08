package node

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
)

const nodeMessageSendPath = "/owner/pw/message/send"
const nodeMessageInboxPathV2 = "/owner/pw/message/inbox?version=2"

var nodeMessageRows = []string{
	"local-pw-message-outgoing-v1", "local-pw-message-envelope-v1",
	"local-pw-message-sent-v1", "local-pw-message-ack-v1",
	"local-pw-message-inbox-v1",
}

func readyMessagePairV2(t *testing.T) (*verificationNode, *verificationNode) {
	t.Helper()
	defer assert.PushTester(t)()
	alice, bob := establishFirstUsePairV2(t)
	result := postPeerProofHTTP(t.Context(),
		alice.owner.URL+"/owner/pw/first-use", alice.auth,
		[]byte(`{"version":2}`), false)
	assert.NoError(result.err)
	assert.Equal(result.status, 200)
	assert.Equal(string(result.body), `{"local_ready":true}`)
	return alice, bob
}

func sendNodeMessageV2(t *testing.T, n *verificationNode, text string,
) peerHTTPResult {
	t.Helper()
	defer assert.PushTester(t)()
	body := try.To1(json.Marshal(struct {
		Version int    `json:"version"`
		Text    string `json:"text"`
	}{2, text}))
	return postPeerProofHTTP(t.Context(), n.owner.URL+nodeMessageSendPath,
		n.auth, body, false)
}

func readNodeInboxV2(t *testing.T, n *verificationNode) pw.MessageInbox {
	t.Helper()
	defer assert.PushTester(t)()
	r := try.To1(http.NewRequestWithContext(t.Context(), http.MethodGet,
		n.owner.URL+nodeMessageInboxPathV2, nil))
	r.Header.Set("Authorization", n.auth)
	client := &http.Client{Timeout: 3 * time.Second}
	response := try.To1(client.Do(r))
	defer func() { assert.NoError(response.Body.Close()) }()
	assert.Equal(response.StatusCode, 200)
	assert.Equal(response.Header.Get("Cache-Control"), "no-store")
	var doc struct {
		Present bool   `json:"present"`
		ID      string `json:"message_id_hex"`
		Text    string `json:"text"`
	}
	try.To(json.NewDecoder(io.LimitReader(response.Body, 2048)).Decode(&doc))
	var id [16]byte
	if doc.Present {
		raw := try.To1(hex.DecodeString(doc.ID))
		assert.Equal(len(raw), 16)
		copy(id[:], raw)
	}
	return pw.MessageInbox{Present: doc.Present, ID: id, Text: doc.Text}
}

type nodeMessageExchange struct {
	request, receipt []byte
	sender, receiver map[string]map[string][]byte
	err              error
}

func (n *verificationNode) serveObservedMessage(w http.ResponseWriter,
	r *http.Request, next http.Handler,
) {
	n.mu.Lock()
	respond := n.messageRespond
	n.mu.Unlock()
	if respond != nil {
		respond(w, r, next)
	} else {
		next.ServeHTTP(w, r)
	}
}

// Observation occurs after the real receiver capability releases its lock but
// before the sender can see the receipt. Assertions stay on the test goroutine.
func observeNodeMessages(t *testing.T, sender, receiver *verificationNode,
	mode string,
) (<-chan nodeMessageExchange, *atomic.Int32) {
	t.Helper()
	done := make(chan nodeMessageExchange, 4)
	posts := &atomic.Int32{}
	receiver.mu.Lock()
	receiver.messageRespond = func(w http.ResponseWriter, r *http.Request,
		next http.Handler,
	) {
		posts.Add(1)
		var exchange nodeMessageExchange
		exchange.request, exchange.err = io.ReadAll(
			io.LimitReader(r.Body, 4097),
		)
		if r.Method != "POST" || r.URL.RequestURI() != "/peer/pw/message" ||
			r.Header.Get(
				"Authorization",
			) != "" || r.Header.Get("Cookie") != "" {
			exchange.err = errors.Join(exchange.err,
				errors.New("unexpected peer route or credentials"))
		}
		r.Body = io.NopCloser(bytes.NewReader(exchange.request))
		captured := httptest.NewRecorder()
		next.ServeHTTP(captured, r)
		exchange.receipt = bytes.Clone(captured.Body.Bytes())
		var err error
		exchange.sender, err = firstUseState(sender.service.store.Vault())
		exchange.err = errors.Join(exchange.err, err)
		exchange.receiver, err = firstUseState(receiver.service.store.Vault())
		exchange.err = errors.Join(exchange.err, err)
		if mode == "ack unavailable" {
			exchange.err = errors.Join(
				exchange.err,
				sender.service.store.Close(),
			)
		}
		if mode == "sender delete" {
			result := postPeerProofHTTP(r.Context(),
				sender.owner.URL+"/owner/pw/holding/delete", sender.auth,
				[]byte(`{}`), false)
			exchange.err = errors.Join(exchange.err, result.err)
			if result.status != 200 {
				exchange.err = errors.Join(exchange.err,
					errors.New("owner mutation blocked during message HTTP"))
			}
		}
		if mode == "lost reply" {
			conn, _, err := w.(http.Hijacker).Hijack()
			exchange.err = errors.Join(exchange.err, err)
			if err == nil {
				exchange.err = errors.Join(exchange.err, conn.Close())
			}
		} else {
			body := captured.Body.Bytes()
			if mode == "wrong version" {
				body = bytes.Replace(body, []byte(`"version":2`),
					[]byte(`"version":1`), 1)
			}
			if mode == "wrong signature" {
				var doc struct {
					Version int    `json:"version"`
					Receipt []byte `json:"receipt"`
				}
				err := json.Unmarshal(body, &doc)
				exchange.err = errors.Join(exchange.err, err)
				if err == nil && len(doc.Receipt) > 0 {
					doc.Receipt[len(doc.Receipt)-1] ^= 1
					body, err = json.Marshal(doc)
					exchange.err = errors.Join(exchange.err, err)
				}
			}
			maps.Copy(w.Header(), captured.Header())
			w.WriteHeader(captured.Code)
			_, err := w.Write(body)
			exchange.err = errors.Join(exchange.err, err)
		}
		done <- exchange
	}
	receiver.mu.Unlock()
	return done, posts
}

func TestServeMessageV2UnknownOutcomes(t *testing.T) {
	for _, mode := range []string{"lost reply", "ack unavailable",
		"wrong version", "wrong signature"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			alice, bob := readyMessagePairV2(t)
			done, posts := observeNodeMessages(t, alice, bob, mode)
			result := sendNodeMessageV2(t, alice, "independent commit")
			assert.NoError(result.err)
			assert.Equal(result.status, 502)
			assert.Equal(string(result.body), "Bad Gateway\n")
			exchange := <-done
			checkNodeMessageV2(t, alice, bob, exchange, true)
			assert.Equal(posts.Load(), 1)
			assert.SNil(exchange.sender["root"][nodeMessageRows[3]])
			vault := alice.service.store.Vault()
			if mode == "ack unavailable" {
				store := try.To1(nodevault.OpenForNode(t.Context(),
					alice.fixture.dir, alice.fixture.storageKey,
					alice.fixture.root, alice.fixture.child))
				defer func() { assert.NoError(store.Close()) }()
				vault = store.Vault()
			}
			assert.DeepEqual(try.To1(firstUseState(vault)), exchange.sender)
			assert.DeepEqual(try.To1(firstUseState(bob.service.store.Vault())),
				exchange.receiver)
			if mode == "lost reply" {
				// An explicit retry can recover; only its first ACK may write.
				disk := nodeMessageDisk(t, bob)
				done, posts = observeNodeMessages(t, alice, bob, "")
				result = sendNodeMessageV2(t, alice, "independent commit")
				assert.NoError(result.err)
				assert.Equal(result.status, 200)
				again := <-done
				assert.NoError(again.err)
				assert.DeepEqual(again.request, exchange.request)
				assert.Equal(posts.Load(), 1)
				assert.DeepEqual(nodeMessageDisk(t, bob), disk)
			}
		})
	}
}

type nodeMessageBindingV2 struct {
	_                      struct{} `cbor:",toarray"`
	Root, Sender, Receiver key.Public
	Requester              bool
	RequestDigest          []byte
	AcceptedDigest         []byte
}

func checkNodeMessageV2(t *testing.T, sender, receiver *verificationNode,
	exchange nodeMessageExchange, requester bool,
) [16]byte {
	t.Helper()
	defer assert.PushTester(t)()
	assert.NoError(exchange.err)
	var request struct {
		Version  int
		Envelope []byte
	}
	var reply struct {
		Version int
		Receipt []byte
	}
	try.To(json.Unmarshal(exchange.request, &request))
	try.To(json.Unmarshal(exchange.receipt, &reply))
	assert.Equal(request.Version, 2)
	assert.Equal(reply.Version, 2)
	a, b := exchange.sender["root"], exchange.receiver["root"]
	assert.DeepEqual(request.Envelope, a[nodeMessageRows[1]])
	var envelope struct {
		_         struct{} `cbor:",toarray"`
		Version   uint8
		Message   []byte
		Signature key.Signature
	}
	try.To(wire.UnmarshalCanonical(&envelope, request.Envelope))
	assert.Equal(envelope.Version, 2)
	assert.DeepEqual(envelope.Message, a[nodeMessageRows[0]])
	digest := key.HashTagged("pw-message-auth/v2", envelope.Message)
	assert.That(envelope.Signature.Verify(sender.fixture.child, digest[:]))
	var message struct {
		_       struct{} `cbor:",toarray"`
		Version uint8
		ID      []byte
		Binding nodeMessageBindingV2
		Text    string
	}
	try.To(wire.UnmarshalCanonical(&message, envelope.Message))
	assert.Equal(message.Version, 2)
	assert.Equal(len(message.ID), 16)
	assert.Equal(message.ID[6]&0xf0, byte(0x40))
	assert.Equal(message.ID[8]&0xc0, byte(0x80))
	assert.DeepEqual(message.Binding.Root, sender.fixture.root)
	assert.DeepEqual(message.Binding.Sender, sender.fixture.child)
	assert.DeepEqual(message.Binding.Receiver, receiver.fixture.child)
	assert.Equal(message.Binding.Requester, requester)
	accepted := a["local-pw-accepted-v1"]
	digest = key.HashTagged("pw-message-accepted-history/v2", accepted)
	assert.DeepEqual(message.Binding.AcceptedDigest, digest[:])
	var history struct {
		_                 struct{} `cbor:",toarray"`
		Version           uint8
		Request, Response []byte
	}
	try.To(wire.UnmarshalCanonical(&history, accepted))
	digest = key.HashTagged("pw-invitation-request-digest/v2", history.Request)
	assert.DeepEqual(message.Binding.RequestDigest, digest[:])
	var established pw.SignedEstablishmentV2
	try.To(wire.UnmarshalCanonical(&established, history.Request))
	ownContact, peerContact := sender.peer.URL, receiver.peer.URL
	if !requester {
		ownContact, peerContact = peerContact, ownContact
	}
	assert.Equal(established.Payload.RequesterContact, ownContact)
	assert.Equal(established.Payload.TargetContact, peerContact)
	var sent struct {
		_              struct{} `cbor:",toarray"`
		Version        uint8
		EnvelopeDigest []byte
	}
	try.To(wire.UnmarshalCanonical(&sent, a[nodeMessageRows[2]]))
	assert.Equal(sent.Version, 2)
	digest = key.HashTagged("pw-message-sent-envelope/v2", request.Envelope)
	assert.DeepEqual(sent.EnvelopeDigest, digest[:])
	var inbox struct {
		_        struct{} `cbor:",toarray"`
		Version  uint8
		Envelope []byte
	}
	try.To(wire.UnmarshalCanonical(&inbox, b[nodeMessageRows[4]]))
	assert.Equal(inbox.Version, 2)
	assert.DeepEqual(inbox.Envelope, request.Envelope)
	var receipt struct {
		_       struct{} `cbor:",toarray"`
		Version uint8
		Payload struct {
			_              struct{} `cbor:",toarray"`
			EnvelopeDigest []byte
			ID             []byte
			Binding        nodeMessageBindingV2
		}
		Signature key.Signature
	}
	try.To(wire.UnmarshalCanonical(&receipt, reply.Receipt))
	assert.Equal(receipt.Version, 2)
	assert.DeepEqual(receipt.Payload.ID, message.ID)
	assert.DeepEqual(receipt.Payload.Binding, message.Binding)
	digest = key.HashTagged("pw-message-receipt-envelope/v2", request.Envelope)
	assert.DeepEqual(receipt.Payload.EnvelopeDigest, digest[:])
	digest = key.HashTagged("pw-message-receipt-auth/v2",
		try.To1(wire.Marshal(receipt.Payload)))
	assert.That(receipt.Signature.Verify(receiver.fixture.child, digest[:]))
	inboxRead := readNodeInboxV2(t, receiver)
	assert.That(inboxRead.Present)
	assert.Equal(inboxRead.ID, [16]byte(message.ID))
	assert.Equal(inboxRead.Text, message.Text)
	return inboxRead.ID
}

func nodeMessageDisk(t *testing.T, n *verificationNode) [2][]byte {
	t.Helper()
	defer assert.PushTester(t)()
	return [2][]byte{
		try.To1(os.ReadFile(filepath.Join(n.fixture.dir, "state", "vault.db"))),
		try.To1(os.ReadFile(filepath.Join(n.fixture.dir, "state", "usage.db"))),
	}
}

func TestServeMessageV2TwoNodeExchange(t *testing.T) {
	defer assert.PushTester(t)()
	alice, bob := readyMessagePairV2(t)
	nodes := []*verificationNode{alice, bob}
	before := []map[string]map[string][]byte{
		try.To1(firstUseState(alice.service.store.Vault())),
		try.To1(firstUseState(bob.service.store.Vault())),
	}
	assert.ThatNot(readNodeInboxV2(t, alice).Present)
	assert.ThatNot(readNodeInboxV2(t, bob).Present)
	var ids [2][16]byte
	for i, sender := range nodes {
		receiver := nodes[1-i]
		done, posts := observeNodeMessages(t, sender, receiver, "")
		result := sendNodeMessageV2(t, sender, "bounded demonstration")
		assert.NoError(result.err)
		assert.Equal(result.status, 200)
		assert.Equal(
			string(result.body),
			`{"local_acknowledgement_saved":true}`,
		)
		exchange := <-done
		ids[i] = checkNodeMessageV2(t, sender, receiver, exchange, i == 0)
		assert.Equal(posts.Load(), 1)
		assert.SNil(exchange.sender["root"][nodeMessageRows[3]])
		for _, name := range nodeMessageRows[:3] {
			before[i]["root"][name] = exchange.sender["root"][name]
		}
		assert.DeepEqual(exchange.sender, before[i])
		before[1-i]["root"][nodeMessageRows[4]] =
			exchange.receiver["root"][nodeMessageRows[4]]
		assert.DeepEqual(exchange.receiver, before[1-i])
		var reply struct{ Receipt []byte }
		try.To(json.Unmarshal(exchange.receipt, &reply))
		before[i]["root"][nodeMessageRows[3]] = try.To1(wire.Marshal(struct {
			_       struct{} `cbor:",toarray"`
			Version uint8
			Receipt []byte
		}{Version: 2, Receipt: reply.Receipt}))
		assert.DeepEqual(try.To1(firstUseState(sender.service.store.Vault())),
			before[i])
		t.Logf(
			"direction %d: owner POST v2 200; peer POST v2 200 without credentials; owner GET version=2 200; inbox committed before ACK",
			i+1,
		)

		// Compare encrypted database AND usage bytes: exact retry is read-only,
		// including the original ACK, even though receipt signatures may differ.
		diskSender, diskReceiver := nodeMessageDisk(t, sender),
			nodeMessageDisk(t, receiver)
		result = sendNodeMessageV2(t, sender, "bounded demonstration")
		assert.NoError(result.err)
		assert.Equal(result.status, 200)
		second := <-done
		assert.NoError(second.err)
		assert.DeepEqual(second.request, exchange.request)
		assert.Equal(
			checkNodeMessageV2(t, sender, receiver, second, i == 0),
			ids[i],
		)
		assert.Equal(posts.Load(), 2)
		assert.DeepEqual(nodeMessageDisk(t, sender), diskSender)
		assert.DeepEqual(nodeMessageDisk(t, receiver), diskReceiver)
		result = sendNodeMessageV2(t, sender, "changed")
		assert.NoError(result.err)
		assert.Equal(result.status, 409)
		result = postPeerProofHTTP(
			t.Context(),
			sender.owner.URL+nodeMessageSendPath,
			sender.auth,
			[]byte(`{"version":2,"text":"x","peer_message_url":"`+
				receiver.peer.URL+`/peer/pw/message"}`),
			false,
		)
		assert.NoError(result.err)
		assert.Equal(result.status, 400)
		assert.Equal(posts.Load(), 2)
		assert.DeepEqual(nodeMessageDisk(t, sender), diskSender)
		assert.DeepEqual(nodeMessageDisk(t, receiver), diskReceiver)
	}
	assert.NotEqual(ids[0], ids[1])
	for i, n := range nodes {
		assert.DeepEqual(
			try.To1(firstUseState(n.service.store.Vault())),
			before[i],
		)
		// Every change was one of the five existing message slots; no pairing,
		// PWOpen or Trust effect. Retain historical inbox after local policy loss.
		path, body := "/owner/pw/holding/delete", []byte(`{}`)
		if i == 0 {
			path = "/owner/policy/deny"
			body = []byte(`{"peer_public_key_hex":"` +
				hex.EncodeToString(bob.fixture.child) + `"}`)
		}
		result := postPeerProofHTTP(
			t.Context(),
			n.owner.URL+path,
			n.auth,
			body,
			false,
		)
		assert.NoError(result.err)
		assert.Equal(result.status, 200)
		retained := try.To1(firstUseState(n.service.store.Vault()))
		assert.Equal(readNodeInboxV2(t, n).ID, ids[1-i])
		result = sendNodeMessageV2(t, n, "bounded demonstration")
		assert.NoError(result.err)
		assert.Equal(result.status, 409)
		n.owner.Close()
		n.peer.Close()
		try.To(n.service.close())
		restarted, _ := try.To2(
			setupNodeServe(t.Context(), serveCommand(t, n.fixture)),
		)
		defer func() { assert.NoError(restarted.close()) }()
		restarted.configurePublication(nil)
		n.owner = httptest.NewServer(restarted.handler)
		defer n.owner.Close()
		n.auth = serveAuthorization(t, restarted)
		assert.Equal(readNodeInboxV2(t, n).ID, ids[1-i])
		assert.DeepEqual(
			try.To1(firstUseState(restarted.store.Vault())),
			retained,
		)
	}
}

func TestServeMessageV2RuntimeCannotRebind(t *testing.T) {
	for _, mode := range []string{"no listener", "changed port"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			alice, bob := readyMessagePairV2(t)
			a := try.To1(firstUseState(alice.service.store.Vault()))
			b := try.To1(firstUseState(bob.service.store.Vault()))
			alice.owner.Close()
			alice.peer.Close()
			try.To(alice.service.close())
			var config net.ListenConfig
			old := try.To1(config.Listen(t.Context(), "tcp",
				strings.TrimPrefix(alice.peer.URL, "http://")))
			defer func() { assert.NoError(old.Close()) }()
			cmd := serveCommand(t, alice.fixture)
			if mode == "changed port" {
				try.To(cmd.Flags().Set("peer-listen", "127.0.0.1:0"))
			}
			restarted, _ := try.To2(setupNodeServe(t.Context(), cmd))
			defer func() { assert.NoError(restarted.close()) }()
			if mode == "changed port" {
				peer := httptest.NewUnstartedServer(nil)
				restarted.configurePublication(peer.Listener)
				peer.Config.Handler = restarted.peerHandler
				peer.Start()
				defer peer.Close()
			} else {
				restarted.configurePublication(nil)
			}
			alice.owner = httptest.NewServer(restarted.handler)
			defer alice.owner.Close()
			alice.auth = serveAuthorization(t, restarted)
			result := sendNodeMessageV2(t, alice, "refused before effects")
			assert.NoError(result.err)
			assert.Equal(result.status, 409)
			assert.DeepEqual(try.To1(firstUseState(restarted.store.Vault())), a)
			assert.DeepEqual(
				try.To1(firstUseState(bob.service.store.Vault())),
				b,
			)
		})
	}
}

func TestServeMessageV2LateACKAndPeerRejection(t *testing.T) {
	defer assert.PushTester(t)()
	alice, bob := readyMessagePairV2(t)
	done, posts := observeNodeMessages(t, alice, bob, "sender delete")
	result := sendNodeMessageV2(t, alice, "historical acknowledgement")
	assert.NoError(result.err)
	assert.Equal(result.status, 200) // Historical ACK after sender Delete.
	exchange := <-done
	checkNodeMessageV2(t, alice, bob, exchange, true)
	assert.Equal(posts.Load(), 1)
	state := try.To1(firstUseState(alice.service.store.Vault()))
	assert.SNil(state["root"]["local-pw-held-v1"])
	assert.SNotEmpty(state["root"][nodeMessageRows[3]])
	result = sendNodeMessageV2(t, alice, "historical acknowledgement")
	assert.NoError(result.err)
	assert.Equal(result.status, 409)
	assert.Equal(posts.Load(), 1)
	bob.mu.Lock()
	bob.messageRespond = nil
	bob.mu.Unlock()
	disk := nodeMessageDisk(t, bob)
	var original struct {
		Version  int    `json:"version"`
		Envelope []byte `json:"envelope"`
	}
	try.To(json.Unmarshal(exchange.request, &original))
	for _, mode := range []string{"JSON version", "signature", "signed version"} {
		doc := original
		doc.Envelope = bytes.Clone(original.Envelope)
		switch mode {
		case "JSON version":
			doc.Version = 1
		case "signature":
			doc.Envelope[len(doc.Envelope)-1] ^= 1
		case "signed version":
			// Canonical envelope array starts with its version integer.
			assert.Equal(doc.Envelope[1], byte(2))
			doc.Envelope[1] = 1
		}
		result = postPeerProofHTTP(t.Context(), bob.peer.URL+"/peer/pw/message",
			"", try.To1(json.Marshal(doc)), false)
		assert.NoError(result.err)
		assert.Equal(result.status, 409)
		assert.DeepEqual(nodeMessageDisk(t, bob), disk)
	}
	result = postPeerProofHTTP(
		t.Context(),
		bob.owner.URL+"/owner/pw/holding/delete",
		bob.auth,
		[]byte(`{}`),
		false,
	)
	assert.NoError(result.err)
	assert.Equal(result.status, 200)
	disk = nodeMessageDisk(t, bob)
	result = postPeerProofHTTP(t.Context(), bob.peer.URL+"/peer/pw/message",
		"", exchange.request, false)
	assert.NoError(result.err)
	assert.Equal(result.status, 409)
	assert.DeepEqual(nodeMessageDisk(t, bob), disk)
	assert.That(readNodeInboxV2(t, bob).Present)
}
