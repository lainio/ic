package ownerapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/internal/pw"
)

func TestOwnerMessageV2StrictSelection(t *testing.T) {
	defer assert.PushTester(t)()
	f, h, auth, _ := messageSendOwner(t)
	defer f.unchanged(t)()
	for _, body := range []string{
		`{"version":2,"text":"x","peer_message_url":"http://127.0.0.1:1/peer/pw/message"}`,
		`{"version":1,"text":"x"}`, `{"version":3,"text":"x"}`,
		`{"version":2.0,"text":"x"}`, `{"version":2e0,"text":"x"}`,
		`{"version":"2","text":"x"}`, `{"version":2,"text":null}`,
		`{"version":2,"text":"x","version":2}`,
		`{"version":2,"text":"x","text":"x"}`,
		`{"vers\u0069on":2,"text":"x"}`,
		`{"version":2,"Text":"x"}`, `{"version":2,"text":""}`,
		`{"version":2,"text":"x"} {}`,
		`{"version":2,"text":"x","origin":"http://127.0.0.1:1"}`,
		`{"version":2,"text":"x","runtime":{}}`,
		`{"version":2,"text":"x","root":"x"}`,
		`{"version":2,"text":"x","request":"x"}`,
		`{"version":2,"text":"x","signer":"x"}`,
	} {
		assert.Equal(
			deviceRequest(h, auth, "POST", messageSendPath, body).Code,
			400,
		)
	}
	for _, body := range []string{`{"version":2,"text":"x"}`,
		" { \"text\":\"x\", \"version\":2 } \n"} {
		r := httptest.NewRequest(
			"POST",
			messageSendPath,
			strings.NewReader(body),
		)
		r.Header.Set("Content-Type", "application/json")
		input, status := readMessageSendRequest(httptest.NewRecorder(), r)
		assert.Equal(status, 0)
		assert.Equal(input, messageSendInput{version: 2, text: "x"})
		assert.Equal(
			deviceRequest(h, "", "POST", messageSendPath, body).Code,
			401,
		)
		// Valid selection cannot reinterpret this fixture's v1 history.
		assert.Equal(
			deviceRequest(h, auth, "POST", messageSendPath, body).Code,
			409,
		)
	}
	assert.DeepEqual(messageSendRows(t, f.vault), [4][]byte{})
}

func TestOwnerMessageInboxV2ExactQuery(t *testing.T) {
	defer assert.PushTester(t)()
	f, h, auth, _ := messageSendOwner(t)
	defer f.unchanged(t)()
	get := func(auth, query string) int {
		r := httptest.NewRequest("GET", messageInboxPath+query, nil)
		r.Header.Set("Authorization", auth)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for _, query := range []string{"?", "?version=1", "?version=3",
		"?Version=2", "?version=%32", "?%76ersion=2", "?version=02",
		"?version=2&version=2", "?version=2&", "?version=2&peer=x"} {
		assert.Equal(get(auth, query), http.StatusBadRequest)
	}
	assert.Equal(get("", "?version=2"), 401)
	assert.Equal(get(auth, "?version=2"), 409)
}

func TestOwnerMessageV2OperationFailures(t *testing.T) {
	for _, stage := range []string{"prepare", "inbox", "receipt", "ack"} {
		t.Run(stage, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newFirstUseHTTPV2(t, nil)
			assert.Equal(deviceRequest(f.owner, f.auth, "POST", firstUsePath,
				`{"version":2}`).Code, 200)
			f.peer = peerapi.NewMessageHandler(f.bob.receiveMessageLocal, f.peer)
			switch stage {
			case "prepare":
				// Outgoing and envelope may persist, but sent must authorize
				// the attempt before preparation can be called successful.
				f.requesterVault.lease.remaining.Store(2)
			case "inbox":
				f.lease.remaining.Store(0)
			case "receipt":
				// Admission and receipt usability probes succeed; signing
				// then fails with the inbox already committed.
				failAt := f.signer.signs.Load() + 3
				f.signer.sign = func(data []byte) ([]byte, error) {
					if f.signer.signs.Load() == failAt {
						return nil, errors.New("private receipt signer diagnostic")
					}
					return f.signer.Handle.Sign(data)
				}
			case "ack":
				f.requesterVault.lease.remaining.Store(3)
			}
			w := deviceRequest(f.owner, f.auth, "POST", messageSendPath,
				`{"version":2,"text":"private message diagnostic"}`)
			want := http.StatusBadGateway
			if stage == "prepare" {
				want = http.StatusConflict
			}
			assert.Equal(w.Code, want)
			assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
			rows := messageSendRows(t, f.requesterVault.vault)
			assert.SNotEmpty(rows[0])
			assert.SNotEmpty(rows[1])
			assert.Equal(len(rows[2]) > 0, stage != "prepare")
			assert.SNil(rows[3])
			inbox := try.To1(pw.ReadMessageInboxV2(f.vault, f.root, f.child))
			assert.Equal(inbox.Present, stage == "receipt" || stage == "ack")
		})
	}
}
