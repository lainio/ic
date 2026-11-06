package pw_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/ownerapi"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/storage"
)

const ownerMessageInboxPath = "/owner/pw/message/inbox"

func getOwnerInbox(h http.Handler, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", ownerMessageInboxPath, nil)
	r.Header.Set("Authorization", auth)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestOwnerMessageInboxEitherFirstAndReopen(t *testing.T) {
	for _, bobFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(bobFirst), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOwnerMessage(t, bobFirst)
			s, r := f.sender, f.receiver
			text := "Hello \"owner\" <&>\nHei, 世界!"
			message := try.To1(pw.CreateOutgoingForTest(s.store.Vault(),
				f.root, s.public, s.signer, text))
			raw := try.To1(pw.PrepareMessageEnvelopeForTest(s.store.Vault(),
				f.root, s.public, s.signer))
			assert.That(try.To1(pw.AdmitIncomingEnvelopeForTest(r.store.Vault(),
				f.root, r.public, r.signer, raw)))
			var saved struct {
				_       struct{} `cbor:",toarray"`
				Version uint8
				ID      []byte
				Binding any
				Text    string
			}
			try.To(wire.DecMode.Unmarshal(message, &saved))
			assert.Equal(len(saved.ID), 16)
			assert.That(saved.ID[6]>>4 == 4 && saved.ID[8]>>6 == 2)
			for _, reopen := range []bool{false, true} {
				if reopen {
					f.reopen(t)
					// Signer loss and a disabled peer capability cannot prevent
					// the owner from reading already committed plaintext.
					h, file, bind := try.To3(ownerapi.NewFirstUseCredentials(
						t.Context(), r.store.Vault(), f.root, r.public, nil,
						t.TempDir()))
					bind(nil)
					f.receiverOwner, f.receiverAuth = h, ownerMessageAuth(
						t,
						file,
					)
					h, file, bind = try.To3(ownerapi.NewFirstUseCredentials(
						t.Context(), s.store.Vault(), f.root, s.public, nil,
						t.TempDir()))
					bind(nil)
					f.owner, f.auth = h, ownerMessageAuth(t, file)
				}
				before := f.snapshot(t)
				signs := len(s.signer.signed()) + len(r.signer.signed())
				for _, auth := range []string{"", f.auth} {
					w := getOwnerInbox(f.receiverOwner, auth)
					assert.Equal(w.Code, 401)
					assert.Equal(w.Body.String(), "Unauthorized\n")
				}
				w := getOwnerInbox(f.receiverOwner, f.receiverAuth)
				assert.Equal(w.Code, 200)
				assert.Equal(w.Header().Get("Cache-Control"), "no-store")
				assert.Equal(w.Header().Get("Content-Type"), "application/json")
				assert.That(w.Body.Len() <= 2048)
				var doc map[string]any
				d := json.NewDecoder(w.Body)
				try.To(d.Decode(&doc))
				assert.DeepEqual(doc, map[string]any{"present": true,
					"message_id_hex": hex.EncodeToString(
						saved.ID,
					), "text": text})
				assert.Equal(d.Decode(&doc), io.EOF)
				w = getOwnerInbox(f.owner, f.auth)
				assert.Equal(w.Code, 200)
				assert.Equal(w.Body.String(), `{"present":false}`)
				assert.DeepEqual(f.snapshot(t), before)
				assert.Equal(
					len(s.signer.signed())+len(r.signer.signed()),
					signs,
				)
				assert.Equal(f.posts.Load(), 0)
			}
			want := getOwnerInbox(f.receiverOwner, f.receiverAuth).Body.String()
			for _, change := range []string{"deny", "delete", "Known/device"} {
				switch change {
				case "deny":
					try.To(ownerMessageMutation(f.receiverOwner, f.receiverAuth,
						"/owner/policy/deny", `{"peer_public_key_hex":"`+
							hex.EncodeToString(s.public)+`"}`))
				case "delete":
					try.To(ownerMessageMutation(f.receiverOwner, f.receiverAuth,
						"/owner/pw/holding/delete", "{}"))
				default:
					try.To(
						r.store.Vault().
							Update(func(tx storage.WriteTx) (err error) {
								defer err2.Handle(&err, nil)
								known := try.To1(
									tx.ChildForUpdate(
										[]byte("known-introductions-v1"),
									),
								)
								try.To(known.Delete(r.public))
								try.To(known.Delete(s.public))
								return try.To1(tx.ChildForUpdate([]byte("local-device-auth-v1"))).
									Delete([]byte("local-software-signer"))
							}),
					)
				}
				before := f.snapshot(t)
				w := getOwnerInbox(f.receiverOwner, f.receiverAuth)
				assert.Equal(w.Code, 200)
				assert.Equal(w.Body.String(), want)
				assert.DeepEqual(f.snapshot(t), before)
				assert.Equal(f.posts.Load(), 0)
			}
		})
	}
}

func TestOwnerMessageInboxEscapingAndResponseBound(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		status     int
		size       int
	}{
		{"UTF8 limit", strings.Repeat("é", 512), 200, 0},
		// JSON overhead is 78 bytes; 328 NULs + 2 ASCII bytes reach 2 KiB.
		{"exact response limit", strings.Repeat("\x00", 328) + "ab", 200, 2048},
		{"over response limit", strings.Repeat("\x00", 328) + "abc", 409, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOwnerMessage(t, false)
			s, r := f.sender, f.receiver
			try.To1(pw.CreateOutgoingForTest(s.store.Vault(), f.root,
				s.public, s.signer, tc.text))
			raw := try.To1(pw.PrepareMessageEnvelopeForTest(s.store.Vault(),
				f.root, s.public, s.signer))
			assert.That(try.To1(pw.AdmitIncomingEnvelopeForTest(r.store.Vault(),
				f.root, r.public, r.signer, raw)))
			before := f.snapshot(t)
			w := getOwnerInbox(f.receiverOwner, f.receiverAuth)
			assert.Equal(w.Code, tc.status)
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
			assert.That(w.Body.Len() <= 2048)
			if tc.size != 0 {
				assert.Equal(w.Body.Len(), tc.size)
			}
			if tc.status == 200 {
				var doc struct{ Text string }
				try.To(json.Unmarshal(w.Body.Bytes(), &doc))
				assert.Equal(doc.Text, tc.text)
			} else {
				assert.Equal(w.Body.String(), "Conflict\n")
			}
			assert.DeepEqual(f.snapshot(t), before)
			assert.Equal(f.posts.Load(), 0)
		})
	}
}
