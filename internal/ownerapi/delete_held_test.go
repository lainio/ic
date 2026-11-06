package ownerapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/storage"
)

func TestDeleteHeldStrictBodyNoWritesOrSigning(t *testing.T) {
	defer assert.PushTester(t)()
	f := newEstablishmentOwner(t)
	h, auth := deleteHeldCredential(t, f.vault, f.root, f.child, f.signer)
	defer f.unchanged(t)()
	signs := f.signer.signs.Load()
	for _, tc := range []struct {
		body   string
		status int
	}{
		{"{}", 200}, {" \t{}\r\n", 200}, {"{ }", 400}, {"", 400},
		{"null", 400}, {"[]", 400}, {"{}{}", 400}, {"{}x", 400},
		{"{}\x00", 400}, {"\xef\xbb\xbf{}", 400}, {"\xff{}", 400},
		{`{"peer":"x","peer":"x"}`, 400}, {`{"root":"x"}`, 400},
		{`{"invitation":"x"}`, 400}, {`{"attempt":"x"}`, 400},
		{`{"endpoint":"x"}`, 400}, {`{"clock":1}`, 400},
		{`{"signer":"x"}`, 400}, {`{"scope":"all"}`, 400},
		{strings.Repeat(" ", 63) + "{}", 413},
		{strings.Repeat(" ", 62) + "{}", 200},
	} {
		w := deviceRequest(h, auth, "POST", deleteHeldPath, tc.body)
		assert.Equal(w.Code, tc.status)
		if tc.status == 200 {
			assert.Equal(w.Body.String(), `{"deleted":false}`)
		} else {
			assert.Equal(w.Body.String(), http.StatusText(tc.status)+"\n")
		}
	}
	for _, mode := range []string{"nil body", "encoding", "trailer", "actual trailer", "cancel"} {
		r := httptest.NewRequest(
			"POST",
			deleteHeldPath,
			strings.NewReader("{}"),
		)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", auth)
		want := 400
		switch mode {
		case "nil body":
			r.Body = nil
		case "encoding":
			r.Header.Set("Content-Encoding", "gzip")
		case "trailer":
			r.Header.Set("Trailer", "X-Secret")
		case "actual trailer":
			r.Trailer = http.Header{"X-Secret": {"x"}}
		case "cancel":
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			r = r.WithContext(ctx)
			want = 409
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assert.Equal(w.Code, want)
	}
	reader := strings.NewReader(strings.Repeat(" ", 1024))
	r := httptest.NewRequest("POST", deleteHeldPath, reader)
	r.ContentLength = 1
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", auth)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(w.Code, 413)
	assert.Equal(reader.Len(), 1024-65)
	assert.Equal(f.signer.signs.Load(), signs)
}

func TestDeleteHeldResponseAfterCommitAndUnlock(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "delivered", true: "lost"}[lost],
			func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newEstablishmentOwner(t)
				assert.Equal(
					deviceRequest(
						f.peer,
						"",
						"POST",
						establishmentPath,
						f.body,
					).Code,
					200,
				)
				h, auth := deleteHeldCredential(
					t,
					f.vault,
					f.root,
					f.child,
					f.signer,
				)
				target := h.(*authenticatedStatusHandler).next.(*firstUseHandler)
				before := f.records(t)
				before[2] = nil
				f.signer.sign = func([]byte) ([]byte, error) { return nil, errors.New("unusable") }
				f.lease.remaining.Store(0)
				signs := f.signer.signs.Load()
				w := &establishmentWriter{
					ResponseRecorder: httptest.NewRecorder(),
					fail:             lost,
					onHeader: func() {
						assert.That(target.mutations.TryLock())
						target.mutations.Unlock()
						assert.DeepEqual(f.records(t), before)
					},
				}
				r := httptest.NewRequest(
					"POST",
					deleteHeldPath,
					strings.NewReader("{}"),
				)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Authorization", auth)
				h.ServeHTTP(w, r)
				assert.Equal(w.Code, 200)
				assert.Equal(w.Body.String(), `{"deleted":true}`)
				assert.Equal(f.lease.remaining.Load(), int64(0))
				assert.Equal(f.signer.signs.Load(), signs)
				defer f.unchanged(t)()
				again := deviceRequest(h, auth, "POST", deleteHeldPath, "{}")
				assert.Equal(again.Code, 200)
				assert.Equal(again.Body.String(), `{"deleted":false}`)
			},
		)
	}
}

func TestDeleteHeldCorruptHTTPDiagnostics(t *testing.T) {
	defer assert.PushTester(t)()
	f := newEstablishmentOwner(t)
	assert.Equal(
		deviceRequest(f.peer, "", "POST", establishmentPath, f.body).Code,
		200,
	)
	try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return tx.Put(
			[]byte("local-pw-accepted-v1"),
			[]byte("PRIVATE_HELD_MARKER"),
		)
	}))
	h, auth := deleteHeldCredential(t, f.vault, f.root, f.child, f.signer)
	defer f.unchanged(t)()
	w := deviceRequest(h, auth, "POST", deleteHeldPath, "{}")
	assert.Equal(w.Code, 409)
	assert.Equal(w.Body.String(), "Conflict\n")
	assert.Equal(w.Header().Get("Cache-Control"), "no-store")
}

// Keep the operational owner and peer capabilities on exactly the same lock.
func heldOwnerTarget(
	t *testing.T,
	f *establishmentOwnerFixture,
) *firstUseHandler {
	t.Helper()
	defer assert.PushTester(t)()
	h, file, bind := try.To3(NewFirstUseCredentials(t.Context(), f.vault,
		f.root, f.child, f.signer, t.TempDir()))
	f.owner = h
	f.auth = strings.TrimSpace(strings.TrimPrefix(
		string(try.To1(os.ReadFile(file))), "Authorization:"))
	target := h.(*authenticatedStatusHandler).next.(*firstUseHandler)
	f.publisher = target.publicationHandler
	prove, _, establish, use, _ := bind(f.listener)
	assert.That(prove != nil)
	f.peer = peerapi.NewFirstUseHandler(use,
		peerapi.NewEstablishmentHandler(establish, http.NotFoundHandler()))
	return target
}
