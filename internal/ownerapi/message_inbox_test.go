package ownerapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/storage"
)

func TestOwnerMessageInboxStrictGET(t *testing.T) {
	defer assert.PushTester(t)()
	f, h, auth, target := messageSendOwner(t)
	f.lease.remaining.Store(0)
	defer f.unchanged(t)()
	signs := f.signer.signs.Load()
	for _, mode := range []string{"valid", "no auth", "wrong auth",
		"duplicate auth", "POST", "HEAD", "PUT", "DELETE", "OPTIONS",
		"suffix", "prefix", "case", "raw path", "opaque", "query", "empty query",
		"fragment", "raw fragment", "encoding", "transfer header", "transfer",
		"trailer header", "trailer", "body", "unknown length", "length",
		"body selector", "empty body stream", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			r := httptest.NewRequest("GET", messageInboxPath, nil)
			r.Header.Set("Authorization", auth)
			want := 400
			switch mode {
			case "valid":
				want = 200
			case "no auth":
				r.Header.Del("Authorization")
				want = 401
			case "wrong auth":
				r.Header.Set("Authorization", "Bearer wrong")
				want = 401
			case "duplicate auth":
				r.Header.Add("Authorization", auth)
				want = 401
			case "POST", "HEAD", "PUT", "DELETE", "OPTIONS":
				r.Method, want = mode, 405
			case "suffix":
				r.URL.Path += "/"
				want = 404
			case "prefix":
				r.URL.Path = "/x" + r.URL.Path
				want = 404
			case "case":
				r.URL.Path = "/owner/pw/message/Inbox"
				want = 404
			case "raw path":
				r.URL.RawPath = "/owner/pw/message/%69nbox"
				want = 404
			case "opaque":
				r.URL.Opaque = "//localhost" + messageInboxPath
				want = 404
			case "query":
				r.URL.RawQuery = "peer=secret"
			case "empty query":
				r.URL.ForceQuery = true
			case "fragment":
				r.URL.Fragment = "x"
			case "raw fragment":
				r.URL.RawFragment = "%78"
			case "encoding":
				r.Header.Set("Content-Encoding", "identity")
			case "transfer header":
				r.Header.Set("Transfer-Encoding", "chunked")
			case "transfer":
				r.TransferEncoding = []string{"chunked"}
			case "trailer header":
				r.Header.Set("Trailer", "X-Test")
			case "trailer":
				r.Trailer = http.Header{"X-Test": nil}
			case "body":
				body := &ownerStatusUnreadBody{}
				r.Body = io.NopCloser(body)
				defer func() { assert.Equal(body.reads, 0) }()
			case "body selector":
				r.Body = io.NopCloser(strings.NewReader(`{"peer":"x"}`))
			case "empty body stream":
				r.Body = io.NopCloser(strings.NewReader(""))
			case "unknown length":
				r.ContentLength = -1
			case "length":
				r.ContentLength = 1
			case "canceled":
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				r = r.WithContext(ctx)
				want = 409
			}
			w := &establishmentWriter{ResponseRecorder: httptest.NewRecorder(),
				onHeader: func() {
					assert.That(target.mutations.TryLock())
					target.mutations.Unlock()
				}}
			h.ServeHTTP(w, r)
			assert.Equal(w.Code, want)
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
			if want == 200 {
				assert.Equal(w.Body.String(), `{"present":false}`)
				assert.Equal(w.Header().Get("Content-Type"), "application/json")
			} else {
				assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
			}
			if want == 405 {
				assert.Equal(w.Header().Get("Allow"), "GET")
			}
			assert.Equal(w.Header().Get("WWW-Authenticate") != "", want == 401)
		})
	}
	assert.Equal(f.signer.signs.Load(), signs)
}

func TestOwnerMessageInboxSensitiveRefusal(t *testing.T) {
	defer assert.PushTester(t)()
	f, h, auth, _ := messageSendOwner(t)
	for _, name := range []string{"local-pw-message-inbox-v1",
		"local-pw-accepted-v1", "local-pw-use-seen-v1"} {
		try.To(f.vault.Update(func(tx storage.WriteTx) error {
			return tx.Put([]byte(name), []byte("PRIVATE_INBOX_MARKER"))
		}))
		func() {
			defer assert.PushTester(t)()
			defer f.unchanged(t)()
			r := httptest.NewRequest("GET", messageInboxPath, nil)
			r.Header.Set("Authorization", auth)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			assert.Equal(w.Code, 409)
			assert.Equal(w.Body.String(), "Conflict\n")
			// Status must not inspect the corrupt inbox/history.
			assert.Equal(
				deviceRequest(h, auth, "GET", "/owner/status", "").Code,
				200,
			)
		}()
	}
}

func TestOwnerMessageInboxDiagnostics(t *testing.T) {
	defer assert.PushTester(t)()
	cmd := exec.CommandContext(
		t.Context(),
		try.To1(os.Executable()),
		"-test.run=^TestOwnerMessageInbox(SensitiveRefusal|OutputFailureDoesNotLogPlaintext)$",
		"-test.count=1",
		"-test.timeout=30s",
		"-v=1",
		"-logtostderr=true",
	)
	output, err := cmd.CombinedOutput()
	assert.NoError(err, "diagnostic subprocess failed")
	assert.ThatNot(strings.Contains(string(output), "PRIVATE_INBOX_MARKER"))
	assert.ThatNot(
		strings.Contains(string(output), "local message inbox read refused"),
	)
}

func TestOwnerMessageInboxOutputFailureDoesNotLogPlaintext(t *testing.T) {
	defer assert.PushTester(t)()
	f, h, auth, _ := messageSendOwner(t)
	defer f.unchanged(t)()
	r := httptest.NewRequest("GET", messageInboxPath, nil)
	r.Header.Set("Authorization", auth)
	w := &inboxFailWriter{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(w, r)
	assert.Equal(w.Code, 200)
	assert.Equal(w.writes, 1)
}

type inboxFailWriter struct {
	*httptest.ResponseRecorder
	writes int
}

func (w *inboxFailWriter) Write(b []byte) (int, error) {
	w.writes++
	return 0, fmt.Errorf("PRIVATE_INBOX_MARKER: %s", b)
}
