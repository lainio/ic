package ownerapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/storage"
)

func TestOwnerMessageSendPreparationLocksAndSignerFailures(t *testing.T) {
	for step := range int32(4) {
		t.Run(fmt.Sprint(step+1), func(t *testing.T) {
			defer assert.PushTester(t)()
			f, h, auth, target := messageSendOwner(t)
			var posts atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter,
				*http.Request,
			) {
				posts.Add(1)
			}))
			defer s.Close()
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			blockAt := f.signer.signs.Load() + step + 1
			f.signer.sign = func(data []byte) ([]byte, error) {
				if f.signer.signs.Load() == blockAt {
					close(entered)
					<-release
					return nil, errors.New("private signer diagnostic")
				}
				return f.signer.Handle.Sign(data)
			}
			body := messageSendBody(t, "private text",
				s.URL+"/peer/pw/message")
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				done <- deviceRequest(h, auth, "POST", messageSendPath, body)
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("preparation did not reach signer")
			}
			locked := target.mutations.TryLock()
			if locked {
				target.mutations.Unlock()
			}
			assert.ThatNot(locked)
			txDone := make(chan error, 1)
			go func() {
				txDone <- f.vault.Update(func(storage.WriteTx) error {
					return nil
				})
			}()
			select {
			case err := <-txDone:
				assert.NoError(err)
			case <-time.After(5 * time.Second):
				t.Fatal("signer held Vault transaction")
			}
			unblock()
			assert.Equal(waitAcceptance(t, done).Code, 409)
			assert.Equal(posts.Load(), 0)
			rows := messageSendRows(t, f.vault)
			assert.Equal(len(rows[0]) > 0, step > 0)
			assert.Equal(len(rows[1]) > 0, step == 3)
			assert.SNil(rows[2])
			assert.SNil(rows[3])
		})
	}
}

func TestOwnerMessageSendCancellationAtLocalBoundaries(t *testing.T) {
	for _, when := range []string{"waiting for lock", "after preparation"} {
		t.Run(when, func(t *testing.T) {
			defer assert.PushTester(t)()
			f, h, auth, target := messageSendOwner(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var posts atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter,
				*http.Request,
			) {
				posts.Add(1)
			}))
			defer s.Close()
			if when == "after preparation" {
				lastProbe := f.signer.signs.Load() + 4
				f.signer.sign = func(data []byte) ([]byte, error) {
					if f.signer.signs.Load() == lastProbe {
						cancel()
					}
					return f.signer.Handle.Sign(data)
				}
			} else {
				target.mutations.Lock()
			}
			body := messageSendBody(t, "retained",
				s.URL+"/peer/pw/message")
			r := httptest.NewRequestWithContext(ctx, "POST", messageSendPath,
				strings.NewReader(body))
			r.Header.Set("Authorization", auth)
			r.Header.Set("Content-Type", "application/json")
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				done <- w
			}()
			if when == "waiting for lock" {
				cancel()
				target.mutations.Unlock()
			}
			w := waitAcceptance(t, done)
			assert.Equal(w.Code, 409)
			assert.Equal(w.Body.String(), "Conflict\n")
			assert.Equal(posts.Load(), 0)
			rows := messageSendRows(t, f.vault)
			for i := range 3 {
				assert.Equal(len(rows[i]) > 0, when == "after preparation")
			}
			assert.SNil(rows[3])
		})
	}
}
