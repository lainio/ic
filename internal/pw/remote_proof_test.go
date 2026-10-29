package pw_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
)

func TestRequestRemoteAcceptanceRejectsWrongProofs(t *testing.T) {
	for _, mode := range []string{"forged", "roles", "nonce", "replay"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			var f *exchangeFixture
			var prior []byte
			var accepts atomic.Int64
			workerErrors := make(chan error, 4)
			f = newExchange(t, func(next http.Handler) http.Handler {
				return http.HandlerFunc(
					func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path != acceptPath {
							next.ServeHTTP(w, r)
							return
						}
						call := accepts.Add(1)
						body, err := io.ReadAll(r.Body)
						if err != nil {
							workerErrors <- err
							w.WriteHeader(500)
							return
						}
						r.Body = io.NopCloser(bytes.NewReader(body))
						reply := httptest.NewRecorder()
						next.ServeHTTP(
							reply,
							r,
						) // Genuine handler consumes and signs first.
						var response struct {
							Version int           `json:"version"`
							Proof   key.Signature `json:"acceptor_proof"`
						}
						if err := json.Unmarshal(reply.Body.Bytes(), &response); err != nil {
							workerErrors <- err
							w.WriteHeader(500)
							return
						}
						var request struct {
							Challenge []byte
							Proof     key.Signature `json:"requester_proof"`
						}
						if err := json.Unmarshal(body, &request); err != nil {
							workerErrors <- err
							w.WriteHeader(500)
							return
						}
						switch mode {
						case "forged":
							response.Proof[len(response.Proof)-1] ^= 1
						case "roles":
							response.Proof = request.Proof
						case "nonce":
							request.Challenge[0] ^= 1
							response.Proof, err = pw.ProveLocalAcceptance(
								f.b.store.Vault(),
								f.root,
								f.b.public,
								f.a.public,
								f.b.signer,
								request.Challenge,
							)
							if err != nil {
								workerErrors <- err
								w.WriteHeader(500)
								return
							}
						case "replay":
							if call == 1 {
								prior = bytes.Clone(response.Proof)
							} else {
								response.Proof = prior
							}
						}
						data, err := json.Marshal(response)
						if err != nil {
							workerErrors <- err
							w.WriteHeader(500)
							return
						}
						reply.Body = bytes.NewBuffer(data)
						copyReply(w, reply)
					},
				)
			})
			before := f.snapshot(t)
			if mode == "replay" {
				try.To(f.request(t.Context()))
			}
			assert.Equal(f.request(t.Context()), pw.ErrRemoteAcceptance)
			want := int64(1)
			if mode == "replay" {
				want++
			}
			assert.Equal(accepts.Load(), want)
			select {
			case err := <-workerErrors:
				assert.NoError(err)
			default:
			}
			assert.DeepEqual(f.snapshot(t), before)
		})
	}
}

func TestRequestRemoteAcceptanceLostAcknowledgementNeverRetries(t *testing.T) {
	defer assert.PushTester(t)()
	var challenges, accepts atomic.Int64
	var mu sync.Mutex
	var nonces [][]byte
	workerErrors := make(chan error, 4)
	f := newExchange(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == challengePath {
				challenges.Add(1)
			}
			if r.URL.Path != acceptPath {
				next.ServeHTTP(w, r)
				return
			}
			call := accepts.Add(1)
			body, err := io.ReadAll(r.Body)
			if err != nil {
				workerErrors <- err
				w.WriteHeader(500)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			reply := httptest.NewRecorder()
			next.ServeHTTP(reply, r)
			var request struct{ Challenge []byte }
			if err := json.Unmarshal(body, &request); err != nil {
				workerErrors <- err
				w.WriteHeader(500)
				return
			}
			mu.Lock()
			nonces = append(nonces, request.Challenge)
			mu.Unlock()
			if reply.Code != 200 {
				copyReply(w, reply)
				return
			}
			if call > 1 {
				copyReply(w, reply)
				return
			}
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				workerErrors <- err
				return
			}
			if err := connection.Close(); err != nil {
				workerErrors <- err
			}
		})
	})
	before := f.snapshot(t)
	assert.Equal(f.request(t.Context()), pw.ErrRemoteAcceptance)
	assert.Equal(challenges.Load(), int64(1))
	assert.Equal(accepts.Load(), int64(1))
	assert.DeepEqual(f.snapshot(t), before)
	// Only a new explicit invocation starts again, with a different challenge.
	try.To(f.request(t.Context()))
	assert.Equal(challenges.Load(), int64(2))
	assert.Equal(accepts.Load(), int64(2))
	mu.Lock()
	observed := append([][]byte(nil), nonces...)
	mu.Unlock()
	assert.Equal(len(observed), 2)
	assert.ThatNot(bytes.Equal(observed[0], observed[1]))
	for _, nonce := range observed {
		assertAcceptanceSignedOnce(t, f, nonce)
	}
	select {
	case err := <-workerErrors:
		assert.NoError(err)
	default:
	}
	assert.DeepEqual(f.snapshot(t), before)
}

func TestRequestRemoteAcceptancePreservesListenerScope(t *testing.T) {
	defer assert.PushTester(t)()
	f := newExchange(t, nil)
	before := f.snapshot(t)
	try.To(f.request(t.Context()))
	for _, path := range []string{"/peer/introduction", "/peer/ad"} {
		w := httptest.NewRecorder()
		f.server.Config.Handler.ServeHTTP(w,
			httptest.NewRequestWithContext(t.Context(), "GET", path, nil))
		assert.Equal(w.Code, 200)
	}
	for _, path := range []string{challengePath, acceptPath, "/peer/ad/proof"} {
		w := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(
			t.Context(),
			"POST",
			path,
			nil,
		)
		request.Header.Set("Authorization", f.ownerAuth)
		f.owner.ServeHTTP(w, request)
		assert.Equal(w.Code, 404)
	}
	for _, path := range []string{"/owner/pw/accept", "/owner/pw/request",
		"/owner/status", "/owner/ads/verify"} {
		w := httptest.NewRecorder()
		f.server.Config.Handler.ServeHTTP(w,
			httptest.NewRequestWithContext(t.Context(), "POST", path, nil))
		assert.Equal(w.Code, 404)
	}
	assert.DeepEqual(f.snapshot(t), before)
}
