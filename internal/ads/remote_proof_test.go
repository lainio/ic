package ads_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestVerifyRemoteProofRefusalsPreserveHistory(t *testing.T) {
	for _, scenario := range []string{"no current", "superseded", "wrong endpoint", "unauthorized", "unusable",
		"nonce", "cached proof", "different ad", "wrong subject", "wrong Root", "changed proof", "forged proof"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRemote(t)
			assert.That(try.To1(f.verify(t.Context())))
			historic := f.ad
			candidate := f.publish(t, time.Now())
			try.To1(ads.ReceiveClaim(f.receiver.Vault(), f.root.public, f.peer.public, candidate))
			configureProofFailure(t, f, scenario, candidate)
			f.publisher.Unchanged(t, func() {
				f.receiver.Unchanged(t, func() {
					changed, err := f.verify(t.Context())
					assert.ThatNot(changed)
					assert.Error(err)
					f.readVerified(t, historic)
				})
			})
			assert.Equal(f.calls.Load(), int32(2))
		})
	}
}

func configureProofFailure(t *testing.T, f *remoteFixture, scenario string, candidate []byte) {
	t.Helper()
	defer assert.PushTester(t)()
	switch scenario {
	case "no current", "unauthorized":
		empty := ads.NewTestVault(t)
		if scenario == "unauthorized" {
			// Valid publication/Known evidence with no device authorization.
			state := try.To1(remoteState(f.publisher.Vault(), false))
			try.To(empty.Vault().Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				for _, name := range []string{"local-current-ad-v1", "known-introductions-v1", "received-introductions-v1"} {
					ns := try.To1(tx.EnsureChild([]byte(name)))
					for k, value := range state {
						if strings.HasPrefix(k, name+"/") {
							try.To(ns.Put([]byte(strings.TrimPrefix(k, name+"/")), value))
						}
					}
				}
				return nil
			}))
		}
		f.setProof(func(ad, nonce []byte) (key.Signature, error) {
			return ads.ProveCurrentLocal(empty.Vault(), f.root.public, f.peer.public, f.peer.handle, f.endpoint, ad, nonce, time.Now())
		})
	case "superseded":
		f.publish(t, time.Now())
	case "wrong endpoint", "unusable":
		bound, signer := f.endpoint, f.peer.handle
		if scenario == "wrong endpoint" {
			bound = "http://127.0.0.1:1/peer/introduction"
		} else {
			signer = nil
		}
		f.setProof(func(ad, nonce []byte) (key.Signature, error) {
			return ads.ProveCurrentLocal(f.publisher.Vault(), f.root.public, f.peer.public, signer, bound, ad, nonce, time.Now())
		})
	case "nonce":
		f.setProof(func(ad, nonce []byte) (key.Signature, error) { nonce[0] ^= 1; return f.currentProof(ad, nonce) })
	case "cached proof":
		cached := try.To1(f.currentProof(candidate, bytes.Repeat([]byte{7}, 32)))
		f.setProof(func([]byte, []byte) (key.Signature, error) { return cached, nil })
	case "different ad":
		latest := f.publish(t, time.Now())
		f.setProof(func(_ []byte, nonce []byte) (key.Signature, error) { return f.currentProof(latest, nonce) })
	case "wrong subject", "wrong Root":
		root, subject := f.root.public, f.peer.public
		other := remoteKey(t)
		if scenario == "wrong Root" {
			root = other.public
		} else {
			subject = other.public
		}
		f.setProof(func(ad, nonce []byte) (key.Signature, error) {
			// Even the expected signer's signature must fail when the proof
			// payload's independently expected identity binding differs.
			digest, err := ads.ProofDigestForTest(root, subject, ad, nonce)
			if err != nil {
				return nil, err
			}
			return f.peer.handle.Sign(digest[:])
		})
	case "changed proof":
		f.setProof(func(ad, nonce []byte) (key.Signature, error) {
			proof, err := f.currentProof(ad, nonce)
			if err == nil {
				proof[len(proof)-1] ^= 1
			}
			return proof, err
		})
	case "forged proof":
		f.setProof(func([]byte, []byte) (key.Signature, error) { return []byte{1, 2, 3}, nil })
	}
}

func TestVerifyRemoteHostileHTTP(t *testing.T) {
	cases := []string{"redirect", "status", "content type", "duplicate content type", "compressed",
		"oversized headers", "trailers", "unannounced trailers", "oversized trailers",
		"oversized body", "chunked oversized body", "truncated body", "malformed status", "malformed header",
		"malformed JSON", "unknown field", "duplicate version", "duplicate proof", "float", "exponent", "invalid UTF8",
		"trailing JSON", "empty proof", "oversized proof", "unpadded base64", "nonzero pad bits", "base64 newline", "nonstring proof"}
	for _, scenario := range cases {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRemote(t)
			assert.That(try.To1(f.verify(t.Context())))
			f.setResponse(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				recorded := newProofRecorder(next, r)
				if recorded.Code != http.StatusOK {
					t.Error("fixture proof failed")
				}
				mutateProofHTTP(t, scenario, w, r, recorded.Body.String(), f.server.URL)
			})
			var trace bytes.Buffer
			oldError, oldReturn := err2.ErrorTracer(), err2.ErrRetTracer()
			err2.SetErrorTracer(&trace)
			err2.SetErrRetTracer(&trace)
			defer func() { err2.SetErrorTracer(oldError); err2.SetErrRetTracer(oldReturn) }()
			f.receiver.Unchanged(t, func() {
				changed, err := f.verify(t.Context())
				assert.ThatNot(changed)
				assert.Error(err)
				assert.ThatNot(strings.Contains(err.Error(), "PRIVATE_PEER_BYTES"))
				f.readVerified(t, f.ad)
			})
			assert.ThatNot(strings.Contains(trace.String(), "PRIVATE_PEER_BYTES"))
			assert.Equal(f.calls.Load(), int32(2)) // No retry or redirect.
		})
	}
}

func mutateProofHTTP(t *testing.T, scenario string, w http.ResponseWriter, r *http.Request, body, base string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	switch scenario {
	case "redirect":
		http.Redirect(w, r, base+"/owner/PRIVATE_PEER_BYTES", http.StatusTemporaryRedirect)
		return
	case "status":
		http.Error(w, "PRIVATE_PEER_BYTES", http.StatusConflict)
		return
	case "content type":
		w.Header().Set("Content-Type", "text/PRIVATE_PEER_BYTES")
	case "duplicate content type":
		w.Header().Add("Content-Type", "application/json")
	case "compressed":
		w.Header().Set("Content-Encoding", "gzip")
	case "oversized headers":
		w.Header().Set("X-Private", strings.Repeat("PRIVATE_PEER_BYTES", 100))
	case "trailers":
		w.Header().Set("Trailer", "X-Private")
	case "oversized body":
		body += strings.Repeat(" ", 1025)
	case "chunked oversized body":
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		body += strings.Repeat(" ", 1025)
	case "truncated body":
		w.Header().Set("Content-Length", "1024")
	case "malformed status", "malformed header", "unannounced trailers", "oversized trailers":
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close() }()
		raw := "HTTP/1.1 PRIVATE_PEER_BYTES\r\n\r\n"
		if scenario == "malformed header" {
			raw = "HTTP/1.1 200 OK\r\nPRIVATE_PEER_BYTES\r\n\r\n"
		}
		if strings.HasSuffix(scenario, "trailers") {
			trailer := "PRIVATE_PEER_BYTES"
			if scenario == "oversized trailers" {
				trailer = strings.Repeat(trailer, 100)
			}
			raw = fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\nX-Private: %s\r\n\r\n", len(body), body, trailer)
		}
		_, _ = rw.WriteString(raw)
		_ = rw.Flush()
		return
	case "malformed JSON":
		body = `{"PRIVATE_PEER_BYTES":`
	case "unknown field":
		body = strings.TrimSuffix(body, "}") + `,"PRIVATE_PEER_BYTES":"PRIVATE_PEER_BYTES"}`
	case "duplicate version":
		body = strings.TrimSuffix(body, "}") + `,"version":1}`
	case "duplicate proof":
		body = strings.TrimSuffix(body, "}") + `,"proof":"AQ=="}`
	case "float":
		body = strings.Replace(body, `"version":1`, `"version":1.0`, 1)
	case "exponent":
		body = strings.Replace(body, `"version":1`, `"version":1e0`, 1)
	case "invalid UTF8":
		body = "\xff" + body
	case "trailing JSON":
		body += `{}`
	case "empty proof":
		body = `{"version":1,"proof":""}`
	case "oversized proof":
		body = `{"version":1,"proof":"` + base64.StdEncoding.EncodeToString(make([]byte, 73)) + `"}`
	case "unpadded base64":
		body = `{"version":1,"proof":"AQ"}`
	case "nonzero pad bits":
		body = `{"version":1,"proof":"AB=="}`
	case "base64 newline":
		body = `{"version":1,"proof":"AQ==\n"}`
	case "nonstring proof":
		body = `{"version":1,"proof":null}`
	}
	_, _ = w.Write([]byte(body))
}

func TestVerifyRemoteSlowResponseAndCancellation(t *testing.T) {
	for _, scenario := range []string{"five second limit", "shorter deadline", "cancel before body"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRemote(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if scenario == "shorter deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 50*time.Millisecond)
				defer stop()
			}
			f.setResponse(func(w http.ResponseWriter, r *http.Request, _ http.Handler) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				if scenario == "cancel before body" {
					cancel()
				}
				<-r.Context().Done()
			})
			start := time.Now()
			f.receiver.Unchanged(t, func() {
				changed, err := f.verify(ctx)
				assert.ThatNot(changed)
				assert.Error(err)
				f.readVerified(t, nil)
			})
			assert.That(time.Since(start) < 7*time.Second)
			assert.Equal(f.calls.Load(), int32(1))
		})
	}
}

func TestVerifyRemoteExpiryWhileProofInFlight(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRemote(t)
	// Real publisher expiry; the receiver still owns its clock. A timer, not an
	// injected clock or a sleep, advances past the signed expiry during delivery.
	candidate := f.publish(t, time.Now().Add(-ads.TTL+time.Second))
	try.To1(ads.ReceiveClaim(f.receiver.Vault(), f.root.public, f.peer.public, candidate))
	var current ads.Current
	try.To(wire.UnmarshalCanonical(&current, candidate))
	f.setResponse(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		recorded := newProofRecorder(next, r)
		if recorded.Code != 200 {
			t.Error("proof must be produced before expiry")
		}
		timer := time.NewTimer(time.Until(time.Unix(0, current.Payload.ExpiresUnixNano)))
		defer timer.Stop()
		select {
		case <-timer.C:
			copyProofResponse(w, recorded)
		case <-r.Context().Done():
		}
	})
	f.receiver.Unchanged(t, func() {
		changed, err := f.verify(t.Context())
		assert.ThatNot(changed)
		assert.ErrorIs(err, ads.ErrInvalidRecord)
		f.readVerified(t, nil)
	})
}
