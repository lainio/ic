package ownerapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func denyBody(peer key.Public) string {
	return `{"peer_public_key_hex":"` + hex.EncodeToString(peer) + `"}`
}

func TestDenyStrictBodyNoWritesOrSigning(t *testing.T) {
	defer assert.PushTester(t)()
	f := newEstablishmentOwner(t)
	h, auth := deleteHeldCredential(t, f.vault, f.root, f.child, f.signer)
	defer f.unchanged(t)()
	signs, publics := f.signer.signs.Load(), f.signer.publics.Load()
	good := denyBody(f.requester)
	for _, body := range []string{
		"", "{}", "null", "[]", good + "{}", good + "x", good + "\x00",
		"\xef\xbb\xbf" + good, "\xff" + good,
		`{"peer_public_key_hex":null}`, `{"peer_public_key_hex":1}`,
		`{"peer_public_key_hex":{}}`, `{"peer_public_key_hex":[]}`,
		`{"peer_public_key_hex":""}`, `{"peer_public_key_hex":"xx"}`,
		`{"peer_public_key_hex":"abc"}`,
		strings.Replace(good, "peer_public_key_hex", "Peer_Public_Key_Hex", 1),
		strings.Replace(good, "peer_public_key_hex", "peer", 1),
		strings.TrimSuffix(good, "}") + `,"peer_public_key_hex":"00"}`,
		strings.TrimSuffix(good, "}") + `,"root":"private"}`,
		strings.TrimSuffix(good, "}") + `,"vault":"private"}`,
		strings.TrimSuffix(good, "}") + `,"local":"private"}`,
		strings.TrimSuffix(good, "}") + `,"allow":true}`,
		strings.Replace(good, hex.EncodeToString(f.requester),
			strings.ToUpper(hex.EncodeToString(f.requester)), 1),
		denyBody(f.child), denyBody([]byte{0xff}), denyBody([]byte{0xa0}),
		denyBody(make([]byte, 129)),
		denyBody(append(bytes.Clone(f.requester), 0)),
		denyBody(append([]byte{0xb8, 5}, f.requester[1:]...)),
	} {
		w := deviceRequest(h, auth, "POST", denyPath, body)
		assert.Equal(w.Code, 400)
		assert.Equal(w.Body.String(), "Bad Request\n")
		assert.Equal(w.Header().Get("Cache-Control"), "no-store")
	}
	for _, mode := range []string{"nil body", "encoding", "trailer",
		"actual trailer", "late trailer", "read error", "cancel"} {
		r := httptest.NewRequest("POST", denyPath, strings.NewReader(good))
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
			r.Trailer = http.Header{"X-Secret": {"private"}}
		case "late trailer", "read error":
			r.Body = &denyTrailerBody{Reader: strings.NewReader(good), r: r,
				fail: mode == "read error"}
		case "cancel":
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			r = r.WithContext(ctx)
			want = 500
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assert.Equal(w.Code, want)
		assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
	}
	reader := strings.NewReader(strings.Repeat(" ", 1024))
	r := httptest.NewRequest("POST", denyPath, reader)
	r.ContentLength = 1
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", auth)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(w.Code, 413)
	assert.Equal(reader.Len(), 1024-513)
	assert.Equal(f.signer.signs.Load(), signs)
	assert.Equal(f.signer.publics.Load(), publics)
}

type denyTrailerBody struct {
	*strings.Reader
	r    *http.Request
	fail bool
}

func (b *denyTrailerBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err == io.EOF {
		if b.fail {
			return n, errors.New("PRIVATE_READ_ERROR")
		}
		b.r.Trailer = http.Header{"X-Secret": {"private"}}
	}
	return n, err
}

func (*denyTrailerBody) Close() error { return nil }

func TestDenyResponseAfterCommitAndExactRetryWithoutAllowance(t *testing.T) {
	defer assert.PushTester(t)()
	f := newEstablishmentOwner(t)
	// No Known relationship is needed; signer availability is irrelevant.
	peer := key.Public(try.To1(key.New().CBORPublicKey()))
	root, local := bytes.Clone(f.root), bytes.Clone(f.child)
	h, auth := deleteHeldCredential(t, f.vault, root, local, f.signer)
	clear(root)
	clear(local)
	target := h.(*authenticatedStatusHandler).next.(*firstUseHandler)
	before := f.records(t)
	f.signer.sign = func([]byte) ([]byte, error) {
		return nil, errors.New("unusable signer")
	}
	signs, publics := f.signer.signs.Load(), f.signer.publics.Load()
	f.lease.remaining.Store(1)
	w := &establishmentWriter{ResponseRecorder: httptest.NewRecorder(),
		fail: true, onHeader: func() {
			assert.That(target.mutations.TryLock())
			target.mutations.Unlock()
			assert.That(
				try.To1(policy.IsDenied(f.vault, f.root, f.child, peer)),
			)
			assert.DeepEqual(f.records(t), before)
		}}
	body := denyBody(peer)
	r := httptest.NewRequest("POST", denyPath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	r.Header.Set("Authorization", auth)
	h.ServeHTTP(w, r)
	assert.Equal(w.Code, 200)
	assert.Equal(w.Body.String(), `{"changed":true}`)
	assert.Equal(w.Header().Get("Content-Type"), "application/json")
	assert.Equal(f.lease.remaining.Load(), int64(0))
	defer f.unchanged(t)()
	for _, padding := range []int{0, 512 - len(body), 513 - len(body)} {
		w := deviceRequest(h, auth, "POST", denyPath,
			strings.Repeat(" ", padding)+body)
		if padding+len(body) > 512 {
			assert.Equal(w.Code, 413)
		} else {
			assert.Equal(w.Code, 200)
			assert.Equal(w.Body.String(), `{"changed":false}`)
		}
	}
	assert.Equal(f.signer.signs.Load(), signs)
	assert.Equal(f.signer.publics.Load(), publics)
}

func TestDenyFailuresAreSanitizedAndNeverRepair(t *testing.T) {
	for _, mode := range []string{"exhausted", "closed", "corrupt",
		"foreign root", "foreign local", "full"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newEstablishmentOwner(t)
			h, auth := deleteHeldCredential(
				t,
				f.vault,
				f.root,
				f.child,
				f.signer,
			)
			want := 500
			switch mode {
			case "exhausted":
				f.lease.remaining.Store(0)
			case "closed":
				try.To(f.vault.Close())
			case "corrupt", "foreign root", "foreign local":
				raw := []byte("PRIVATE_POLICY_MARKER")
				if mode != "corrupt" {
					root, local := f.root, f.child
					if mode == "foreign root" {
						root = f.requester
					} else {
						local = f.requester
					}
					raw = try.To1(
						wire.Marshal([]any{1, root, local, []key.Public{}}),
					)
				}
				try.To(f.vault.Update(func(tx storage.WriteTx) error {
					return tx.Put([]byte("local-denied-peers-v1"), raw)
				}))
			case "full":
				var peer key.Public
				for range 32 {
					peer = key.Public(try.To1(key.New().CBORPublicKey()))
					assert.Equal(deviceRequest(h, auth, "POST", denyPath,
						denyBody(peer)).Code, 200)
				}
				check := f.unchanged(t)
				w := deviceRequest(h, auth, "POST", denyPath, denyBody(peer))
				assert.Equal(w.Code, 200)
				assert.Equal(w.Body.String(), `{"changed":false}`)
				check()
				want = 409
			}
			defer f.unchanged(t)()
			for range 2 {
				w := deviceRequest(
					h,
					auth,
					"POST",
					denyPath,
					denyBody(f.requester),
				)
				assert.Equal(w.Code, want)
				assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
				assert.Equal(w.Header().Get("Cache-Control"), "no-store")
			}
		})
	}
}
