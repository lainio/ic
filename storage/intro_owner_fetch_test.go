package storage_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const fetchPath = "/owner/introductions/fetch"

type fetchPair struct {
	sender, receiver introductionFixture
	root, alice, bob key.Public
	rootSigner       key.Handle
	aliceSigner      *choiceSigningHandle
	proposal         intro.Path
	acceptance       key.Signature
}

func newFetchPair(t *testing.T) fetchPair {
	t.Helper()
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	f := fetchPair{
		root: key.InfoFromHandle(root).Public, alice: key.InfoFromHandle(alice).Public,
		bob: key.InfoFromHandle(bob).Public, rootSigner: root,
		aliceSigner: &choiceSigningHandle{Handle: alice},
	}
	f.sender = newIntroductionFixture(t, f.root, f.alice)
	f.receiver = newIntroductionFixture(t, f.root, f.bob)
	evidenceCredentials(t, &f.receiver, f.root, f.bob)
	f.proposal = intro.New(key.Info{Public: f.root}).Introduce(root, key.Info{Public: f.alice},
		intro.WithEndpoint("http://evidence.invalid/never-fetch", false))
	f.acceptance = try.To1(onboarding.SignAfterStoredChoice(
		f.sender.vault, f.aliceSigner, f.root, f.root, f.proposal,
	))
	return f
}

func fetchRequest(f introductionFixture, endpoint string) *http.Request {
	r := checkRequest(f.authorization, []byte(`{"peer_url":"`+endpoint+`"}`))
	r.URL.Path = fetchPath
	return r
}

func fetchResponse(f introductionFixture, endpoint string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, fetchRequest(f, endpoint))
	return w
}

func assertFetchUnselected(t *testing.T, f fetchPair) {
	t.Helper()
	defer assert.PushTester(t)()

	_, found := try.To2(onboarding.ReadStoredChoice(f.receiver.vault, f.root, f.bob))
	assert.ThatNot(found)
	assert.SEmpty(try.To1(onboarding.ListKnownIntroductions(f.receiver.vault, f.root)))
	try.To(f.receiver.vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		assert.ThatNot(try.To1(tx.HasChild([]byte(knownNamespace))))
		assert.ThatNot(try.To1(tx.HasChild([]byte("introduction-choice-demo"))))
		return nil
	}))
}

func TestOwnerFetchTwoVaultsReceivedOnlyReplayReopen(t *testing.T) {
	defer assert.PushTester(t)()

	f := newFetchPair(t)
	// Unrelated received material on Alice must not enter the exported path.
	other := key.New()
	otherPath := intro.New(key.Info{Public: f.root}).Introduce(f.rootSigner, key.Info{Public: key.InfoFromHandle(other).Public})
	try.To2(onboarding.SaveIntroduction(f.sender.vault, f.root, otherPath.Bytes(),
		try.To1(otherPath.SignAcceptance(other))))
	f.sender.assertReadOnly(t)
	f.aliceSigner.signErr = errors.New("fetch must not sign")
	server := httptest.NewServer(peerapi.NewHandler(f.sender.vault, f.root, f.alice))
	defer server.Close()
	endpoint := server.URL + "/peer/introduction"
	assert.SEmpty(try.To1(onboarding.ListIntroductions(f.receiver.vault, f.root)))
	f.receiver.provider.mu.Lock()
	beforeBudget := f.receiver.provider.remainingEncryptions
	f.receiver.provider.mu.Unlock()
	assertSaved(t, fetchResponse(f.receiver, endpoint), f.alice, false, true)
	f.receiver.provider.mu.Lock()
	afterBudget := f.receiver.provider.remainingEncryptions
	f.receiver.provider.mu.Unlock()
	assert.Equal(afterBudget, beforeBudget-1) // One Received record, no other seals.
	record := try.To1(receivedRecord(f.receiver.vault, f.alice))
	assert.DeepEqual(record[5:5+len(f.proposal.Bytes())], f.proposal.Bytes())
	assert.DeepEqual(record[5+len(f.proposal.Bytes()):], []byte(f.acceptance))
	assertListed(t, f.receiver, f.bob, f.alice)
	assertFetchUnselected(t, f)
	t.Run("replay without encryption or rewrite", func(t *testing.T) {
		defer assert.PushTester(t)()
		f.receiver.assertReadOnly(t)
		assertSaved(t, fetchResponse(f.receiver, endpoint), f.alice, false, false)
		assert.DeepEqual(try.To1(receivedRecord(f.receiver.vault, f.alice)), record)
	})
	assert.Equal(f.aliceSigner.signCalls, 1)
	assert.SEmpty(try.To1(onboarding.ListKnownIntroductions(f.sender.vault, f.root)))
	assert.DeepEqual(try.To1(onboarding.ListIntroductions(f.sender.vault, f.root)),
		[]key.Public{otherPath.LeafPubKey()})

	try.To(f.receiver.vault.Close())
	try.To(f.receiver.db.Close())
	db := try.To1(storage.OpenBolt(f.receiver.path))
	defer func() { try.Out(db.Close()).Logf() }()
	p := f.receiver.provider
	f.receiver.vault = try.To1(db.OpenVault(t.Context(), p.vault, p.id, p))
	defer func() { try.Out(f.receiver.vault.Close()).Logf() }()
	evidenceCredentials(t, &f.receiver, f.root, f.bob)
	f.receiver.assertReadOnly(t)
	assertSaved(t, fetchResponse(f.receiver, endpoint), f.alice, false, false)
	assert.DeepEqual(try.To1(receivedRecord(f.receiver.vault, f.alice)), record)
	assertFetchUnselected(t, f)
}

func TestOwnerFetchPeerFailuresWriteNothing(t *testing.T) {
	defer assert.PushTester(t)()

	f := newFetchPair(t)
	valid := checkDocument(f.proposal, f.acceptance)
	wrongRoot := key.InfoFromHandle(key.New()).Public
	badProof := try.To1(intro.ParsePath(f.proposal.Bytes()))
	badProof[1].Body.Options.Position++
	f.sender.assertReadOnly(t)
	f.receiver.assertReadOnly(t)
	for _, scenario := range []string{
		"wrong root", "bad proof", "bad acceptance", "malformed", "duplicate field",
		"oversize", "chunked oversize", "false length", "truncated", "bad media", "duplicate media",
		"non-200", "redirect", "unavailable", "unselected sender", "pending sender", "self",
	} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()

			var requests atomic.Int32
			peer := peerapi.NewHandler(f.sender.vault, f.root, f.alice)
			if scenario == "unselected sender" || scenario == "pending sender" {
				incomplete := newIntroductionFixture(t, f.root, f.alice)
				if scenario == "pending sender" {
					try.To(incomplete.vault.Update(func(tx storage.WriteTx) (err error) {
						defer err2.Handle(&err, nil)
						ns := try.To1(tx.EnsureChild([]byte("introduction-choice-demo")))
						return ns.Put([]byte("selected-proposal"), f.proposal.Bytes())
					}))
				}
				incomplete.assertReadOnly(t)
				peer = peerapi.NewHandler(incomplete.vault, f.root, f.alice)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Content-Type", "application/json")
				body := valid
				switch scenario {
				case "wrong root", "self", "unselected sender", "pending sender":
					peer.ServeHTTP(w, r)
					return
				case "bad proof":
					body = checkDocument(badProof, f.acceptance)
				case "bad acceptance":
					body = checkDocument(f.proposal, []byte("remote secret"))
				case "malformed":
					body = []byte(`{"remote secret":true}`)
				case "duplicate field":
					body = bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
				case "oversize", "chunked oversize":
					body = append(bytes.Clone(valid), bytes.Repeat([]byte(" "), onboarding.MaxIntroductionBytes)...)
					if scenario == "chunked oversize" {
						w.(http.Flusher).Flush()
					} else {
						w.Header().Set("Content-Length", strconv.Itoa(len(body)))
					}
				case "false length":
					w.Header().Set("Content-Length", "1")
				case "truncated":
					w.Header().Set("Content-Length", "100000")
				case "bad media":
					w.Header().Set("Content-Type", "text/plain")
				case "duplicate media":
					w.Header().Add("Content-Type", "application/json")
				case "non-200":
					w.WriteHeader(http.StatusForbidden)
				case "redirect":
					w.Header().Set("Location", "/peer/introduction")
					w.WriteHeader(http.StatusFound)
				}
				_, _ = w.Write(body) // Deliberately broken framing and early client closes.
			}))
			defer server.Close()
			if scenario == "unavailable" {
				server.Close()
			}
			receiver := f.receiver
			want := http.StatusBadGateway
			if scenario == "wrong root" {
				evidenceCredentials(t, &receiver, wrongRoot, f.bob)
			}
			if scenario == "self" {
				receiver = f.sender
				evidenceCredentials(t, &receiver, f.root, f.alice)
				want = http.StatusBadRequest
			}
			assertCheckError(t, fetchResponse(receiver, server.URL+"/peer/introduction"), want)
			wantRequests := int32(1)
			if scenario == "unavailable" {
				wantRequests = 0
			}
			assert.Equal(requests.Load(), wantRequests)
			assert.SEmpty(try.To1(onboarding.ListIntroductions(f.receiver.vault, f.root)))
			assertFetchUnselected(t, f)
		})
	}
}

func TestOwnerFetchConflictAndFailedWrite(t *testing.T) {
	for _, scenario := range []string{"conflict", "failed write"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()

			f := newFetchPair(t)
			server := httptest.NewServer(peerapi.NewHandler(f.sender.vault, f.root, f.alice))
			defer server.Close()
			want := http.StatusInternalServerError
			if scenario == "conflict" {
				other := intro.New(key.Info{Public: f.root}).Introduce(f.rootSigner, key.Info{Public: f.alice})
				try.To2(onboarding.SaveIntroduction(f.receiver.vault, f.root, other.Bytes(),
					try.To1(other.SignAcceptance(f.aliceSigner))))
				want = http.StatusConflict
			}
			before := try.To1(os.ReadFile(f.receiver.path))
			f.receiver.assertReadOnly(t) // Exhausted encryption budget simulates failed Put.
			assertCheckError(t, fetchResponse(f.receiver, server.URL+"/peer/introduction"), want)
			assert.DeepEqual(try.To1(os.ReadFile(f.receiver.path)), before)
			assertFetchUnselected(t, f)
			if scenario == "failed write" {
				assert.SEmpty(try.To1(onboarding.ListIntroductions(f.receiver.vault, f.root)))
			}
		})
	}
}

func TestOwnerFetchDirectRequestHasNoCredentials(t *testing.T) {
	defer assert.PushTester(t)()

	f := newFetchPair(t)
	var proxyCalls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyCalls.Add(1)
		w.WriteHeader(http.StatusTeapot)
	}))
	defer proxy.Close()
	for _, name := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(name, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	requests := make(chan *http.Request, 2)
	peer := peerapi.NewHandler(f.sender.vault, f.root, f.alice)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(r.Context())
		w.Header().Set("Set-Cookie", "peer_secret=never-return")
		peer.ServeHTTP(w, r)
	}))
	defer server.Close()
	var lookups atomic.Int32
	ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { lookups.Add(1) },
	})
	endpoint := strings.Replace(server.URL, "127.0.0.1", "localhost", 1) + "/peer/introduction"
	for _, created := range []bool{true, false} {
		r := fetchRequest(f.receiver, endpoint).WithContext(ctx)
		r.Header.Set("Cookie", "owner_secret=private")
		r.Header.Set("Proxy-Authorization", "private")
		r.Header.Set("X-Forwarded-Authorization", f.receiver.authorization)
		r.Header.Set("X-Destination-Header", "private")
		w := httptest.NewRecorder()
		f.receiver.handler.ServeHTTP(w, r)
		assertSaved(t, w, f.alice, false, created)
		select {
		case request := <-requests:
			assert.Equal(request.Method, http.MethodGet)
			assert.Equal(request.URL.RequestURI(), "/peer/introduction")
			assert.Equal(request.ContentLength, int64(0))
			assert.Equal(request.Host, strings.TrimPrefix(server.URL, "http://"))
			for _, header := range []string{"Authorization", "Cookie", "Proxy-Authorization", "X-Forwarded-Authorization", "X-Destination-Header", "Accept-Encoding"} {
				assert.Empty(request.Header.Get(header))
			}
		default:
			t.Fatal("peer did not receive a request")
		}
		assert.Empty(w.Header().Get("Set-Cookie"))
	}
	assert.Equal(proxyCalls.Load(), int32(0))
	assert.Equal(lookups.Load(), int32(0))
}

func TestOwnerFetchTimeoutAndCancellation(t *testing.T) {
	for _, cancelRequest := range []bool{false, true} {
		t.Run(map[bool]string{false: "five second timeout", true: "request cancellation"}[cancelRequest], func(t *testing.T) {
			defer assert.PushTester(t)()

			f := newFetchPair(t)
			f.receiver.assertReadOnly(t)
			entered, closed := make(chan struct{}), make(chan struct{})
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(closed)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, " ")
				w.(http.Flusher).Flush()
				close(entered)
				select {
				case <-r.Context().Done():
				case <-release:
				case <-time.After(7 * time.Second):
				}
			}))
			defer server.Close()
			defer close(release)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			response := make(chan *httptest.ResponseRecorder, 1)
			started := time.Now()
			go func() {
				w := httptest.NewRecorder()
				f.receiver.handler.ServeHTTP(w, fetchRequest(f.receiver, server.URL+"/peer/introduction").WithContext(ctx))
				response <- w
			}()
			waitFetchSignal(t, entered, time.Second)
			// A stalled response must not hold a Vault write transaction.
			unlocked := make(chan error, 1)
			noChange := errors.New("rollback probe")
			go func() { unlocked <- f.receiver.vault.Update(func(storage.WriteTx) error { return noChange }) }()
			select {
			case err := <-unlocked:
				assert.ErrorIs(err, noChange)
			case <-time.After(time.Second):
				t.Fatal("network I/O held a Vault transaction")
			}
			bound := 7 * time.Second
			if cancelRequest {
				cancel()
				bound = time.Second
			}
			select {
			case w := <-response:
				assertCheckError(t, w, http.StatusBadGateway)
			case <-time.After(bound):
				t.Fatal("fetch did not stop promptly")
			}
			if !cancelRequest {
				assert.That(time.Since(started) >= 4*time.Second)
			}
			waitFetchSignal(t, closed, time.Second)
			assert.SEmpty(try.To1(onboarding.ListIntroductions(f.receiver.vault, f.root)))
			assertFetchUnselected(t, f)
		})
	}
}

func waitFetchSignal(t *testing.T, signal <-chan struct{}, bound time.Duration) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(bound):
		t.Fatal("timed out waiting for fetch signal")
	}
}
