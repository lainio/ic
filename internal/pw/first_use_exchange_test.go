package pw_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/lainio/ic/internal/ownerapi"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/storage"
)

const ownerUsePath, peerUsePath = "/owner/pw/first-use", "/peer/pw/first-use"
const aliceUseKey, bobUseKey = "local-pw-first-use-v1", "local-pw-use-seen-v1"

type observedUseRecord struct {
	_                 struct{} `cbor:",toarray"`
	Version           uint8
	State             string
	Request, Response []byte
}
type observedUseReceipt struct {
	_                 struct{} `cbor:",toarray"`
	Version           uint8
	Request, Response []byte
}

type firstUseExchange struct {
	*exchangeFixture
	aliceOwner, bobOwner *httptest.Server
	aliceAuth, bobAuth   string
	peer                 http.Handler
	mu                   sync.Mutex
	requests, responses  [][]byte
	failure              error
	drop, invalid        bool
	before, after        func() error
}

func newFirstUseExchange(t *testing.T) *firstUseExchange {
	t.Helper()
	defer assert.PushTester(t)()
	f := &firstUseExchange{}
	f.exchangeFixture = newExchange(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case peerUsePath:
				f.serveUse(w, r)
			case "/peer/pw/establish":
				f.peer.ServeHTTP(w, r)
			default:
				next.ServeHTTP(w, r)
			}
		})
	})
	f.bind(t)
	row := try.To1(
		pw.IssueInvitation(f.b.store.Vault(), f.root, f.b.public, f.a.public),
	)
	body := try.To1(json.Marshal(map[string]string{
		"target_public_key_hex": hex.EncodeToString(f.b.public),
		"invitation_id_hex": hex.EncodeToString(
			row.ID,
		), "audience": row.Audience,
	}))
	status, _ := try.To2(f.post(t.Context(), redeemPath, body))
	assert.Equal(status, 200)
	assert.Equal(len(f.requests), 0) // Redemption never starts first use.
	return f
}

func (f *firstUseExchange) bind(t *testing.T) {
	t.Helper()
	defer assert.PushTester(t)()
	h, file, bind := try.To3(
		ownerapi.NewFirstUseCredentials(
			t.Context(),
			f.a.store.Vault(),
			f.root,
			f.a.public,
			f.a.signer,
			t.TempDir(),
		),
	)
	bind(nil)
	f.aliceOwner = httptest.NewServer(h)
	t.Cleanup(f.aliceOwner.Close)
	f.aliceAuth = strings.TrimSpace(
		strings.TrimPrefix(
			string(try.To1(os.ReadFile(file))),
			"Authorization:",
		),
	)
	h, file, bind = try.To3(
		ownerapi.NewFirstUseCredentials(
			t.Context(),
			f.b.store.Vault(),
			f.root,
			f.b.public,
			f.b.signer,
			t.TempDir(),
		),
	)
	prove, _, establish, use, _ := bind(f.server.Listener)
	assert.That(prove != nil)
	f.peer = peerapi.NewFirstUseHandler(
		use,
		peerapi.NewEstablishmentHandler(establish, http.NotFoundHandler()),
	)
	f.bobOwner = httptest.NewServer(h)
	t.Cleanup(f.bobOwner.Close)
	f.bobAuth = strings.TrimSpace(
		strings.TrimPrefix(
			string(try.To1(os.ReadFile(file))),
			"Authorization:",
		),
	)
}

func (f *firstUseExchange) post(
	ctx context.Context,
	path string,
	body []byte,
) (int, []byte, error) {
	return useHTTP(ctx, f.aliceOwner.URL+path, f.aliceAuth, body)
}

func useHTTP(
	ctx context.Context,
	url, auth string,
	body []byte,
) (int, []byte, error) {
	r, err := http.NewRequestWithContext(
		ctx,
		"POST",
		url,
		bytes.NewReader(body),
	)
	if err != nil {
		return 0, nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	transport := &http.Transport{DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Do(r)
	if err != nil {
		return 0, nil, err
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	closeErr := response.Body.Close()
	return response.StatusCode, data, errors.Join(err, closeErr)
}

func readUseRecord(v *storage.Vault, name string) (raw []byte, err error) {
	defer err2.Handle(&err, nil)
	try.To(v.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		raw, _ = try.To2(tx.Get([]byte(name)))
		return nil
	}))
	return raw, nil
}

func (f *firstUseExchange) observeUse(r *http.Request) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	var doc struct {
		Version int
		Request []byte
	}
	if json.Unmarshal(body, &doc) != nil || doc.Version != 1 ||
		r.Header.Get("Authorization") != "" ||
		r.Header.Get("Cookie") != "" {
		return errors.New("invalid envelope or forwarded credentials")
	}
	raw, err := readUseRecord(f.a.store.Vault(), aliceUseKey)
	if err != nil {
		return err
	}
	var record observedUseRecord
	if wire.UnmarshalCanonical(&record, raw) != nil ||
		record.State != "Await" ||
		!bytes.Equal(record.Request, doc.Request) ||
		record.Response != nil {
		return errors.New("Await not committed before peer I/O")
	}
	f.requests = append(f.requests, bytes.Clone(doc.Request))
	return nil
}

func (f *firstUseExchange) serveUse(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.observeUse(r); err != nil {
		f.failure = err
		http.Error(w, "fixture failed", 500)
		return
	}
	if f.before != nil {
		if err := f.before(); err != nil {
			f.failure = err
			http.Error(w, "fixture failed", 500)
			return
		}
	}
	recorder := httptest.NewRecorder()
	f.peer.ServeHTTP(recorder, r)
	f.responses = append(f.responses, bytes.Clone(recorder.Body.Bytes()))
	if recorder.Code == 200 {
		var doc struct {
			Version  int
			Response []byte
		}
		raw, err := readUseRecord(f.b.store.Vault(), bobUseKey)
		var receipt observedUseReceipt
		if err != nil || json.Unmarshal(recorder.Body.Bytes(), &doc) != nil ||
			wire.UnmarshalCanonical(&receipt, raw) != nil ||
			!bytes.Equal(receipt.Response, doc.Response) ||
			!bytes.Equal(receipt.Request, f.requests[len(f.requests)-1]) {
			f.failure = errors.New("Bob response preceded exact receipt commit")
			http.Error(w, "fixture failed", 500)
			return
		}
	}
	if f.after != nil {
		if err := f.after(); err != nil {
			f.failure = err
		}
	}
	if f.drop {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			f.failure = err
			return
		}
		if err = conn.Close(); err != nil {
			f.failure = err
		}
		return
	}
	maps.Copy(w.Header(), recorder.Header())
	w.WriteHeader(recorder.Code)
	if f.invalid {
		_, _ = w.Write([]byte(`{"version":1,"response":"AQ=="}`))
	} else {
		_, _ = w.Write(recorder.Body.Bytes())
	}
}

func (f *firstUseExchange) reopen(t *testing.T) {
	t.Helper()
	defer assert.PushTester(t)()
	f.aliceOwner.Close()
	f.bobOwner.Close()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range []*exchangeNode{f.a, f.b} {
		try.To(n.store.Close())
		n.store = try.To1(
			nodevault.OpenForNode(
				t.Context(),
				n.dir,
				n.storageKey,
				f.root,
				n.public,
			),
		)
	}
	f.bind(t)
}

func TestFirstUseTwoNodeHTTPCommitOrderAndRestart(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseExchange(t)
	aBefore := try.To1(exchangeRecords(f.a.store.Vault()))
	bBefore := try.To1(exchangeRecords(f.b.store.Vault()))
	status, body := try.To2(f.post(t.Context(), ownerUsePath, []byte("{}")))
	assert.Equal(status, 200)
	assert.Equal(string(body), `{"local_ready":true}`)
	f.mu.Lock()
	assert.NoError(f.failure)
	assert.Equal(len(f.requests), 1)
	assert.Equal(len(f.responses), 1)
	f.mu.Unlock()
	alice := try.To1(readUseRecord(f.a.store.Vault(), aliceUseKey))
	bob := try.To1(readUseRecord(f.b.store.Vault(), bobUseKey))
	var record observedUseRecord
	try.To(wire.UnmarshalCanonical(&record, alice))
	assert.Equal(record.State, "Ready")
	assert.SNotEmpty(record.Response)
	assert.DeepEqual(try.To1(exchangeRecords(f.a.store.Vault())), aBefore)
	assert.DeepEqual(try.To1(exchangeRecords(f.b.store.Vault())), bBefore)
	f.reopen(t)
	assert.DeepEqual(
		try.To1(readUseRecord(f.a.store.Vault(), aliceUseKey)),
		alice,
	)
	assert.DeepEqual(try.To1(readUseRecord(f.b.store.Vault(), bobUseKey)), bob)
	before := f.snapshot(t)
	status, _ = try.To2(f.post(t.Context(), ownerUsePath, []byte("{}")))
	assert.Equal(status, 409)
	assert.DeepEqual(f.snapshot(t), before)
	assert.Equal(len(f.requests), 1)
	assert.That(
		try.To1(pw.ExpireFirstUse(f.a.store.Vault(), f.root, f.a.public, true)),
	)
	expired := try.To1(readUseRecord(f.a.store.Vault(), aliceUseKey))
	try.To(wire.UnmarshalCanonical(&record, expired))
	assert.Equal(record.State, "Expired")
	f.reopen(t)
	assert.DeepEqual(
		try.To1(readUseRecord(f.a.store.Vault(), aliceUseKey)),
		expired,
	)
	before = f.snapshot(t)
	ready, err := pw.ReceiveFirstUse(
		f.a.store.Vault(),
		f.root,
		f.a.public,
		f.a.signer,
		record.Response,
	)
	assert.Equal(err, pw.ErrFirstUse)
	assert.ThatNot(ready)
	assert.DeepEqual(f.snapshot(t), before)
}

func TestFirstUseLostResponseRetainsAwaitAndOneTimeReceipt(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseExchange(t)
	f.drop = true
	status, body := try.To2(f.post(t.Context(), ownerUsePath, []byte("{}")))
	assert.Equal(status, 502)
	assert.Equal(
		string(body),
		"First-use peer outcome unknown; Await retained\n",
	)
	f.mu.Lock()
	assert.NoError(f.failure)
	assert.Equal(len(f.requests), 1)
	request := bytes.Clone(f.requests[0])
	f.mu.Unlock()
	alice := try.To1(readUseRecord(f.a.store.Vault(), aliceUseKey))
	bob := try.To1(readUseRecord(f.b.store.Vault(), bobUseKey))
	var record observedUseRecord
	try.To(wire.UnmarshalCanonical(&record, alice))
	assert.Equal(record.State, "Await")
	assert.SNil(record.Response)
	f.reopen(t)
	assert.DeepEqual(
		try.To1(readUseRecord(f.a.store.Vault(), aliceUseKey)),
		alice,
	)
	assert.DeepEqual(try.To1(readUseRecord(f.b.store.Vault(), bobUseKey)), bob)
	f.drop = false
	before := f.snapshot(t)
	envelope := try.To1(json.Marshal(struct {
		Version int    `json:"version"`
		Request []byte `json:"request"`
	}{1, request}))
	status, body = try.To2(
		useHTTP(t.Context(), f.server.URL+peerUsePath, "", envelope),
	)
	assert.Equal(status, 409)
	assert.Equal(string(body), "Conflict\n")
	assert.DeepEqual(f.snapshot(t), before)
	status, _ = try.To2(f.post(t.Context(), ownerUsePath, []byte("{}")))
	assert.Equal(status, 409)
	assert.Equal(len(f.requests), 2) // Only the deliberately injected replay.
	assert.DeepEqual(f.snapshot(t), before)
}

func TestFirstUseTwoNodeChangedGuardsAndInvalidReply(t *testing.T) {
	for _, mode := range []string{"Alice deny", "Bob deny before", "Bob deny after", "Alice delete", "Bob delete", "invalid response", "Alice signer", "Bob signer"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newFirstUseExchange(t)
			node, peer := f.a, f.b
			if strings.HasPrefix(mode, "Bob") {
				node, peer = f.b, f.a
			}
			change := func() error {
				if strings.Contains(mode, "delete") {
					return node.store.Vault().
						Update(func(tx storage.WriteTx) error { return tx.Delete([]byte("local-pw-held-v1")) })
				}
				_, err := policy.DenyLocal(
					node.store.Vault(),
					f.root,
					node.public,
					peer.public,
				)
				return err
			}
			switch mode {
			case "Bob deny before", "Bob delete":
				f.before = change
			case "Alice deny", "Alice delete", "Bob deny after":
				f.after = change
			case "invalid response":
				f.invalid = true
			case "Alice signer", "Bob signer":
				node.signer.fail = true
			}
			status, _ := try.To2(
				f.post(t.Context(), ownerUsePath, []byte("{}")),
			)
			want := 409
			if mode == "Bob deny before" || mode == "Bob delete" ||
				mode == "Bob signer" {
				want = 502
			}
			if mode == "Bob deny after" {
				want = 200
			}
			assert.Equal(status, want)
			f.mu.Lock()
			assert.NoError(f.failure)
			f.mu.Unlock()
			raw := try.To1(readUseRecord(f.a.store.Vault(), aliceUseKey))
			if mode == "Alice signer" {
				assert.SNil(raw)
				assert.Equal(len(f.requests), 0)
				return
			}
			var record observedUseRecord
			try.To(wire.UnmarshalCanonical(&record, raw))
			if mode == "Bob deny after" {
				assert.Equal(record.State, "Ready")
			} else {
				assert.Equal(record.State, "Await")
			}
			if want == 502 {
				assert.SNil(
					try.To1(readUseRecord(f.b.store.Vault(), bobUseKey)),
				)
			}
			if mode == "Alice delete" {
				assert.SNil(try.To1(exchangeRecords(f.a.store.Vault()))[2])
			}
		})
	}
}

func TestFirstUseOwnerLocksReleasedDuringHTTP(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseExchange(t)
	f.after = func() error {
		// This executes after Bob commits, before Alice receives. Both owner
		// routers must admit a mutation using their SAME signing/mutation locks.
		for _, owner := range []struct{ url, auth string }{{f.aliceOwner.URL, f.aliceAuth}, {f.bobOwner.URL, f.bobAuth}} {
			status, _, err := useHTTP(
				t.Context(),
				owner.url+"/owner/introductions/verify",
				owner.auth,
				[]byte("{}"),
			)
			if err != nil {
				return err
			}
			if status != 200 {
				return errors.New("owner lock held during HTTP")
			}
		}
		return nil
	}
	status, _ := try.To2(f.post(t.Context(), ownerUsePath, []byte("{}")))
	assert.Equal(status, 200)
	f.mu.Lock()
	assert.NoError(f.failure)
	f.mu.Unlock()
}

func TestFirstUseConcurrentOwnerStartsOnlyOneSession(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseExchange(t)
	start := make(chan struct{})
	type result struct {
		status int
		err    error
	}
	results := make(chan result, 8)
	for range 8 {
		go func() {
			<-start
			s, _, err := f.post(t.Context(), ownerUsePath, []byte("{}"))
			results <- result{s, err}
		}()
	}
	close(start)
	successes := 0
	for range 8 {
		r := <-results
		assert.NoError(r.err)
		if r.status == 200 {
			successes++
		} else {
			assert.Equal(r.status, 409)
		}
	}
	assert.Equal(successes, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	assert.NoError(f.failure)
	assert.Equal(len(f.requests), 1)
}
