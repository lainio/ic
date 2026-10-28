package ownerapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const adVerifyPath = "/owner/ads/verify"

func adVerifyBody(subject key.Public) string {
	return `{"subject_public_key_hex":"` + hex.EncodeToString(subject) + `"}`
}

func verificationCredential(t *testing.T, f adFetchFixture) (http.Handler, string) {
	t.Helper()
	defer assert.PushTester(t)()
	root, local := bytes.Clone(f.root), bytes.Clone(f.local)
	h, file, bind := try.To3(NewVerificationCredentials(t.Context(), f.vault,
		root, local, f.signer, t.TempDir()))
	clear(root)
	clear(local)
	assert.That(bind(nil) == nil) // Verification needs no publication endpoint.
	return h, strings.TrimSpace(strings.TrimPrefix(string(try.To1(os.ReadFile(file))), "Authorization: "))
}

func TestAdVerificationStrictRequest(t *testing.T) {
	defer assert.PushTester(t)()
	f := newAdFetchFixture(t)
	h, auth := verificationCredential(t, f)
	defer f.unchanged(t)()
	valid := adVerifyBody(f.subject)
	for _, body := range []string{
		"", `{}`, `null`, `[]`, `{"subject_public_key_hex":null}`,
		`{"subject_public_key_hex":1}`, `{"subject_public_key_hex":{}}`,
		`{"subject_public_key_hex":[]}`, `{"subject_public_key_hex":true}`,
		`{"subject_public_key_hex":""}`, `{"subject_public_key_hex":"0"}`,
		`{"subject_public_key_hex":"AB"}`, `{"subject_public_key_hex":"gg"}`,
		`{"subject_public_key_hex":" 01"}`, `{"subject_public_key_hex":"0x01"}`,
		`{"subject_public_key_hex":"` + strings.Repeat("01", 129) + `"}`,
		strings.Replace(valid, "subject_public_key_hex", "Subject_public_key_hex", 1),
		valid[:len(valid)-1] + `,"subject_public_key_hex":"01"}`,
		valid[:len(valid)-1] + `,"root":"01"}`, valid + `{}`, valid[:len(valid)-1],
		"{\"subject_public_key_hex\":\"\xff\"}",
	} {
		w := deviceRequest(h, auth, "POST", adVerifyPath, body)
		assert.Equal(w.Code, 400, body)
		assert.Equal(w.Body.String(), "Bad Request\n")
	}
	for _, field := range []string{"url", "ad", "proof", "challenge", "clock", "slot", "epoch", "device", "header", "callback"} {
		body := valid[:len(valid)-1] + `,"` + field + `":"x"}`
		assert.Equal(deviceRequest(h, auth, "POST", adVerifyPath, body).Code, 400)
	}
	reader := strings.NewReader(strings.Repeat(" ", 4096))
	r := httptest.NewRequest("POST", adVerifyPath, reader)
	r.ContentLength = 1
	r.Header.Set("Authorization", auth)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(w.Code, 413)
	assert.Equal(reader.Len(), 4096-1025)
	assert.Equal(f.signer.signs.Load(), int32(0))
	assert.Equal(f.signer.publics.Load(), int32(0))
}

func TestAdVerificationAuthAndRoutesBeforeBody(t *testing.T) {
	defer assert.PushTester(t)()
	f := newAdFetchFixture(t)
	h, auth := verificationCredential(t, f)
	defer f.unchanged(t)()
	for _, tc := range []struct {
		method, path, media, extra string
		status                     int
	}{
		{"GET", adVerifyPath, "application/json", "", 405},
		{"HEAD", adVerifyPath, "application/json", "", 405},
		{"PUT", adVerifyPath, "application/json", "", 405},
		{"DELETE", adVerifyPath, "application/json", "", 405},
		{"OPTIONS", adVerifyPath, "application/json", "", 405},
		{"POST", adVerifyPath + "/", "application/json", "", 404},
		{"POST", "/owner/ads/%76erify", "application/json", "", 404},
		{"POST", "/owner//ads/verify", "application/json", "", 404},
		{"POST", "/owner/ads/../ads/verify", "application/json", "", 404},
		{"POST", adVerifyPath + "?", "application/json", "", 400},
		{"POST", adVerifyPath + "?root=x", "application/json", "", 400},
		{"POST", adVerifyPath, "", "", 415},
		{"POST", adVerifyPath, "text/plain", "", 415},
		{"POST", adVerifyPath, "application/json, application/json", "", 415},
		{"POST", adVerifyPath, "application/json", "media", 415},
		{"POST", adVerifyPath, "application/json", "auth", 401},
		{"POST", adVerifyPath, "application/json", "fragment", 400},
		{"POST", adVerifyPath, "application/json", "raw fragment", 400},
		{"POST", adVerifyPath, "application/json", "opaque", 404},
	} {
		for _, credential := range []string{"", "Bearer wrong", auth} {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			r.Header.Set("Authorization", credential)
			r.Header.Set("Content-Type", tc.media)
			switch tc.extra {
			case "media":
				r.Header.Add("Content-Type", "application/json")
			case "auth":
				r.Header.Add("Authorization", auth)
			case "fragment":
				r.URL.Fragment = "x"
			case "raw fragment":
				r.URL.RawFragment = "%78"
			case "opaque":
				r.URL.Opaque = "//localhost/owner/ads/verify"
			}
			body := &ownerStatusUnreadBody{}
			r.Body = io.NopCloser(body)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := tc.status
			if credential != auth {
				want = 401
			}
			assert.Equal(w.Code, want)
			assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
			assert.Equal(body.reads, 0)
			if want == 405 {
				assert.Equal(w.Header().Get("Allow"), "POST")
			}
		}
	}
}

func TestAdVerificationEarlierCredentialsAndPeer(t *testing.T) {
	defer assert.PushTester(t)()
	for _, constructor := range []func(context.Context, *storage.Vault, key.Public, key.Public, string) (http.Handler, string, error){
		NewStatusCredentials, NewReadCredentials, NewEvidenceCredentials,
		func(ctx context.Context, v *storage.Vault, root, child key.Public, dir string) (http.Handler, string, error) {
			return NewDeviceCredentials(ctx, v, root, child, nil, dir)
		},
		func(ctx context.Context, v *storage.Vault, root, child key.Public, dir string) (http.Handler, string, error) {
			h, file, _, err := NewPublicationCredentials(ctx, v, root, child, nil, dir)
			return h, file, err
		},
		func(ctx context.Context, v *storage.Vault, root, child key.Public, dir string) (http.Handler, string, error) {
			h, file, _, err := NewPublicationProofCredentials(ctx, v, root, child, nil, dir)
			return h, file, err
		},
	} {
		h, file := try.To2(constructor(t.Context(), nil, nil, nil, t.TempDir()))
		auth := strings.TrimSpace(strings.TrimPrefix(string(try.To1(os.ReadFile(file))), "Authorization: "))
		for _, handler := range []http.Handler{h, peerapi.NewHandler(nil, nil, nil),
			peerapi.NewAdHandler(nil, nil, nil, ""), peerapi.NewProofHandler(nil, nil, nil, "", nil)} {
			for _, method := range []string{"POST", "GET"} {
				r := httptest.NewRequest(method, adVerifyPath, nil)
				r.Header.Set("Authorization", auth)
				body := &ownerStatusUnreadBody{}
				r.Body = io.NopCloser(body)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				assert.Equal(w.Code, 404)
				assert.Equal(body.reads, 0)
			}
		}
	}
}

// Keep crypto/storage matrices in ads; this fixture checks their HTTP boundary
// through the actual publisher capability and a finite encrypted receiver lease.
func newAdVerificationFixture(t *testing.T) (adFetchFixture, *atomic.Int32) {
	t.Helper()
	defer assert.PushTester(t)()
	f := newAdFetchFixture(t)
	publisher := newDeviceFixture(t)
	for _, vault := range []*storage.Vault{f.vault, publisher.vault} {
		try.To2(onboarding.SaveIntroduction(vault, f.root, f.choice.Proposal.Bytes(), f.choice.Acceptance))
		try.To1(onboarding.VerifyReceived(vault, f.root))
	}
	try.To1(device.BootstrapLocal(publisher.vault, f.root, f.subject, f.peer))
	_, _, bind := proofCredentials(t, publisher.vault, f.root, f.subject, f.peer)
	server := httptest.NewUnstartedServer(nil)
	endpoint := "http://" + server.Listener.Addr().String() + "/peer/introduction"
	next := peerapi.NewProofHandler(publisher.vault, f.root, f.subject, endpoint, bind(server.Listener))
	calls := &atomic.Int32{}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		next.ServeHTTP(w, r)
	})
	server.Start()
	t.Cleanup(server.Close)
	f.current = try.To1(ads.PublishLocal(publisher.vault, f.root, f.subject, f.peer, endpoint, time.Now()))
	try.To1(ads.ReceiveClaim(f.vault, f.root, f.subject, try.To1(wire.Marshal(f.current))))
	f.handler, f.auth = verificationCredential(t, f)
	return f, calls
}

func TestAdVerificationNoReceiverSigningAndLostResponse(t *testing.T) {
	defer assert.PushTester(t)()
	f, calls := newAdVerificationFixture(t)
	remaining := f.lease.remaining.Load()
	r := httptest.NewRequest("POST", adVerifyPath, strings.NewReader(adVerifyBody(f.subject)))
	r.Header.Set("Authorization", f.auth)
	r.Header.Set("Content-Type", "application/json")
	w := &ownerStatusFailedWriter{ResponseRecorder: httptest.NewRecorder()}
	f.handler.ServeHTTP(w, r)
	assert.Equal(w.Code, 200)
	assert.Equal(w.headerCalls, 1)
	assert.Equal(w.writeCalls, 1)
	assert.Equal(calls.Load(), int32(1))
	assert.Equal(f.lease.remaining.Load(), remaining-1)
	got, found := try.To2(ads.ReadVerifiedClaim(f.vault, f.root, f.subject))
	assert.That(found)
	assert.DeepEqual(got, try.To1(wire.Marshal(f.current)))

	f.lease.remaining.Store(0)
	defer f.unchanged(t)()
	retry := deviceRequest(f.handler, f.auth, "POST", adVerifyPath, adVerifyBody(f.subject))
	assert.Equal(retry.Code, 200)
	assert.Equal(retry.Body.String(), `{"subject_public_key_hex":"`+hex.EncodeToString(f.subject)+`","verified":true,"changed":false}`)
	assert.Equal(calls.Load(), int32(2))
	assert.Equal(f.signer.signs.Load(), int32(0))
	assert.Equal(f.signer.publics.Load(), int32(0))
}

func TestAdVerificationFailureBoundaryPreservesHistory(t *testing.T) {
	for _, scenario := range []string{"invalid key", "self", "unknown", "missing", "forged", "expired", "Known corruption", "receipt corruption", "verified corruption", "exhaustion", "canceled", "deadline"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			f, calls := newAdVerificationFixture(t)
			assert.Equal(deviceRequest(f.handler, f.auth, "POST", adVerifyPath, adVerifyBody(f.subject)).Code, 200)
			history := try.To1(wire.Marshal(f.current))
			subject, want, extraCalls := f.subject, 409, int32(0)
			ctx := t.Context()
			switch scenario {
			case "invalid key":
				subject, want = []byte{1}, 400
			case "self":
				subject, want = f.local, 400
			case "unknown":
				subject = try.To1(key.New().CBORPublicKey())
			case "missing":
				try.To(f.vault.Update(func(tx storage.WriteTx) error { return tx.Delete([]byte("received-ad-claims-v1")) }))
			case "forged", "expired":
				f.current.Payload.ExpiresUnixNano = int64(ads.TTL)
				if scenario == "expired" {
					digest := key.HashTagged(ads.SignaturePurpose, try.To1(wire.Marshal(f.current.Payload)))
					f.current.Signature = try.To1(f.peer.Sign(digest[:]))
				}
				try.To1(ads.ReceiveClaim(f.vault, f.root, f.subject, try.To1(wire.Marshal(f.current))))
			case "Known corruption":
				want = 500
				try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					ns := try.To1(tx.ChildForUpdate([]byte("known-introductions-v1")))
					return ns.Put(f.subject, []byte{0xff})
				}))
			case "receipt corruption", "verified corruption":
				want = 500
				name := "received-ad-claims-v1"
				if scenario == "verified corruption" {
					name, extraCalls = "verified-ad-claims-v1", 1
				}
				try.To(f.vault.Update(func(tx storage.WriteTx) error { return tx.Put([]byte(name), []byte{0xff}) }))
			case "exhaustion":
				want, extraCalls = 500, 1
				try.To(f.vault.Update(func(tx storage.WriteTx) error { return tx.Delete([]byte("verified-ad-claims-v1")) }))
				f.lease.remaining.Store(0)
			case "canceled", "deadline":
				want = 504
				var cancel context.CancelFunc
				if scenario == "deadline" {
					ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				} else {
					ctx, cancel = context.WithCancel(ctx)
				}
				cancel()
			}
			defer f.unchanged(t)()
			r := httptest.NewRequestWithContext(ctx, "POST", adVerifyPath, strings.NewReader(adVerifyBody(subject)))
			r.Header.Set("Authorization", f.auth)
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			f.handler.ServeHTTP(w, r)
			assert.Equal(w.Code, want)
			assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
			assert.Equal(calls.Load(), 1+extraCalls)
			if scenario != "verified corruption" && scenario != "exhaustion" {
				got, found := try.To2(ads.ReadVerifiedClaim(f.vault, f.root, f.subject))
				assert.That(found)
				assert.DeepEqual(got, history)
			}
		})
	}
}

func TestAdVerificationErrorMapping(t *testing.T) {
	defer assert.PushTester(t)()
	for _, tc := range []struct {
		err    error
		status int
	}{
		{ads.ErrInvalidInput, 400}, {ads.ErrSubjectNotKnown, 409},
		{ads.ErrNoReceivedClaim, 409}, {ads.ErrReceivedClaimChanged, 409},
		{ads.ErrInvalidRecord, 409}, {ads.ErrVerifiedClaimsFull, 409},
		{ads.ErrRemoteProof, 502}, {ads.ErrInvalidProof, 502},
		{context.Canceled, 504}, {context.DeadlineExceeded, 504},
		{ads.ErrInvalidReceivedClaims, 500}, {ads.ErrInvalidVerifiedClaims, 500},
		{storage.ErrKeyUsageExhausted, 500}, {storage.ErrClosed, 500},
		{errors.New("private storage or seal diagnostic"), 500},
	} {
		w := httptest.NewRecorder()
		writeAdVerificationError(w, fmt.Errorf("private wrapper: %w", tc.err))
		assert.Equal(w.Code, tc.status)
		assert.Equal(w.Body.String(), http.StatusText(tc.status)+"\n")
	}
}
