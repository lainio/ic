package ownerapi

import (
	"context"
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

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const acceptanceExchangePath = "/owner/pw/acceptance/exchange"

func exchangeCredential(t *testing.T, v *storage.Vault,
	root, local key.Public, signer key.Handle,
) (http.Handler, string) {
	t.Helper()
	defer assert.PushTester(t)()
	h, file, bind := try.To3(NewAcceptanceCredentials(t.Context(), v,
		root, local, signer, t.TempDir()))
	prove, accept := bind(nil)
	assert.That(prove == nil && accept == nil)
	return h, strings.TrimSpace(strings.TrimPrefix(
		string(try.To1(os.ReadFile(file))), "Authorization: "))
}

func TestAcceptanceExchangeStrictSelector(t *testing.T) {
	defer assert.PushTester(t)()
	f := newAdFetchFixture(t)
	h, auth := exchangeCredential(t, f.vault, f.root, f.local, f.signer)
	defer f.unchanged(t)()
	valid := adVerifyBody(f.subject)
	for _, body := range []string{
		"", `{}`, `null`, `[]`, `{"subject_public_key_hex":null}`,
		`{"subject_public_key_hex":1}`, `{"subject_public_key_hex":{}}`,
		`{"subject_public_key_hex":[]}`, `{"subject_public_key_hex":true}`,
		`{"subject_public_key_hex":""}`, `{"subject_public_key_hex":"0"}`,
		`{"subject_public_key_hex":"AB"}`, `{"subject_public_key_hex":"gg"}`,
		`{"subject_public_key_hex":"01"}`, // Hex, but no canonical public key.
		strings.ToUpper(valid), adVerifyBody(f.local),
		strings.Replace(valid, "subject_public_key_hex", "Subject_public_key_hex", 1),
		valid[:len(valid)-1] + `,"subject_public_key_hex":"01"}`,
		valid + `{}`, valid[:len(valid)-1],
		"{\"subject_public_key_hex\":\"\xff\"}",
	} {
		w := deviceRequest(h, auth, "POST", acceptanceExchangePath, body)
		assert.Equal(w.Code, 400, body)
		assert.Equal(w.Body.String(), "Bad Request\n")
	}
	for _, field := range []string{"peer_url", "root", "local", "identity",
		"ad", "nonce", "proof", "signer", "retry", "policy"} {
		body := valid[:len(valid)-1] + `,"` + field + `":"x"}`
		w := deviceRequest(h, auth, "POST", acceptanceExchangePath, body)
		assert.Equal(w.Code, 400)
	}
	reader := strings.NewReader(strings.Repeat(" ", 4096))
	r := httptest.NewRequest("POST", acceptanceExchangePath, reader)
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

func TestAcceptanceExchangeAuthAndRoutingBeforeBody(t *testing.T) {
	defer assert.PushTester(t)()
	h, auth := exchangeCredential(t, nil, nil, nil, nil)
	for _, tc := range []struct {
		method, path, media, extra string
		status                     int
	}{
		{"POST", acceptanceExchangePath, "application/json", "auth", 401},
		{"GET", acceptanceExchangePath, "application/json", "", 405},
		{"HEAD", acceptanceExchangePath, "application/json", "", 405},
		{"PUT", acceptanceExchangePath, "application/json", "", 405},
		{"DELETE", acceptanceExchangePath, "application/json", "", 405},
		{"OPTIONS", acceptanceExchangePath, "application/json", "", 405},
		{"POST", acceptanceExchangePath + "/", "application/json", "", 404},
		{"POST", "/owner/pw/acceptance/%65xchange", "application/json", "", 404},
		{"POST", "/owner//pw/acceptance/exchange", "application/json", "", 404},
		{"POST", "/owner/pw/../pw/acceptance/exchange", "application/json", "", 404},
		{"POST", acceptanceExchangePath + "?", "application/json", "", 400},
		{"POST", acceptanceExchangePath + "?root=x", "application/json", "", 400},
		{"POST", acceptanceExchangePath, "", "", 415},
		{"POST", acceptanceExchangePath, "text/plain", "", 415},
		{"POST", acceptanceExchangePath, "application/json, application/json", "", 415},
		{"POST", acceptanceExchangePath, "application/json", "media", 415},
		{"POST", acceptanceExchangePath, "application/json", "fragment", 400},
		{"POST", acceptanceExchangePath, "application/json", "raw fragment", 400},
		{"POST", acceptanceExchangePath, "application/json", "opaque", 404},
	} {
		for _, credential := range []string{"", "Bearer wrong", auth} {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			r.Header.Set("Authorization", credential)
			r.Header.Set("Content-Type", tc.media)
			switch tc.extra {
			case "auth":
				r.Header.Add("Authorization", auth)
			case "media":
				r.Header.Add("Content-Type", "application/json")
			case "fragment":
				r.URL.Fragment = "x"
			case "raw fragment":
				r.URL.RawFragment = "%78"
			case "opaque":
				r.URL.Opaque = "//localhost" + acceptanceExchangePath
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

func TestAcceptanceExchangeEarlierCredentialsAndPeer(t *testing.T) {
	defer assert.PushTester(t)()
	for _, constructor := range []func(context.Context, *storage.Vault,
		key.Public, key.Public, string) (http.Handler, string, error){
		NewStatusCredentials, NewReadCredentials, NewEvidenceCredentials,
		func(ctx context.Context, v *storage.Vault, root, child key.Public,
			dir string,
		) (http.Handler, string, error) {
			return NewDeviceCredentials(ctx, v, root, child, nil, dir)
		},
		func(ctx context.Context, v *storage.Vault, root, child key.Public,
			dir string,
		) (http.Handler, string, error) {
			h, file, _, err := NewPublicationCredentials(ctx, v, root, child, nil, dir)
			return h, file, err
		},
		func(ctx context.Context, v *storage.Vault, root, child key.Public,
			dir string,
		) (http.Handler, string, error) {
			h, file, _, err := NewPublicationProofCredentials(ctx, v, root, child, nil, dir)
			return h, file, err
		},
		func(ctx context.Context, v *storage.Vault, root, child key.Public,
			dir string,
		) (http.Handler, string, error) {
			h, file, _, err := NewVerificationCredentials(ctx, v, root, child, nil, dir)
			return h, file, err
		},
	} {
		h, file := try.To2(
			constructor(t.Context(), nil, nil, nil, t.TempDir()),
		)
		auth := strings.TrimSpace(strings.TrimPrefix(
			string(try.To1(os.ReadFile(file))), "Authorization: "))
		for _, handler := range []http.Handler{h,
			peerapi.NewHandler(nil, nil, nil),
			peerapi.NewAdHandler(nil, nil, nil, ""),
			peerapi.NewProofHandler(nil, nil, nil, "", nil),
			peerapi.NewChallengeHandler(nil, nil, nil, "",
				peerapi.NewHandler(nil, nil, nil)),
			peerapi.NewAcceptanceHandler(nil, nil, nil, "", nil,
				peerapi.NewHandler(nil, nil, nil)),
		} {
			for _, method := range []string{"POST", "GET"} {
				r := httptest.NewRequest(
					method,
					acceptanceExchangePath,
					nil,
				)
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

func TestAcceptanceExchangeErrorMapping(t *testing.T) {
	defer assert.PushTester(t)()
	for _, tc := range []struct {
		err    error
		status int
	}{
		{pw.ErrInvalidInput, 400}, {pw.ErrNotKnown, 409}, {pw.ErrDenied, 409},
		{pw.ErrUnauthorized, 409}, {pw.ErrUnusableSigner, 409},
		{pw.ErrAdEvidence, 409}, {pw.ErrRemoteAcceptance, 502},
		{pw.ErrInvalidProof, 502}, {context.Canceled, 504},
		{context.DeadlineExceeded, 504}, {pw.ErrLocalState, 500},
		{errors.New("private provider diagnostic"), 500},
	} {
		w := httptest.NewRecorder()
		writeAcceptanceExchangeError(
			w,
			fmt.Errorf("private wrapper: %w", tc.err),
		)
		assert.Equal(w.Code, tc.status)
		assert.Equal(w.Body.String(), http.StatusText(tc.status)+"\n")
	}
}

func TestAcceptanceExchangeExhaustedLeasesAndLostOwnerReply(t *testing.T) {
	defer assert.PushTester(t)()
	f := newAcceptanceFixture(t)
	server := httptest.NewUnstartedServer(nil)
	_, _, bind := try.To3(NewAcceptanceCredentials(t.Context(), f.vault,
		f.root, f.child, f.signer, t.TempDir()))
	prove, accept := bind(server.Listener)
	endpoint := "http://" + server.Listener.Addr().
		String() +
		"/peer/introduction"
	peer := peerapi.NewAcceptanceHandler(
		f.vault,
		f.root,
		f.child,
		endpoint,
		accept,
		peerapi.NewProofHandler(f.vault, f.root, f.child, endpoint, prove),
	)
	var calls atomic.Int32
	server.Config.Handler = http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			peer.ServeHTTP(w, r)
		},
	)
	server.Start()
	t.Cleanup(server.Close)
	ad := try.To1(wire.Marshal(try.To1(ads.PublishLocal(f.vault, f.root,
		f.child, f.signer, endpoint, time.Now()))))
	v := f.requesterVault.vault
	try.To1(ads.ReceiveClaim(v, f.root, f.child, ad))
	try.To1(
		ads.VerifyReceivedRemote(
			t.Context(),
			v,
			f.root,
			f.requester,
			f.child,
		),
	)
	h, auth := exchangeCredential(t, v, f.root, f.requester, f.requesterKey)
	calls.Store(0)
	f.lease.remaining.Store(0)
	f.requesterVault.lease.remaining.Store(0)
	defer f.unchanged(t)()
	defer f.requesterVault.unchanged(t)()

	r := httptest.NewRequest("POST", acceptanceExchangePath,
		strings.NewReader(adVerifyBody(f.child)))
	r.Header.Set("Authorization", auth)
	r.Header.Set("Content-Type", "application/json")
	w := &ownerStatusFailedWriter{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(w, r)
	assert.Equal(w.Code, 200)
	assert.Equal(w.headerCalls, 1)
	assert.Equal(w.writeCalls, 1)
	assert.Equal(calls.Load(), int32(2))
}
