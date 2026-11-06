package ownerapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func deleteHeldCredential(t *testing.T, v *storage.Vault,
	root, local key.Public, signer key.Handle,
) (http.Handler, string) {
	t.Helper()
	defer assert.PushTester(t)()
	h, file, bind := try.To3(NewFirstUseCredentials(t.Context(), v,
		root, local, signer, t.TempDir()))
	bind(nil)
	return h, strings.TrimSpace(strings.TrimPrefix(
		string(try.To1(os.ReadFile(file))), "Authorization: "))
}

func TestDeleteHeldAuthAndRoutingBeforeBody(t *testing.T) {
	defer assert.PushTester(t)()
	h, auth := deleteHeldCredential(t, nil, nil, nil, nil)
	for _, tc := range []struct {
		method, path, media, extra string
		status                     int
	}{
		{"POST", deleteHeldPath, "application/json", "auth", 401},
		{"GET", deleteHeldPath, "application/json", "", 405},
		{"HEAD", deleteHeldPath, "application/json", "", 405},
		{"PUT", deleteHeldPath, "application/json", "", 405},
		{"DELETE", deleteHeldPath, "application/json", "", 405},
		{"OPTIONS", deleteHeldPath, "application/json", "", 405},
		{"POST", deleteHeldPath + "/", "application/json", "", 404},
		{"POST", "/owner/pw/holding/%64elete", "application/json", "", 404},
		{"POST", "/owner//pw/holding/delete", "application/json", "", 404},
		{"POST", "/owner/pw/../pw/holding/delete", "application/json", "", 404},
		{"POST", deleteHeldPath + "?", "application/json", "", 400},
		{"POST", deleteHeldPath + "?root=x", "application/json", "", 400},
		{"POST", deleteHeldPath, "", "", 415},
		{"POST", deleteHeldPath, "text/plain", "", 415},
		{"POST", deleteHeldPath, "application/json, application/json", "", 415},
		{"POST", deleteHeldPath, "application/json", "media", 415},
		{"POST", deleteHeldPath, "application/json", "fragment", 400},
		{"POST", deleteHeldPath, "application/json", "raw fragment", 400},
		{"POST", deleteHeldPath, "application/json", "opaque", 404},
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
				r.URL.Opaque = "//localhost" + deleteHeldPath
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

func TestDeleteHeldEarlierCredentialsAndPeer(t *testing.T) {
	defer assert.PushTester(t)()
	operational, _ := deleteHeldCredential(t, nil, nil, nil, nil)
	for _, constructor := range []func(context.Context, *storage.Vault,
		key.Public, key.Public, string) (http.Handler, string, error){
		NewStatusCredentials, NewReadCredentials, NewEvidenceCredentials,
		func(ctx context.Context, v *storage.Vault, root, child key.Public,
			dir string,
		) (http.Handler, string, error) {
			h, file, _, err := NewEstablishmentCredentials(ctx, v, root, child, nil, dir)
			return h, file, err
		},
		func(ctx context.Context, v *storage.Vault, root, child key.Public,
			dir string,
		) (http.Handler, string, error) {
			h, file, _, err := NewAcceptanceCredentials(ctx, v, root, child, nil, dir)
			return h, file, err
		},
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
		assert.Equal(deviceRequest(operational, auth, "POST", denyPath,
			`{"peer_public_key_hex":"00"}`).Code, 401)
		for _, handler := range []http.Handler{h,
			peerapi.NewHandler(nil, nil, nil),
			peerapi.NewEstablishmentHandler(nil, http.NotFoundHandler()),
			peerapi.NewFirstUseHandler(nil, http.NotFoundHandler()),
			peerapi.NewMessageHandler(nil, http.NotFoundHandler()),
			peerapi.NewAdHandler(nil, nil, nil, ""),
			peerapi.NewProofHandler(nil, nil, nil, "", nil),
			peerapi.NewChallengeHandler(nil, nil, nil, "",
				peerapi.NewHandler(nil, nil, nil)),
			peerapi.NewAcceptanceHandler(nil, nil, nil, "", nil,
				peerapi.NewHandler(nil, nil, nil)),
		} {
			for _, path := range []string{deleteHeldPath, denyPath, messageSendPath} {
				for _, method := range []string{"POST", "GET"} {
					r := httptest.NewRequest(
						method,
						path,
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
}
