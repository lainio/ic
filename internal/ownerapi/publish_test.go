package ownerapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const publishPath = "/owner/ads/publish"

func publicationCredential(t *testing.T, vault *storage.Vault, root, child key.Public, signer key.Handle) (http.Handler, string, func(net.Listener)) {
	t.Helper()
	defer assert.PushTester(t)()
	h, file, configure := try.To3(NewPublicationCredentials(t.Context(), vault, root, child, signer, t.TempDir()))
	return h, strings.TrimSpace(strings.TrimPrefix(string(try.To1(os.ReadFile(file))), "Authorization: ")), configure
}

func publicationListener(t *testing.T) net.Listener {
	t.Helper()
	defer assert.PushTester(t)()
	config := &net.ListenConfig{}
	listener := try.To1(config.Listen(t.Context(), "tcp", "127.0.0.1:0"))
	t.Cleanup(func() { assert.NoError(listener.Close()) })
	return listener
}

func TestPublicationRequestBoundary(t *testing.T) {
	defer assert.PushTester(t)()
	f := newDeviceFixture(t)
	signer := &deviceProbe{Handle: key.New()}
	root := try.To1(signer.Handle.CBORPublicKey())
	// A closed Vault makes an accidental domain call observable as 500.
	try.To(f.vault.Close())
	h, auth, configure := publicationCredential(t, f.vault, root, root, signer)
	configure(publicationListener(t))
	defer f.unchanged(t)()
	for _, tc := range []struct {
		method, path, body, media string
		status                    int
	}{
		{"GET", publishPath, "{}", "application/json", 405},
		{"HEAD", publishPath, "{}", "application/json", 405},
		{"PUT", publishPath, "{}", "application/json", 405},
		{"DELETE", publishPath, "{}", "application/json", 405},
		{"OPTIONS", publishPath, "{}", "application/json", 405},
		{"POST", publishPath + "/", "{}", "application/json", 404},
		{"POST", "/owner/ads/%70ublish", "{}", "application/json", 404},
		{"POST", "/owner//ads/publish", "{}", "application/json", 404},
		{"POST", "/owner/ads/../ads/publish", "{}", "application/json", 404},
		{"POST", publishPath + "?", "{}", "application/json", 400},
		{"POST", publishPath + "?slot=1", "{}", "application/json", 400},
		{"POST", publishPath, "{}", "", 415},
		{"POST", publishPath, "{}", "text/plain", 415},
		{"POST", publishPath, "{}", "application/json, application/json", 415},
		{"POST", publishPath, "", "application/json", 400},
		{"POST", publishPath, "null", "application/json", 400},
		{"POST", publishPath, "[]", "application/json", 400},
		{"POST", publishPath, "{ }", "application/json", 400},
		{"POST", publishPath, `{"peer_url":"http://127.0.0.1:1/peer/introduction"}`, "application/json", 400},
		{"POST", publishPath, `{"root":"x","node":"x","device_id":"x"}`, "application/json", 400},
		{"POST", publishPath, `{"slot":1,"epoch":0,"token":"x","clock":1}`, "application/json", 400},
		{"POST", publishPath, `{"signing_payload":"x"}`, "application/json", 400},
		{"POST", publishPath, `{"x":0,"x":1}`, "application/json", 400},
		{"POST", publishPath, "{} {}", "application/json", 400},
		{"POST", publishPath, "{}x", "application/json", 400},
		{"POST", publishPath, "\u00a0{}", "application/json", 400},
		{"POST", publishPath, strings.Repeat(" ", 63) + "{}", "application/json", 413},
	} {
		for _, credential := range []string{"", "Bearer wrong", auth} {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Authorization", credential)
			r.Header.Set("Content-Type", tc.media)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := tc.status
			if credential != auth {
				want = http.StatusUnauthorized
				assert.Equal(string(try.To1(io.ReadAll(r.Body))), tc.body)
			}
			assert.Equal(w.Code, want, tc.path, tc.body)
			assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
			if want == 405 {
				assert.Equal(w.Header().Get("Allow"), "POST")
			}
		}
	}
	for _, invalid := range []string{"duplicate media", "fragment", "raw fragment"} {
		r := httptest.NewRequest(http.MethodPost, publishPath, strings.NewReader("{}"))
		r.Header.Set("Authorization", auth)
		r.Header.Set("Content-Type", "application/json")
		want := 400
		switch invalid {
		case "duplicate media":
			r.Header.Add("Content-Type", "application/json")
			want = 415
		case "fragment":
			r.URL.Fragment = "selector"
		default:
			r.URL.RawFragment = "%73elector"
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assert.Equal(w.Code, want)
		assert.Equal(string(try.To1(io.ReadAll(r.Body))), "{}")
	}
	reader := strings.NewReader(strings.Repeat(" ", 1024))
	r := httptest.NewRequest(http.MethodPost, publishPath, reader)
	r.ContentLength = 1
	r.Header.Set("Authorization", auth)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(w.Code, 413)
	assert.Equal(reader.Len(), 1024-65)
	assert.Equal(signer.publics.Load(), int32(0))
	assert.Equal(signer.signs.Load(), int32(0))
}

func TestPublicationUnavailableToEarlierCredentialsAndPeer(t *testing.T) {
	defer assert.PushTester(t)()
	for _, constructor := range []func(context.Context, *storage.Vault, key.Public, key.Public, string) (http.Handler, string, error){
		NewStatusCredentials, NewReadCredentials, NewEvidenceCredentials,
		func(ctx context.Context, v *storage.Vault, root, child key.Public, dir string) (http.Handler, string, error) {
			return NewDeviceCredentials(ctx, v, root, child, nil, dir)
		},
	} {
		h, file := try.To2(constructor(t.Context(), nil, nil, nil, t.TempDir()))
		auth := strings.TrimSpace(strings.TrimPrefix(string(try.To1(os.ReadFile(file))), "Authorization: "))
		for _, method := range []string{"GET", "POST"} {
			assert.Equal(deviceRequest(h, auth, method, publishPath, "{}").Code, 404)
			assert.Equal(deviceRequest(peerapi.NewHandler(nil, nil, nil), auth, method, publishPath, "{}").Code, 404)
		}
	}
}

func TestPublicationNeedsBoundEndpoint(t *testing.T) {
	defer assert.PushTester(t)()
	f := newDeviceFixture(t)
	signer := &deviceProbe{Handle: key.New()}
	root := try.To1(signer.Handle.CBORPublicKey())
	h, auth, configure := publicationCredential(t, f.vault, root, root, signer)
	assert.Equal(signer.publics.Load(), int32(0))
	assert.Equal(deviceRequest(h, auth, "POST", bootstrapPath, "{}").Code, 200)
	assert.Equal(signer.signs.Load(), int32(1))
	defer f.unchanged(t)()
	assert.Equal(deviceRequest(h, auth, "POST", publishPath, "{}").Code, 409)
	configure(nil)
	configure(publicationListener(t)) // Disabled invocation cannot later change.
	assert.Equal(deviceRequest(h, auth, "POST", publishPath, "{}").Code, 409)
	try.To(f.vault.Close())
	assert.Equal(deviceRequest(h, auth, "POST", publishPath, "{}").Code, 409)
	assert.Equal(signer.publics.Load(), int32(1))
	assert.Equal(signer.signs.Load(), int32(1))
}

func TestPublicationFailuresPreserveCurrentAndAllowance(t *testing.T) {
	for _, scenario := range []string{"no Known", "no bootstrap", "missing signer", "wrong signer", "unavailable signer", "ad signing failure", "bad signature", "tampered ad", "exhausted", "closed"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newDeviceFixture(t)
			signer := &deviceProbe{Handle: key.New()}
			root := key.Public(try.To1(signer.Handle.CBORPublicKey()))
			child := root
			var handle key.Handle = signer
			listener := publicationListener(t)
			endpoint := "http://" + listener.Addr().String() + "/peer/introduction"
			if scenario != "no bootstrap" && scenario != "no Known" {
				try.To1(device.BootstrapLocal(f.vault, root, root, signer.Handle))
				try.To1(ads.PublishLocal(f.vault, root, root, signer.Handle, endpoint, time.Now()))
			}
			want, signs := 409, int32(0)
			switch scenario {
			case "no Known":
				child = try.To1(key.New().CBORPublicKey())
			case "missing signer":
				handle = nil
			case "wrong signer":
				signer.Handle = key.New()
			case "unavailable signer":
				signer.sign = func([]byte) ([]byte, error) { return nil, errors.New("private provider diagnostic") }
				signs = 1
			case "ad signing failure", "bad signature":
				signer.sign = func(data []byte) ([]byte, error) {
					if signer.signs.Load() == 1 {
						return signer.Handle.Sign(data)
					}
					if scenario == "bad signature" {
						return []byte("bad signature"), nil
					}
					return nil, errors.New("private signing diagnostic")
				}
				want, signs = 500, 2
			case "tampered ad":
				try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					ns := try.To1(tx.ChildForUpdate([]byte("local-current-ad-v1")))
					return ns.Put([]byte("slot-1"), []byte("private corrupt record"))
				}))
				want, signs = 500, 2
			case "exhausted":
				f.lease.remaining.Store(0)
				want, signs = 500, 2
			case "closed":
				try.To(f.vault.Close())
				want = 500
			}
			h, auth, configure := publicationCredential(t, f.vault, root, child, handle)
			configure(listener)
			assert.Equal(signer.publics.Load(), int32(0))
			assert.Equal(signer.signs.Load(), int32(0))
			defer f.unchanged(t)()
			w := deviceRequest(h, auth, "POST", publishPath, "{}")
			assert.Equal(w.Code, want)
			assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
			assert.Equal(signer.signs.Load(), signs)
		})
	}
}

func TestPublicationExplicitReplacementAndLostResponse(t *testing.T) {
	defer assert.PushTester(t)()
	f := newDeviceFixture(t)
	signer := &deviceProbe{Handle: key.New()}
	root := try.To1(signer.Handle.CBORPublicKey())
	try.To1(device.BootstrapLocal(f.vault, root, root, signer.Handle))
	h, auth, configure := publicationCredential(t, f.vault, root, root, signer)
	listener := publicationListener(t)
	configure(listener)
	configure(publicationListener(t)) // The first bound endpoint stays fixed.
	remaining := f.lease.remaining.Load()
	var previous ads.Current
	for i := range 2 {
		w := deviceRequest(h, auth, "POST", publishPath, strings.Repeat(" ", 58)+"\t\r\n{}\n")
		assert.Equal(w.Code, 200)
		assert.Equal(w.Header().Get("Content-Type"), "application/json")
		assert.Equal(w.Header().Get("Cache-Control"), "no-store")
		current, found := try.To2(ads.ReadCurrentLocal(f.vault, root, root, time.Now()))
		assert.That(found)
		var fields map[string]json.RawMessage
		try.To(json.Unmarshal(w.Body.Bytes(), &fields))
		assert.Equal(len(fields), 5)
		assert.Equal(string(fields["published"]), "true")
		assert.Equal(string(fields["slot"]), "1")
		assert.Equal(string(fields["epoch"]), "0")
		assert.DeepEqual(fields["expires_unix_nano"], json.RawMessage(try.To1(json.Marshal(current.Payload.ExpiresUnixNano))))
		assert.DeepEqual(fields["peer_introduction_url"], json.RawMessage(try.To1(json.Marshal("http://"+listener.Addr().String()+"/peer/introduction"))))
		if i > 0 {
			assert.ThatNot(bytes.Equal(previous.Payload.Token, current.Payload.Token))
			assert.ThatNot(bytes.Equal(previous.Signature, current.Signature))
			assert.That(current.Payload.ExpiresUnixNano > previous.Payload.ExpiresUnixNano)
		}
		previous = current
	}
	r := httptest.NewRequest(http.MethodPost, publishPath, strings.NewReader("{}"))
	r.Header.Set("Authorization", auth)
	r.Header.Set("Content-Type", "application/json")
	failed := &ownerStatusFailedWriter{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(failed, r)
	assert.Equal(failed.headerCalls, 1)
	assert.Equal(failed.writeCalls, 1)
	current, found := try.To2(ads.ReadCurrentLocal(f.vault, root, root, time.Now()))
	assert.That(found)
	assert.ThatNot(bytes.Equal(previous.Payload.Token, current.Payload.Token))
	assert.Equal(signer.signs.Load(), int32(6)) // One usability probe and one ad per request; no retry.
	assert.Equal(f.lease.remaining.Load(), remaining-3)
	defer f.unchanged(t)()
	_, _, configure = publicationCredential(t, f.vault, root, root, signer)
	configure(listener)
	assert.Equal(signer.signs.Load(), int32(6)) // Reconstructing never probes or renews.
}

func TestPeerAdNeverUsesPublicationSignerOrEncryption(t *testing.T) {
	defer assert.PushTester(t)()
	f := newDeviceFixture(t)
	root := key.New()
	r := try.To1(root.CBORPublicKey())
	signer := &deviceProbe{Handle: key.New()}
	child := try.To1(signer.Handle.CBORPublicKey())
	proposal := intro.New(key.Info{Public: r}).Introduce(root, key.Info{Public: child})
	try.To1(onboarding.SignAfterStoredChoice(f.vault, signer, r, r, proposal))
	choice, found := try.To2(onboarding.ReadStoredChoice(f.vault, r, child))
	assert.That(found)
	try.To2(onboarding.SaveIntroduction(f.vault, r, proposal.Bytes(), choice.Acceptance))
	try.To1(onboarding.VerifyReceived(f.vault, r))
	owner, auth, configure := publicationCredential(t, f.vault, r, child, signer)
	listener := publicationListener(t)
	configure(listener)
	peer := peerapi.NewAdHandler(f.vault, r, child, "http://"+listener.Addr().String()+"/peer/introduction")
	read := func(status int) []byte {
		t.Helper()
		defer f.unchanged(t)()
		signs, publics := signer.signs.Load(), signer.publics.Load()
		w := httptest.NewRecorder()
		peer.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/peer/ad", nil))
		assert.Equal(w.Code, status)
		assert.Equal(signer.signs.Load(), signs)
		assert.Equal(signer.publics.Load(), publics)
		return bytes.Clone(w.Body.Bytes())
	}
	read(409)
	assert.Equal(deviceRequest(owner, auth, "POST", bootstrapPath, "{}").Code, 200)
	read(409)
	assert.Equal(deviceRequest(owner, auth, "POST", publishPath, "{}").Code, 200)
	current, found := try.To2(ads.ReadCurrentLocal(f.vault, r, child, time.Now()))
	assert.That(found)
	first := read(200)
	// Historical signature disclosure does not probe present device liveness.
	signer.sign = func([]byte) ([]byte, error) { return nil, errors.New("signer unavailable") }
	f.lease.remaining.Store(0)
	for range 3 {
		assert.DeepEqual(read(200), first)
	}
	after, found := try.To2(ads.ReadCurrentLocal(f.vault, r, child, time.Now()))
	assert.That(found)
	assert.DeepEqual(try.To1(wire.Marshal(after)), try.To1(wire.Marshal(current)))
	assert.Equal(deviceRequest(peer, auth, "POST", publishPath, "{}").Code, 404)
	assert.Equal(deviceRequest(peer, auth, "POST", bootstrapPath, "{}").Code, 404)
}

func TestEveryOwnerCredentialExcludesPeerAd(t *testing.T) {
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
	} {
		h, file := try.To2(constructor(t.Context(), nil, nil, nil, t.TempDir()))
		auth := strings.TrimSpace(strings.TrimPrefix(string(try.To1(os.ReadFile(file))), "Authorization: "))
		for _, method := range []string{"GET", "HEAD", "POST"} {
			w := deviceRequest(h, auth, method, "/peer/ad", "")
			assert.Equal(w.Code, 404)
			assert.Equal(w.Body.String(), "Not Found\n")
		}
	}
}
