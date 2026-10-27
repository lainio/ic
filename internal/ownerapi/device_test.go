package ownerapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const bootstrapPath = "/owner/device/bootstrap"

// Finite encryption lease, so read-only retries must preserve both bytes and
// usage. The node integration tests use the saved identity and nodevault.
type deviceLease struct {
	secret    []byte
	remaining atomic.Int64
}

func (p *deviceLease) Acquire(context.Context, storage.VaultID, storage.KeyID) (storage.Lease, error) {
	return p, nil
}
func (p *deviceLease) Secret() []byte { return p.secret }
func (*deviceLease) Check() error     { return nil }
func (*deviceLease) Release() error   { return nil }
func (p *deviceLease) ConsumeEncryption() error {
	for {
		n := p.remaining.Load()
		if n == 0 {
			return storage.ErrKeyUsageExhausted
		}
		if p.remaining.CompareAndSwap(n, n-1) {
			return nil
		}
	}
}

type deviceFixture struct {
	vault *storage.Vault
	lease *deviceLease
	path  string
}

func newDeviceFixture(t *testing.T) deviceFixture {
	t.Helper()
	defer assert.PushTester(t)()
	p := &deviceLease{secret: make([]byte, 32)}
	try.To1(rand.Read(p.secret))
	p.remaining.Store(128)
	t.Cleanup(func() { clear(p.secret) })
	path := filepath.Join(t.TempDir(), "vault.db")
	db := try.To1(storage.OpenBolt(path))
	t.Cleanup(func() { assert.NoError(db.Close()) })
	try.To(db.CreateVault(t.Context(), storage.VaultID{1}, storage.KeyID{1}, p))
	return deviceFixture{
		try.To1(db.OpenVault(t.Context(), storage.VaultID{1}, storage.KeyID{1}, p)), p, path,
	}
}

func (f deviceFixture) unchanged(t *testing.T) func() {
	t.Helper()
	defer assert.PushTester(t)()
	before := try.To1(os.ReadFile(f.path))
	remaining := f.lease.remaining.Load()
	return func() {
		t.Helper()
		assert.DeepEqual(try.To1(os.ReadFile(f.path)), before)
		assert.Equal(f.lease.remaining.Load(), remaining)
	}
}

type deviceProbe struct {
	key.Handle
	publics, signs atomic.Int32
	sign           func([]byte) ([]byte, error)
}

func (p *deviceProbe) CBORPublicKey() ([]byte, error) {
	p.publics.Add(1)
	return p.Handle.CBORPublicKey()
}
func (p *deviceProbe) Sign(data []byte) ([]byte, error) {
	p.signs.Add(1)
	if p.sign != nil {
		return p.sign(data)
	}
	return p.Handle.Sign(data)
}
func (*deviceProbe) ID() []byte                 { panic("must not expose handle") }
func (*deviceProbe) Verify([]byte, []byte) bool { panic("must verify independently") }

func deviceCredential(t *testing.T, f deviceFixture, root, child key.Public, signer key.Handle) (http.Handler, string) {
	t.Helper()
	defer assert.PushTester(t)()
	h, file := try.To2(NewDeviceCredentials(t.Context(), f.vault, root, child, signer, t.TempDir()))
	return h, strings.TrimSpace(strings.TrimPrefix(string(try.To1(os.ReadFile(file))), "Authorization: "))
}

func deviceRequest(h http.Handler, auth, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", auth)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestDeviceRequestAndCredentialBoundaries(t *testing.T) {
	defer assert.PushTester(t)()
	f := newDeviceFixture(t)
	signer := &deviceProbe{Handle: key.New()}
	root := try.To1(signer.Handle.CBORPublicKey())
	h, auth := deviceCredential(t, f, root, root, signer)
	defer f.unchanged(t)()
	for _, tc := range []struct {
		method, path, body, media string
		status                    int
	}{
		{"GET", bootstrapPath, "{}", "application/json", 405},
		{"HEAD", bootstrapPath, "{}", "application/json", 405},
		{"PUT", bootstrapPath, "{}", "application/json", 405},
		{"DELETE", bootstrapPath, "{}", "application/json", 405},
		{"OPTIONS", bootstrapPath, "{}", "application/json", 405},
		{"POST", bootstrapPath + "/", "{}", "application/json", 404},
		{"POST", "/owner/device/%62ootstrap", "{}", "application/json", 404},
		{"POST", "/owner//device/bootstrap", "{}", "application/json", 404},
		{"POST", "/owner/device/../device/bootstrap", "{}", "application/json", 404},
		{"POST", bootstrapPath + "?", "{}", "application/json", 400},
		{"POST", bootstrapPath + "?root=other", "{}", "application/json", 400},
		{"POST", bootstrapPath, "{}", "", 415},
		{"POST", bootstrapPath, "{}", "text/plain", 415},
		{"POST", bootstrapPath, "{}", "application/json, application/json", 415},
		{"POST", bootstrapPath, "", "application/json", 400},
		{"POST", bootstrapPath, "null", "application/json", 400},
		{"POST", bootstrapPath, "[]", "application/json", 400},
		{"POST", bootstrapPath, "{ }", "application/json", 400},
		{"POST", bootstrapPath, `{"device_id":"x"}`, "application/json", 400},
		{"POST", bootstrapPath, `{"root":"x"}`, "application/json", 400},
		{"POST", bootstrapPath, `{"identity":"x"}`, "application/json", 400},
		{"POST", bootstrapPath, `{"signing_input":"x"}`, "application/json", 400},
		{"POST", bootstrapPath, `{"peer_url":"x"}`, "application/json", 400},
		{"POST", bootstrapPath, `{"x":0,"x":1}`, "application/json", 400},
		{"POST", bootstrapPath, "{} {}", "application/json", 400},
		{"POST", bootstrapPath, "{}x", "application/json", 400},
		{"POST", bootstrapPath, "\u00a0{}", "application/json", 400},
		{"POST", bootstrapPath, strings.Repeat(" ", 63) + "{}", "application/json", 413},
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
			assert.Equal(w.Code, want)
			assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
			if want == 405 {
				assert.Equal(w.Header().Get("Allow"), "POST")
			}
		}
	}
	for _, credential := range []string{"", "Bearer wrong"} {
		assert.Equal(deviceRequest(h, credential, "POST", bootstrapPath, "{}").Code, 401)
	}
	for _, invalid := range []string{"duplicate media", "fragment", "raw fragment"} {
		r := httptest.NewRequest(http.MethodPost, bootstrapPath, strings.NewReader("{}"))
		r.Header.Set("Authorization", auth)
		r.Header.Set("Content-Type", "application/json")
		want := http.StatusBadRequest
		switch invalid {
		case "duplicate media":
			r.Header.Add("Content-Type", "application/json")
			want = http.StatusUnsupportedMediaType
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
	r := httptest.NewRequest(http.MethodPost, bootstrapPath, reader)
	r.ContentLength = 1
	r.Header.Set("Authorization", auth)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(w.Code, http.StatusRequestEntityTooLarge)
	assert.Equal(reader.Len(), 1024-65)
	assert.Equal(signer.publics.Load(), int32(0))
	assert.Equal(signer.signs.Load(), int32(0))
}

func TestDeviceUnavailableToEarlierCredentialsAndPeer(t *testing.T) {
	defer assert.PushTester(t)()
	for _, constructor := range []func(context.Context, *storage.Vault, key.Public, key.Public, string) (http.Handler, string, error){
		NewStatusCredentials, NewReadCredentials, NewEvidenceCredentials,
	} {
		h, file := try.To2(constructor(t.Context(), nil, nil, nil, t.TempDir()))
		auth := strings.TrimSpace(strings.TrimPrefix(string(try.To1(os.ReadFile(file))), "Authorization: "))
		for _, method := range []string{"GET", "POST"} {
			assert.Equal(deviceRequest(h, auth, method, bootstrapPath, "{}").Code, 404)
			assert.Equal(deviceRequest(peerapi.NewHandler(nil, nil, nil), auth, method, bootstrapPath, "{}").Code, 404)
		}
	}
}

func TestDeviceRootBootstrapAndLostAcknowledgement(t *testing.T) {
	for _, scenario := range []string{"success", "lost acknowledgement"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newDeviceFixture(t)
			signer := &deviceProbe{Handle: key.New()}
			root := try.To1(signer.Handle.CBORPublicKey())
			configuredRoot, configuredChild := bytes.Clone(root), bytes.Clone(root)
			h, auth := deviceCredential(t, f, configuredRoot, configuredChild, signer)
			clear(configuredRoot)
			clear(configuredChild)
			assert.Equal(signer.signs.Load(), int32(0))
			assert.Equal(try.To1(device.InspectLocal(f.vault, root, root, nil)), device.Local{})
			remaining := f.lease.remaining.Load()
			r := httptest.NewRequest(http.MethodPost, bootstrapPath,
				strings.NewReader(strings.Repeat(" ", 58)+"\t\r\n{}\n")) // Exactly 64 bytes.
			r.Header.Set("Authorization", auth)
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			if scenario == "lost acknowledgement" {
				failed := &ownerStatusFailedWriter{ResponseRecorder: w}
				h.ServeHTTP(failed, r)
				assert.Equal(failed.headerCalls, 1)
				assert.Equal(failed.writeCalls, 1)
			} else {
				h.ServeHTTP(w, r)
				assert.Equal(w.Body.String(), `{"authorized":true,"usable":true}`)
			}
			assert.Equal(w.Code, http.StatusOK)
			assert.Equal(w.Header().Get("Content-Type"), "application/json")
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
			assert.Equal(f.lease.remaining.Load(), remaining-1)
			assert.Equal(signer.signs.Load(), int32(1))
			defer f.unchanged(t)()
			assert.Equal(try.To1(device.InspectLocal(f.vault, root, root, nil)), device.Local{Authorized: true})
			assert.Equal(deviceRequest(h, auth, "POST", bootstrapPath, "{}").Code, 409)
			assert.Equal(signer.signs.Load(), int32(1))
			// Reconstructing operational credentials never probes a persisted
			// authorization; even an unavailable signer leaves retries read-only.
			signer.sign = func([]byte) ([]byte, error) { return nil, errors.New("signer is now unavailable") }
			h, auth = deviceCredential(t, f, root, root, signer)
			assert.Equal(signer.signs.Load(), int32(1))
			assert.Equal(deviceRequest(h, auth, "GET", "/owner/status", "").Code, 200)
			assert.Equal(deviceRequest(h, auth, "POST", bootstrapPath, "{}").Code, 409)
			assert.Equal(signer.signs.Load(), int32(1))
			signer.sign = nil
			assert.Equal(try.To1(device.InspectLocal(f.vault, root, root, signer)), device.Local{Authorized: true, Usable: true})
			assert.Equal(signer.signs.Load(), int32(2))
		})
	}
}

func TestDeviceFailuresAreGenericAndReadOnly(t *testing.T) {
	for _, scenario := range []string{"missing signer", "wrong signer", "failed signer", "binding", "corrupt", "tampered binding", "closed", "exhausted"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newDeviceFixture(t)
			signer := &deviceProbe{Handle: key.New()}
			root := key.Public(try.To1(signer.Handle.CBORPublicKey()))
			child := root
			var handle key.Handle = signer
			want, signs := 500, int32(0)
			switch scenario {
			case "missing signer":
				handle, want = nil, 409
			case "wrong signer":
				signer.Handle, want = key.New(), 409
			case "failed signer":
				signer.sign = func([]byte) ([]byte, error) { return nil, errors.New("secret wrapped handle diagnostic") }
				want, signs = 409, 1
			case "binding":
				child = nil
			case "corrupt":
				try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					ns := try.To1(tx.EnsureChild([]byte("local-device-auth-v1")))
					return ns.Put([]byte("local-software-signer"), []byte("corrupt private data"))
				}))
			case "tampered binding":
				try.To1(device.BootstrapLocal(f.vault, root, root, signer.Handle))
				root = try.To1(key.New().CBORPublicKey())
			case "closed":
				try.To(f.vault.Close())
			case "exhausted":
				f.lease.remaining.Store(0)
				signs = 1
			}
			h, auth := deviceCredential(t, f, root, child, handle)
			defer f.unchanged(t)()
			w := deviceRequest(h, auth, "POST", bootstrapPath, "{}")
			assert.Equal(w.Code, want)
			assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
			assert.Equal(signer.signs.Load(), signs)
		})
	}
}

func TestDeviceSerializesSigningWithEvidenceMutations(t *testing.T) {
	for _, operation := range []string{bootstrapPath, publishPath} {
		for _, path := range []string{"/owner/introductions", fetchPath, verifyPath} {
			t.Run(operation+path, func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newDeviceFixture(t)
				signer := &deviceProbe{Handle: key.New()}
				root := try.To1(signer.Handle.CBORPublicKey())
				other := key.New()
				proposal := intro.New(key.Info{Public: root}).Introduce(signer.Handle, key.Info{Public: try.To1(other.CBORPublicKey())})
				acceptance := try.To1(proposal.SignAcceptance(other))
				document := string(try.To1(onboarding.EncodeIntroduction(onboarding.StoredChoice{Proposal: proposal, Acceptance: acceptance})))
				body := document
				if path == verifyPath {
					try.To2(onboarding.SaveIntroduction(f.vault, root, proposal.Bytes(), acceptance))
					body = "{}"
				}
				if path == fetchPath {
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						_, _ = io.WriteString(w, document)
					}))
					defer server.Close()
					body = `{"peer_url":"` + server.URL + `/peer/introduction"}`
				}
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				defer unblock()
				signer.sign = func(data []byte) ([]byte, error) {
					if signer.signs.Load() == 1 {
						close(entered)
					}
					<-release
					return signer.Handle.Sign(data)
				}
				h, auth := deviceCredential(t, f, root, root, signer)
				secondStatus, totalSigns := 409, int32(1)
				if operation == publishPath {
					try.To1(device.BootstrapLocal(f.vault, root, root, signer.Handle))
					var configure func(net.Listener)
					h, auth, configure = publicationCredential(t, f.vault, root, root, signer)
					configure(publicationListener(t))
					secondStatus, totalSigns = 200, 4
				}
				remaining := f.lease.remaining.Load()
				first, second, mutation := make(chan int, 1), make(chan int, 1), make(chan int, 1)
				go func() { first <- deviceRequest(h, auth, "POST", operation, "{}").Code }()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("request did not reach signer")
				}
				go func() { second <- deviceRequest(h, auth, "POST", operation, "{}").Code }()
				bootstrap := make(chan int, 1)
				go func() { bootstrap <- deviceRequest(h, auth, "POST", bootstrapPath, "{}").Code }()
				go func() { mutation <- deviceRequest(h, auth, "POST", path, body).Code }()
				// An independent write transaction and ordinary reads can complete
				// during the probe: the service mutex must not be a Vault transaction.
				reads := make(chan error, 1)
				go func() {
					reads <- f.vault.Update(func(storage.WriteTx) error { return nil })
				}()
				select {
				case err := <-reads:
					assert.NoError(err)
				case <-time.After(5 * time.Second):
					t.Fatal("signer held a Vault transaction")
				}
				read := make(chan int, 1)
				go func() { read <- deviceRequest(h, auth, "GET", "/owner/introductions", "").Code }()
				assert.Equal(waitDeviceResponse(t, read), 200)
				select {
				case <-mutation:
					t.Fatal("evidence mutation overlapped signing")
				case <-bootstrap:
					t.Fatal("bootstrap overlapped signing request")
				case <-second:
					t.Fatal("second request overlapped signing")
				case <-time.After(50 * time.Millisecond):
				}
				assert.Equal(signer.signs.Load(), int32(1))
				assert.Equal(f.lease.remaining.Load(), remaining)
				unblock()
				assert.Equal(waitDeviceResponse(t, first), 200)
				assert.Equal(waitDeviceResponse(t, second), secondStatus)
				assert.Equal(waitDeviceResponse(t, bootstrap), 409)
				assert.Equal(waitDeviceResponse(t, mutation), 200)
				assert.Equal(signer.signs.Load(), totalSigns)
			})
		}
	}
}

func waitDeviceResponse(t *testing.T, result <-chan int) int {
	t.Helper()
	select {
	case code := <-result:
		return code
	case <-time.After(5 * time.Second):
		t.Fatal("owner request did not finish")
		return 0
	}
}
