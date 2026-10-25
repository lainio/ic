package storage_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/ownerapi"
	"github.com/lainio/ic/key"
)

const checkPath = "/owner/introduction/check"

func checkRequest(authorization string, document []byte) *http.Request {
	r := httptest.NewRequest(
		http.MethodPost,
		checkPath,
		bytes.NewReader(document),
	)
	r.Header.Set("Authorization", authorization)
	r.Header.Set("Content-Type", "application/json")
	return r
}

func assertChecked(t *testing.T, w *httptest.ResponseRecorder,
	subject key.Public, self bool,
) {
	t.Helper()
	defer assert.PushTester(t)()

	assert.Equal(w.Code, http.StatusOK)
	assert.Equal(w.Header().Get("Content-Type"), "application/json")
	assert.Equal(w.Header().Get("Cache-Control"), "no-store")
	assert.That(w.Body.Len() <= 4096)
	var result map[string]any
	try.To(json.Unmarshal(w.Body.Bytes(), &result))
	assert.DeepEqual(result, map[string]any{
		"subject_public_key_hex": hex.EncodeToString(subject), "is_self": self,
	})
}

func TestOwnerCheckExportedEvidence(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	rootPublic := key.Public(try.To1(root.CBORPublicKey()))
	alicePublic := key.Public(try.To1(alice.CBORPublicKey()))
	bobPublic := key.Public(try.To1(bob.CBORPublicKey()))
	proposal := intro.New(key.Info{Public: rootPublic}).Introduce(
		root, key.Info{Public: alicePublic},
		intro.WithEndpoint("http://evidence.invalid/never-fetch", false),
	)
	exporter := newIntroductionFixture(t, rootPublic, alicePublic)
	signer := &choiceSigningHandle{Handle: alice}
	try.To1(onboarding.SignAfterStoredChoice(
		exporter.vault, signer, rootPublic, rootPublic, proposal,
	))
	exporter.assertReadOnly(t)
	exported := httptest.NewRecorder()
	exporter.handler.ServeHTTP(exported, exporter.request())
	assert.Equal(exported.Code, http.StatusOK)
	document := bytes.Clone(exported.Body.Bytes())

	// Bob has no local selection. Its copied configuration supplies the Root.
	receiver := newIntroductionFixture(t, rootPublic, bobPublic)
	receiver.assertReadOnly(t)
	for _, f := range []introductionFixture{receiver, exporter} {
		request := checkRequest(f.authorization, document)
		request.URL.RawQuery = "root=other&child=other"
		response := httptest.NewRecorder()
		f.handler.ServeHTTP(response, request)
		assertChecked(t, response, alicePublic, f.vault == exporter.vault)
	}
	assert.Equal(
		try.To1(readOwnerStatus(receiver.handler, receiver.authorization)),
		"unselected",
	)
	assert.Equal(
		try.To1(readOwnerStatus(exporter.handler, exporter.authorization)),
		"completed",
	)
	assert.Equal(signer.signCalls, 1)
	assert.That(strings.Contains(string(document), `"version":1`))

	// Failure also leaves the completed and unselected local choices intact.
	for _, f := range []introductionFixture{receiver, exporter} {
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, checkRequest(f.authorization, []byte(`{}`)))
		assertCheckError(t, w, http.StatusBadRequest)
	}
	assert.Equal(
		try.To1(readOwnerStatus(receiver.handler, receiver.authorization)),
		"unselected",
	)
	assert.Equal(
		try.To1(readOwnerStatus(exporter.handler, exporter.authorization)),
		"completed",
	)
}

func checkDocument(proposal intro.Path, signature key.Signature) []byte {
	return try.To1(json.Marshal(struct {
		Version    int    `json:"version"`
		Proposal   []byte `json:"proposal"`
		Acceptance []byte `json:"acceptance"`
	}{1, proposal.Bytes(), signature}))
}

func checkHandler(t *testing.T, root, child key.Public) (http.Handler, string) {
	t.Helper()
	defer assert.PushTester(t)()

	// A nil Vault makes even an accidental View fail. No signer is supplied.
	rootCopy, childCopy := bytes.Clone(root), bytes.Clone(child)
	handler, file := try.To2(ownerapi.NewReadCredentials(
		t.Context(), nil, rootCopy, childCopy, t.TempDir(),
	))
	clear(rootCopy)
	clear(childCopy)
	header := string(try.To1(os.ReadFile(file)))
	return handler, strings.TrimSpace(
		strings.TrimPrefix(header, "Authorization: "),
	)
}

func assertCheckError(t *testing.T, w *httptest.ResponseRecorder, code int) {
	t.Helper()
	defer assert.PushTester(t)()

	assert.Equal(w.Code, code)
	assert.Equal(w.Body.String(), http.StatusText(code)+"\n")
	assert.Equal(w.Header().Get("Cache-Control"), "no-store")
	assert.Equal(w.Header().Get("Content-Type"), "text/plain; charset=utf-8")
}

func TestOwnerCheckPathsWithoutVaultOrSigner(t *testing.T) {
	defer assert.PushTester(t)()

	root, parent, child := key.New(), key.New(), key.New()
	rootPublic := key.Public(try.To1(root.CBORPublicKey()))
	parentPublic := key.Public(try.To1(parent.CBORPublicKey()))
	childPublic := key.Public(try.To1(child.CBORPublicKey()))
	handler, authorization := checkHandler(t, rootPublic, parentPublic)
	for _, scenario := range []string{
		"longer path", "wrong Root", "broken predecessor", "wrong acceptance",
		"root ID", "parent ID", "child ID", "backup", "rotation", "root rotation",
		"empty path", "root only",
	} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()

			rootInfo := key.Info{Public: rootPublic}
			parentInfo := key.Info{Public: parentPublic}
			childInfo := key.Info{Public: childPublic}
			switch scenario {
			case "root ID":
				rootInfo.ID = []byte("synthetic-private-id")
			case "parent ID":
				parentInfo.ID = []byte("synthetic-private-id")
			case "child ID":
				childInfo.ID = []byte("synthetic-private-id")
			}
			rootPath := intro.New(rootInfo)
			if scenario == "root rotation" {
				rootPath[0].Body.Options.Rotation = true
			}
			proposal := rootPath.Introduce(root, parentInfo).
				Introduce(parent, childInfo)
			switch scenario {
			case "broken predecessor":
				proposal[2].Body.Prev[0] ^= 1
			case "backup":
				proposal[2].Body.Options.BackupKeyIndex = 1
			case "rotation":
				proposal[2].Body.Options.Rotation = true
			}
			// Re-sign altered fields so rejection is not just a stale signature.
			proposal[2].ParentSig = nil
			proposal[2].ParentSig = try.To1(parent.Sign(proposal[2].Bytes()))
			assert.That(proposal[2].VerifySignature(parentPublic))
			acceptance := try.To1(proposal.SignAcceptance(child))
			assert.NoError(proposal.VerifyAcceptance(acceptance))
			h, auth := handler, authorization
			switch scenario {
			case "wrong Root":
				h, auth = checkHandler(t, childPublic, parentPublic)
			case "broken predecessor":
				assert.ErrorIs(
					proposal.ProveFromRoot(rootPublic),
					intro.ErrBrokenPath,
				)
			case "wrong acceptance":
				other := intro.New(rootInfo).Introduce(root, childInfo)
				acceptance = try.To1(other.SignAcceptance(child))
			case "empty path":
				proposal = intro.Path{}
			case "root only":
				proposal = rootPath
			}
			if strings.HasSuffix(scenario, " ID") {
				assert.NoError(proposal.ProveFromRoot(rootPublic))
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(
				w,
				checkRequest(auth, checkDocument(proposal, acceptance)),
			)
			if scenario == "longer path" {
				assertChecked(t, w, childPublic, false)
				failed := &ownerStatusFailedWriter{
					ResponseRecorder: httptest.NewRecorder(),
				}
				h.ServeHTTP(
					failed,
					checkRequest(auth, checkDocument(proposal, acceptance)),
				)
				assert.Equal(failed.Code, http.StatusOK)
				assert.Equal(failed.headerCalls, 1)
				assert.Equal(failed.writeCalls, 1)
			} else {
				assertCheckError(t, w, http.StatusBadRequest)
			}
		})
	}
}

func TestOwnerCheckEnvelopeAndLimits(t *testing.T) {
	defer assert.PushTester(t)()

	root, child := key.New(), key.New()
	rootPublic := key.Public(try.To1(root.CBORPublicKey()))
	childPublic := key.Public(try.To1(child.CBORPublicKey()))
	proposal := intro.New(key.Info{Public: rootPublic}).
		Introduce(root, key.Info{Public: childPublic})
	acceptance := try.To1(proposal.SignAcceptance(child))
	document := checkDocument(proposal, acceptance)
	handler, authorization := checkHandler(t, rootPublic, childPublic)
	// Keep all unrelated fields genuine so each malformed envelope must be
	// rejected by decoding, rather than accidentally by path verification.
	replace := strings.NewReplacer(
		"AQ==", base64.StdEncoding.EncodeToString(proposal.Bytes()),
		"Ag==", base64.StdEncoding.EncodeToString(acceptance),
	)
	for _, document := range []string{
		``, `null`, `[]`, `{}`, `{"version":1,"proposal":"AQ=="}`,
		`{"proposal":"AQ==","acceptance":"Ag=="}`,
		`{"version":1,"acceptance":"Ag=="}`,
		`{"version":1,"proposal":"AQ==","acceptance":"Ag==","extra":0}`,
		`{"version":1,"version":1,"proposal":"AQ==","acceptance":"Ag=="}`,
		`{"version":1,"proposal":"AQ==","proposal":"Ag==","acceptance":"Ag=="}`,
		`{"version":1,"proposal":"AQ==","acceptance":"Ag==","acceptance":"Ag=="}`,
		`{"version":2,"proposal":"AQ==","acceptance":"Ag=="}`,
		`{"version":1.0,"proposal":"AQ==","acceptance":"Ag=="}`,
		`{"version":1e0,"proposal":"AQ==","acceptance":"Ag=="}`,
		`{"version":"1","proposal":"AQ==","acceptance":"Ag=="}`,
		`{"version":null,"proposal":"AQ==","acceptance":"Ag=="}`,
		`{"version":1,"proposal":[],"acceptance":"Ag=="}`,
		`{"version":1,"proposal":"AQ==","acceptance":true}`,
		`{"version":1,"proposal":"AQ==","acceptance":null}`,
		`{"version":1,"proposal":"","acceptance":"Ag=="}`,
		`{"version":1,"proposal":"AQ==","acceptance":""}`,
		`{"version":1,"proposal":"AQ","acceptance":"Ag=="}`,
		`{"version":1,"proposal":"_w==","acceptance":"Ag=="}`,
		`{"version":1,"proposal":"AR==","acceptance":"Ag=="}`,
		`{"version":1,"proposal":"AQ==\n","acceptance":"Ag=="}`,
		`{"version":1,"proposal":"AQ==","acceptance":"bad!"}`,
		`{"version":1,"proposal":"AQ==","acceptance":"Ag=="} {}`,
		`{"version":1,"proposal":"AQ==","acceptance":"Ag=="} trailing`,
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(
			w,
			checkRequest(authorization, []byte(replace.Replace(document))),
		)
		assertCheckError(t, w, http.StatusBadRequest)
	}

	boundary := append(
		bytes.Clone(document),
		bytes.Repeat([]byte(" "), 128*1024-len(document))...)
	for _, length := range []int64{-1, 1, 128 * 1024 * 2} {
		for _, oversized := range []bool{false, true} {
			body := bytes.Clone(boundary)
			if oversized {
				body = append(body, bytes.Repeat([]byte(" "), 128*1024)...)
			}
			r := checkRequest(authorization, nil)
			reader := &checkCountingReader{Reader: bytes.NewReader(body)}
			r.Body = io.NopCloser(reader)
			r.ContentLength = length
			r.Header.Set("Content-Type", "application/json; charset=utf-8")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			assert.That(reader.bytesRead <= 128*1024+1)
			if oversized {
				assertCheckError(t, w, http.StatusRequestEntityTooLarge)
			} else {
				assertChecked(t, w, childPublic, true)
			}
		}
	}
}

type checkCountingReader struct {
	io.Reader
	bytesRead int
}

func (r *checkCountingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.bytesRead += n
	return n, err
}

func TestOwnerCheckAuthenticationAndRoutes(t *testing.T) {
	defer assert.PushTester(t)()

	handler, authorization := checkHandler(t, nil, nil)
	for _, tc := range []struct {
		method, path, media, auth string
		status                    int
	}{
		{http.MethodPost, checkPath, "application/json", "", http.StatusUnauthorized},
		{http.MethodPost, checkPath, "application/json", "Bearer wrong", http.StatusUnauthorized},
		{http.MethodGet, checkPath, "application/json", authorization, http.StatusMethodNotAllowed},
		{http.MethodPost, checkPath + "/", "application/json", authorization, http.StatusNotFound},
		{http.MethodPost, checkPath, "", authorization, http.StatusUnsupportedMediaType},
		{http.MethodPost, checkPath, "text/plain", authorization, http.StatusUnsupportedMediaType},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		reader := &checkCountingReader{
			Reader: strings.NewReader("must not read"),
		}
		r.Body = io.NopCloser(reader)
		r.Header.Set("Authorization", tc.auth)
		r.Header.Set("Content-Type", tc.media)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		assertCheckError(t, w, tc.status)
		assert.Equal(reader.bytesRead, 0)
		if tc.status == http.StatusMethodNotAllowed {
			assert.Equal(w.Header().Get("Allow"), "POST")
		}
	}

	token := bytes.Repeat([]byte{0xab}, 32)
	statusOnly := try.To1(
		ownerapi.NewAuthenticatedStatusHandler(nil, nil, nil, token),
	)
	statusCredentials, file := try.To2(
		ownerapi.NewStatusCredentials(t.Context(), nil, nil, nil, t.TempDir()),
	)
	header := string(try.To1(os.ReadFile(file)))
	for _, tc := range []struct {
		handler http.Handler
		auth    string
	}{
		{ownerapi.NewStatusHandler(nil, nil, nil), ""},
		{statusOnly, "Bearer " + hex.EncodeToString(token)},
		{statusCredentials, strings.TrimSpace(strings.TrimPrefix(header, "Authorization: "))},
	} {
		w := httptest.NewRecorder()
		tc.handler.ServeHTTP(w, checkRequest(tc.auth, []byte(`{}`)))
		assertCheckError(t, w, http.StatusNotFound)
	}
}
