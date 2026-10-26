package storage_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/ownerapi"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const receivedPath = "/owner/introductions"

func evidenceCredentials(t *testing.T, f *introductionFixture, root, child key.Public) {
	t.Helper()
	defer assert.PushTester(t)()

	rootCopy, childCopy := bytes.Clone(root), bytes.Clone(child)
	handler, file := try.To2(ownerapi.NewEvidenceCredentials(
		t.Context(), f.vault, rootCopy, childCopy, t.TempDir(),
	))
	clear(rootCopy)
	clear(childCopy)
	f.handler = handler
	f.authorization = strings.TrimSpace(strings.TrimPrefix(
		string(try.To1(os.ReadFile(file))), "Authorization: ",
	))
}

func receivedRequest(auth, method string, document []byte) *http.Request {
	r := checkRequest(auth, document)
	r.Method, r.URL.Path = method, receivedPath
	return r
}

func receivedResponse(f introductionFixture, method string, document []byte) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, receivedRequest(f.authorization, method, document))
	return w
}

func assertSaved(t *testing.T, w *httptest.ResponseRecorder, subject key.Public, self, created bool) {
	t.Helper()
	defer assert.PushTester(t)()

	assert.Equal(w.Code, http.StatusOK)
	assert.Equal(w.Header().Get("Cache-Control"), "no-store")
	assert.Equal(w.Header().Get("Content-Type"), "application/json")
	assert.That(w.Body.Len() <= 4096)
	var result map[string]any
	try.To(json.Unmarshal(w.Body.Bytes(), &result))
	assert.DeepEqual(result, map[string]any{
		"subject_public_key_hex": hex.EncodeToString(subject),
		"is_self":                self, "created": created,
	})
}

func assertListed(t *testing.T, f introductionFixture, self key.Public, subjects ...key.Public) {
	t.Helper()
	defer assert.PushTester(t)()

	w := receivedResponse(f, http.MethodGet, nil)
	assert.Equal(w.Code, http.StatusOK)
	assert.Equal(w.Header().Get("Cache-Control"), "no-store")
	assert.Equal(w.Header().Get("Content-Type"), "application/json")
	assert.That(w.Body.Len() <= 256*1024)
	slices.SortFunc(subjects, func(a, b key.Public) int { return bytes.Compare(a, b) })
	items := make([]any, 0, len(subjects))
	for _, subject := range subjects {
		items = append(items, map[string]any{
			"subject_public_key_hex": hex.EncodeToString(subject),
			"is_self":                bytes.Equal(subject, self),
		})
	}
	var result map[string]any
	try.To(json.Unmarshal(w.Body.Bytes(), &result))
	assert.DeepEqual(result, map[string]any{"introductions": items})
}

func receivedRecord(vault *storage.Vault, subject key.Public) (record []byte, err error) {
	defer err2.Handle(&err, nil)

	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		ns := try.To1(tx.Child([]byte("received-introductions-v1")))
		record, _ = try.To2(ns.Get(subject))
		return nil
	}))
	return record, nil
}

func TestOwnerReceivedExportReopen(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	r, a, b := key.Public(try.To1(root.CBORPublicKey())),
		key.Public(try.To1(alice.CBORPublicKey())), key.Public(try.To1(bob.CBORPublicKey()))
	path := intro.New(key.Info{Public: r}).Introduce(root, key.Info{Public: a},
		intro.WithEndpoint("http://evidence.invalid/never-fetch", false))
	exporter := newIntroductionFixture(t, r, a)
	signer := &choiceSigningHandle{Handle: alice}
	acceptance := try.To1(onboarding.SignAfterStoredChoice(exporter.vault, signer, r, r, path))
	exporter.assertReadOnly(t)
	exported := httptest.NewRecorder()
	exporter.handler.ServeHTTP(exported, exporter.request())
	assert.Equal(exported.Code, http.StatusOK)

	receiver := newIntroductionFixture(t, r, b)
	evidenceCredentials(t, &receiver, r, b)
	assertListed(t, receiver, b)
	own := intro.New(key.Info{Public: r}).Introduce(root, key.Info{Public: b})
	ownAcceptance := try.To1(onboarding.SignAfterStoredChoice(receiver.vault, bob, r, r, own))
	checked := httptest.NewRecorder()
	receiver.handler.ServeHTTP(checked, checkRequest(receiver.authorization, exported.Body.Bytes()))
	assertChecked(t, checked, a, false)
	assertSaved(t, receivedResponse(receiver, http.MethodPost, exported.Body.Bytes()), a, false, true)
	assertSaved(t, receivedResponse(receiver, http.MethodPost, checkDocument(own, ownAcceptance)), b, true, true)
	assertListed(t, receiver, b, a, b)

	// The complete exact pair is retained in one record, separate from choice.
	record := try.To1(receivedRecord(receiver.vault, a))
	assert.DeepEqual(record[5:5+len(path.Bytes())], path.Bytes())
	assert.DeepEqual(record[5+len(path.Bytes()):], []byte(acceptance))
	choice, found := try.To2(onboarding.ReadStoredChoice(receiver.vault, r, b))
	assert.That(found)
	assert.DeepEqual(choice.Proposal.Bytes(), own.Bytes())
	assert.DeepEqual(choice.Acceptance, ownAcceptance)
	assert.Equal(try.To1(readOwnerStatus(receiver.handler, receiver.authorization)), "completed")
	assert.Equal(signer.signCalls, 1)

	try.To(receiver.vault.Close())
	try.To(receiver.db.Close())
	reopened := try.To1(storage.OpenBolt(receiver.path))
	defer func() { try.Out(reopened.Close()).Logf() }()
	p := receiver.provider
	receiver.vault = try.To1(reopened.OpenVault(t.Context(), p.vault, p.id, p))
	defer func() { try.Out(receiver.vault.Close()).Logf() }()
	evidenceCredentials(t, &receiver, r, b)
	receiver.assertReadOnly(t)
	assertListed(t, receiver, b, a, b)
	assertSaved(t, receivedResponse(receiver, http.MethodPost, exported.Body.Bytes()), a, false, false)
	assert.Equal(try.To1(readOwnerStatus(receiver.handler, receiver.authorization)), "completed")
}

func TestOwnerReceivedRetryConflictAndOutputFailure(t *testing.T) {
	defer assert.PushTester(t)()

	root, child := key.New(), key.New()
	r, c := key.Public(try.To1(root.CBORPublicKey())), key.Public(try.To1(child.CBORPublicKey()))
	path := intro.New(key.Info{Public: r}).Introduce(root, key.Info{Public: c})
	acceptance := try.To1(path.SignAcceptance(child))
	another := try.To1(path.SignAcceptance(child))
	assert.ThatNot(bytes.Equal(acceptance, another))
	otherPath := intro.New(key.Info{Public: r}).Introduce(root, key.Info{Public: c},
		intro.WithEndpoint("different valid proposal", false))
	otherAcceptance := try.To1(otherPath.SignAcceptance(child))
	f := newIntroductionFixture(t, r, c)
	evidenceCredentials(t, &f, r, c)
	failed := &ownerStatusFailedWriter{ResponseRecorder: httptest.NewRecorder()}
	f.handler.ServeHTTP(failed, receivedRequest(f.authorization, http.MethodPost, checkDocument(path, acceptance)))
	assert.Equal(failed.Code, http.StatusOK)
	assert.Equal(failed.headerCalls, 1)
	assert.Equal(failed.writeCalls, 1)
	before := try.To1(receivedRecord(f.vault, c))
	f.assertReadOnly(t)
	for _, signature := range []key.Signature{acceptance, another} {
		assertSaved(t, receivedResponse(f, http.MethodPost, checkDocument(path, signature)), c, true, false)
	}
	assertCheckError(t, receivedResponse(f, http.MethodPost, checkDocument(otherPath, otherAcceptance)), http.StatusConflict)
	assert.DeepEqual(try.To1(receivedRecord(f.vault, c)), before)
	assertListed(t, f, c, c)
}

func TestOwnerReceivedRechecksAndBounds(t *testing.T) {
	defer assert.PushTester(t)()

	root, child := key.New(), key.New()
	r, c := key.Public(try.To1(root.CBORPublicKey())), key.Public(try.To1(child.CBORPublicKey()))
	path := intro.New(key.Info{Public: r}).Introduce(root, key.Info{Public: c})
	document := checkDocument(path, try.To1(path.SignAcceptance(child)))
	private := intro.New(key.Info{Public: r}).Introduce(root, key.Info{Public: c, ID: []byte("private")})
	privateDocument := checkDocument(private, try.To1(private.SignAcceptance(child)))
	f := newIntroductionFixture(t, r, c)
	evidenceCredentials(t, &f, r, c)
	checked := httptest.NewRecorder()
	f.handler.ServeHTTP(checked, checkRequest(f.authorization, document))
	assertChecked(t, checked, c, true)
	f.assertReadOnly(t)
	for _, invalid := range [][]byte{
		[]byte(`{}`), privateDocument, checkDocument(path, []byte("changed after checking")),
		bytes.Replace(document, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
	} {
		assertCheckError(t, receivedResponse(f, http.MethodPost, invalid), http.StatusBadRequest)
	}
	wrongRoot := f
	evidenceCredentials(t, &wrongRoot, c, c)
	assertCheckError(t, receivedResponse(wrongRoot, http.MethodPost, document), http.StatusBadRequest)
	rq := receivedRequest(f.authorization, http.MethodPost, nil)
	reader := &checkCountingReader{Reader: strings.NewReader(strings.Repeat(" ", 256*1024))}
	rq.Body, rq.ContentLength = io.NopCloser(reader), 1
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, rq)
	assertCheckError(t, w, http.StatusRequestEntityTooLarge)
	assert.Equal(reader.bytesRead, 128*1024+1)
	assertListed(t, f, c)
	assert.Equal(try.To1(readOwnerStatus(f.handler, f.authorization)), "unselected")
}

func TestOwnerReceivedFailedWrite(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "existing"}[existing], func(t *testing.T) {
			defer assert.PushTester(t)()

			root, alice, bob := key.New(), key.New(), key.New()
			r, a, b := key.Public(try.To1(root.CBORPublicKey())),
				key.Public(try.To1(alice.CBORPublicKey())), key.Public(try.To1(bob.CBORPublicKey()))
			f := newIntroductionFixture(t, r, b)
			evidenceCredentials(t, &f, r, b)
			if existing {
				path := intro.New(key.Info{Public: r}).Introduce(root, key.Info{Public: a})
				assertSaved(t, receivedResponse(f, http.MethodPost, checkDocument(path, try.To1(path.SignAcceptance(alice)))), a, false, true)
			}
			f.assertReadOnly(t)
			path := intro.New(key.Info{Public: r}).Introduce(root, key.Info{Public: b})
			signature := try.To1(path.SignAcceptance(bob))
			assertCheckError(t, receivedResponse(f, http.MethodPost, checkDocument(path, signature)), http.StatusInternalServerError)
			subject, created, err := onboarding.SaveIntroduction(f.vault, r, path.Bytes(), signature)
			assert.ErrorIs(err, storage.ErrKeyUsageExhausted)
			assert.SNil(subject)
			assert.ThatNot(created)
			if existing {
				assertListed(t, f, b, a)
			} else {
				assertListed(t, f, b)
				try.To(f.vault.View(func(tx storage.ReadTx) (err error) {
					defer err2.Handle(&err, nil)
					assert.ThatNot(try.To1(tx.HasChild([]byte("received-introductions-v1"))))
					return nil
				}))
			}
		})
	}
}

func TestOwnerReceivedCollectionLimit(t *testing.T) {
	defer assert.PushTester(t)()

	root := key.New()
	r := key.Public(try.To1(root.CBORPublicKey()))
	f := newIntroductionFixture(t, r, r)
	evidenceCredentials(t, &f, r, r)
	var subjects []key.Public
	var firstDocument []byte
	// One positive fixture per slot, without multiplying the verifier matrix.
	for index := range 33 {
		child := key.New()
		c := key.Public(try.To1(child.CBORPublicKey()))
		path := intro.New(key.Info{Public: r}).Introduce(root, key.Info{Public: c})
		document := checkDocument(path, try.To1(path.SignAcceptance(child)))
		if index == 0 {
			firstDocument = document
		}
		if index == 32 {
			f.assertReadOnly(t)
			assertCheckError(t, receivedResponse(f, http.MethodPost, document), http.StatusConflict)
		} else {
			assertSaved(t, receivedResponse(f, http.MethodPost, document), c, false, true)
			subjects = append(subjects, c)
		}
	}
	assertSaved(t, receivedResponse(f, http.MethodPost, firstDocument), subjects[0], false, false)
	assertListed(t, f, r, subjects...)
	owned := try.To1(onboarding.ListIntroductions(f.vault, r))
	clear(owned[0])
	assertListed(t, f, r, subjects...)
}

func TestOwnerReceivedInvalidRecord(t *testing.T) {
	for _, damage := range []string{"empty", "version", "signature", "key mismatch"} {
		t.Run(damage, func(t *testing.T) {
			defer assert.PushTester(t)()

			root, alice, bob := key.New(), key.New(), key.New()
			r, a, b := key.Public(try.To1(root.CBORPublicKey())),
				key.Public(try.To1(alice.CBORPublicKey())), key.Public(try.To1(bob.CBORPublicKey()))
			f := newIntroductionFixture(t, r, b)
			evidenceCredentials(t, &f, r, b)
			path := intro.New(key.Info{Public: r}).Introduce(root, key.Info{Public: a})
			document := checkDocument(path, try.To1(path.SignAcceptance(alice)))
			assertSaved(t, receivedResponse(f, http.MethodPost, document), a, false, true)
			record := try.To1(receivedRecord(f.vault, a))
			subject := a
			switch damage {
			case "empty":
				record = []byte{}
			case "version":
				record[0]++
			case "signature":
				record[len(record)-1] ^= 1
			case "key mismatch":
				subject = b
				path = intro.New(key.Info{Public: r}).Introduce(root, key.Info{Public: b})
				document = checkDocument(path, try.To1(path.SignAcceptance(bob)))
			}
			try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				ns := try.To1(tx.ChildForUpdate([]byte("received-introductions-v1")))
				return ns.Put(subject, record)
			}))
			f.assertReadOnly(t)
			assertCheckError(t, receivedResponse(f, http.MethodGet, nil), http.StatusInternalServerError)
			assertCheckError(t, receivedResponse(f, http.MethodPost, document), http.StatusInternalServerError)
			listed, err := onboarding.ListIntroductions(f.vault, r)
			assert.Error(err)
			assert.SNil(listed)
			assert.DeepEqual(try.To1(receivedRecord(f.vault, subject)), record)
		})
	}
}

func TestOwnerReceivedCredentialScope(t *testing.T) {
	defer assert.PushTester(t)()

	f := introductionFixture{}
	evidenceCredentials(t, &f, nil, nil)
	for _, tc := range []struct {
		method, path, auth, media string
		status                    int
	}{
		{http.MethodPost, receivedPath, "", "application/json", 401},
		{http.MethodGet, receivedPath, "Bearer wrong", "", 401},
		{http.MethodDelete, receivedPath, f.authorization, "", 405},
		{http.MethodHead, receivedPath, f.authorization, "", 405},
		{http.MethodPost, receivedPath + "/", f.authorization, "application/json", 404},
		{http.MethodPost, receivedPath, f.authorization, "text/plain", 415},
	} {
		r := receivedRequest(tc.auth, tc.method, nil)
		r.URL.Path = tc.path
		r.Header.Set("Content-Type", tc.media)
		reader := &checkCountingReader{Reader: strings.NewReader("must not read")}
		r.Body = io.NopCloser(reader)
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		assertCheckError(t, w, tc.status)
		assert.Equal(reader.bytesRead, 0)
		if tc.status == 405 {
			assert.Equal(w.Header().Get("Allow"), "GET, POST")
		}
	}
	read, readFile := try.To2(ownerapi.NewReadCredentials(t.Context(), nil, nil, nil, t.TempDir()))
	status, statusFile := try.To2(ownerapi.NewStatusCredentials(t.Context(), nil, nil, nil, t.TempDir()))
	token := bytes.Repeat([]byte{0xab}, 32)
	authenticated := try.To1(ownerapi.NewAuthenticatedStatusHandler(nil, nil, nil, token))
	for _, old := range []struct {
		handler http.Handler
		auth    string
	}{
		{read, strings.TrimSpace(strings.TrimPrefix(string(try.To1(os.ReadFile(readFile))), "Authorization: "))},
		{status, strings.TrimSpace(strings.TrimPrefix(string(try.To1(os.ReadFile(statusFile))), "Authorization: "))},
		{authenticated, "Bearer " + hex.EncodeToString(token)},
		{ownerapi.NewStatusHandler(nil, nil, nil), ""},
	} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			for _, path := range []string{receivedPath, fetchPath} {
				w := httptest.NewRecorder()
				r := receivedRequest(old.auth, method, nil)
				r.URL.Path = path
				reader := &checkCountingReader{Reader: strings.NewReader("must not read")}
				r.Body = io.NopCloser(reader)
				old.handler.ServeHTTP(w, r)
				assertCheckError(t, w, http.StatusNotFound)
				assert.Equal(reader.bytesRead, 0)
			}
		}
	}
}
