package ownerapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/pw"
)

func TestInvitationStrictRequestBoundary(t *testing.T) {
	defer assert.PushTester(t)()
	f := newInvitationOwner(t)
	defer f.unchanged(t)()
	for _, path := range []string{invitationIssuePath, invitationRevokePath} {
		field, valid := "recipient_public_key_hex", issueAnyBody
		if path == invitationRevokePath {
			field, valid = "invitation_id_hex", revokeInvitationBody(
				make([]byte, 32),
			)
		}
		for _, method := range []string{"GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"} {
			w := deviceRequest(f.owner, f.auth, method, path, valid)
			assert.Equal(w.Code, 405)
			assert.Equal(w.Header().Get("Allow"), "POST")
		}
		for _, badPath := range []string{path + "/", strings.Replace(path, "/pw/", "/%70w/", 1),
			strings.Replace(path, "/pw/", "//pw/", 1),
			strings.Replace(path, "/pw/", "/x/../pw/", 1),
			strings.Replace(path, "/owner/", "/peer/", 1)} {
			assert.Equal(
				deviceRequest(f.owner, f.auth, "POST", badPath, valid).Code,
				404,
			)
		}
		for _, query := range []string{"?", "?expiry=1"} {
			assert.Equal(
				deviceRequest(f.owner, f.auth, "POST", path+query, valid).Code,
				400,
			)
		}
		for _, body := range []string{"", "null", "[]", "{}", "{", valid + " {}", valid + "x",
			`{"unknown":null}`, `{"` + strings.ToUpper(field) + `":null}`,
			`{"` + field + `":null,"` + field + `":null}`,
			`{"` + field + `":null,"expiry":1}`,
			`{"` + field + `":null,"root":"x"}`,
			`{"` + field + `":false}`, `{"` + field + `":1}`, `{"` + field + `":[]}`,
			`{"` + field + `":""}`, `{"` + field + `":"00"}`,
			`{"` + field + `":"` + strings.Repeat("AB", 32) + `"}`,
			`{"` + field + `":"` + strings.Repeat("gg", 32) + `"}`,
			`{"` + field + `":"` + strings.Repeat("a", 63) + `"}`,
			`{"` + field + `":"` + strings.Repeat("a", 66) + `"}`,
			`{"` + field + `":"` + strings.Repeat("a", 258) + `"}`,
			"\u00a0" + valid, string([]byte{0xff}) + valid,
		} {
			w := deviceRequest(f.owner, f.auth, "POST", path, body)
			assert.Equal(w.Code, 400, body)
			assert.Equal(w.Body.String(), "Bad Request\n")
			assert.Equal(
				w.Header().Get("Content-Type"),
				"text/plain; charset=utf-8",
			)
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
		}
		for _, media := range []string{"", "text/plain", "application/json, application/json"} {
			r := httptest.NewRequest("POST", path, strings.NewReader(valid))
			r.Header.Set("Authorization", f.auth)
			r.Header.Set("Content-Type", media)
			w := httptest.NewRecorder()
			f.owner.ServeHTTP(w, r)
			assert.Equal(w.Code, 415)
		}
		for _, mutate := range []func(*http.Request){
			func(r *http.Request) { r.URL.Opaque = "//owner" },
			func(r *http.Request) { r.URL.Fragment = "expiry" },
			func(r *http.Request) { r.URL.RawFragment = "expiry" },
			func(r *http.Request) { r.Header.Add("Content-Type", "application/json") },
		} {
			r := httptest.NewRequest("POST", path, strings.NewReader(valid))
			r.Header.Set("Authorization", f.auth)
			r.Header.Set("Content-Type", "application/json")
			mutate(r)
			w := httptest.NewRecorder()
			f.owner.ServeHTTP(w, r)
			assert.That(w.Code == 400 || w.Code == 404 || w.Code == 415)
		}
		reader := strings.NewReader(strings.Repeat(" ", 1024))
		r := httptest.NewRequest("POST", path, reader)
		r.ContentLength = 1 // Bound actual bytes, not the claim.
		r.Header.Set("Authorization", f.auth)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.owner.ServeHTTP(w, r)
		assert.Equal(w.Code, 413)
		assert.Equal(reader.Len(), 1024-maxInvitationRequestBytes-1)
	}
	assert.Equal(deviceRequest(f.owner, f.auth, "POST", invitationRevokePath,
		`{"invitation_id_hex":null}`).Code, 400)
}

func TestInvitationConcurrentOwnerIssue(t *testing.T) {
	defer assert.PushTester(t)()
	f := newInvitationOwner(t)
	f.lease.remaining.Store(1)
	results := make(chan *httptest.ResponseRecorder, 12)
	var workers sync.WaitGroup
	for range 12 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			results <- deviceRequest(f.owner, f.auth, "POST", invitationIssuePath, issueAnyBody)
		}()
	}
	workers.Wait()
	close(results)
	successes := 0
	for w := range results {
		if w.Code == 200 {
			successes++
		} else {
			assert.Equal(w.Code, 409)
		}
	}
	assert.Equal(successes, 1)
}

func TestInvitationSharesPublicationAndProofMutationLock(t *testing.T) {
	for _, blocker := range []string{publishPath, currentProofPath, acceptancePath} {
		for _, path := range []string{invitationIssuePath, invitationRevokePath} {
			t.Run(blocker+path, func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newAcceptanceFixture(t)
				body := issueAnyBody
				if path == invitationRevokePath {
					row := try.To1(
						pw.IssueInvitation(f.vault, f.root, f.child, nil),
					)
					body = revokeInvitationBody(row.ID)
				}
				blockingHandler, blockingAuth, blockingBody := f.owner, f.auth, "{}"
				switch blocker {
				case currentProofPath:
					blockingHandler, blockingAuth = f.peer, ""
					blockingBody = currentProofBody(
						t,
						f.ad,
						currentProofNonce(t),
					)
				case acceptancePath:
					blockingHandler, blockingAuth = f.peer, ""
					nonce := f.challenge(t)
					blockingBody = f.body(t, nonce, f.requesterProof(t, nonce))
				}
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				defer unblock()
				f.signer.sign = func(data []byte) ([]byte, error) {
					if f.signer.signs.Load() == 1 {
						close(entered)
						<-release
					}
					return f.signer.Handle.Sign(data)
				}
				done := make(chan *httptest.ResponseRecorder, 1)
				go func() { done <- deviceRequest(blockingHandler, blockingAuth, "POST", blocker, blockingBody) }()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("signer did not start")
				}
				mutation := make(chan *httptest.ResponseRecorder, 1)
				go func() { mutation <- deviceRequest(f.owner, f.auth, "POST", path, body) }()
				select {
				case <-mutation:
					t.Fatal("invitation escaped the service mutation lock")
				case <-time.After(30 * time.Millisecond):
				}
				unblock()
				assert.Equal(waitAcceptance(t, done).Code, 200)
				assert.Equal(waitAcceptance(t, mutation).Code, 200)
			})
		}
	}
}
