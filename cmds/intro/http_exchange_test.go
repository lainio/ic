package intro

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	coreintro "github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
)

func Example_httpExchange() {
	defer err2.Catch(err2.Stdout)

	root := key.New()
	alice := key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	handler := newHTTPExchangeHandler(root)
	ctx := context.Background()

	info := try.To1(exchangePublicInfo(alice))
	offer := postHTTPExchange(
		ctx,
		handler,
		"/intro/offer",
		wire.TryMarshal(info),
	)
	assert.Equal(offer.Code, http.StatusOK)

	proposal := try.To1(coreintro.ParsePath(offer.Body.Bytes()))
	proofErr := proposal.ProveFromRoot(expectedRoot)
	assert.NoError(proofErr)
	signature := try.To1(saveExchangeAcceptance(
		ctx, alice, expectedRoot, offer.Body.Bytes(), io.Discard,
	))
	verifyErr := proposal.VerifyAcceptance(signature)
	assert.NoError(verifyErr)

	accepted := postHTTPExchange(ctx, handler, "/intro/acceptance",
		wire.TryMarshal(signature))
	assert.Equal(accepted.Code, http.StatusNoContent)
	fmt.Println("proposal proof passes:", proofErr == nil)
	fmt.Println("Alice's acceptance verifies:", verifyErr == nil)
	fmt.Println(
		"issuer returned HTTP 204:",
		accepted.Code == http.StatusNoContent,
	)
	// Output:
	// proposal proof passes: true
	// Alice's acceptance verifies: true
	// issuer returned HTTP 204: true
}

func postHTTPExchange(
	ctx context.Context, handler http.Handler, path string, body []byte,
) *httptest.ResponseRecorder {
	request := httptest.NewRequestWithContext(ctx, http.MethodPost, path,
		bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/cbor")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestHTTPExchangeStoredChoice(t *testing.T) {
	defer assert.PushTester(t)()

	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	root := &exchangeObservedHandle{Handle: key.New()}
	alice := &exchangeObservedHandle{Handle: key.New()}
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	handler := newHTTPExchangeHandler(root)
	info := try.To1(exchangePublicInfo(alice))
	assert.SEmpty(info.ID)

	offer := postHTTPExchange(t.Context(), handler, "/intro/offer",
		wire.TryMarshal(info))
	assert.Equal(offer.Code, http.StatusOK)
	assert.Equal(offer.Header().Get("Content-Type"), "application/cbor")
	proposal := try.To1(coreintro.ParsePath(offer.Body.Bytes()))
	assert.DeepEqual(proposal.Bytes(), offer.Body.Bytes())
	assert.NoError(proposal.ProveFromRoot(expectedRoot))
	assert.SLen(proposal, 2)
	assert.SEmpty(proposal[0].Body.Child.ID)
	assert.SEmpty(proposal[1].Body.Child.ID)
	assert.That(proposal.LastEdge().Public().Equal(info.Public))

	signature := try.To1(saveExchangeAcceptance(
		t.Context(), alice, expectedRoot, offer.Body.Bytes(), io.Discard,
	))
	assert.NoError(proposal.VerifyAcceptance(signature))
	assert.SEmpty(try.To1(os.ReadDir(parent)))
	for range 2 {
		accepted := postHTTPExchange(
			t.Context(),
			handler,
			"/intro/acceptance",
			wire.TryMarshal(signature),
		)
		assert.Equal(accepted.Code, http.StatusNoContent)
		assert.Empty(accepted.Body.String())
	}
	assert.Equal(root.signCalls, 1)
	assert.Equal(alice.signCalls, 1)
}

func TestHTTPExchangeWrongRoot(t *testing.T) {
	defer assert.PushTester(t)()

	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	root, other := key.New(), key.New()
	alice := &exchangeObservedHandle{Handle: key.New()}
	expectedRoot := key.Public(try.To1(other.CBORPublicKey()))
	handler := newHTTPExchangeHandler(root)
	info := try.To1(exchangePublicInfo(alice))
	offer := postHTTPExchange(t.Context(), handler, "/intro/offer",
		wire.TryMarshal(info))
	assert.Equal(offer.Code, http.StatusOK)

	signature, err := saveExchangeAcceptance(
		t.Context(), alice, expectedRoot, offer.Body.Bytes(), io.Discard,
	)
	assert.ErrorIs(err, coreintro.ErrWrongRoot)
	assert.SNil(signature)
	assert.Equal(alice.signCalls, 0)
	assert.SEmpty(try.To1(os.ReadDir(parent)))
	// Alice refused locally: there is no acceptance request to send.
}

func TestHTTPExchangeDifferentProposal(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	rootInfo := try.To1(exchangePublicInfo(root))
	info := try.To1(exchangePublicInfo(alice))
	handler := newHTTPExchangeHandler(root)
	offer := postHTTPExchange(t.Context(), handler, "/intro/offer",
		wire.TryMarshal(info))
	assert.Equal(offer.Code, http.StatusOK)
	proposal := try.To1(coreintro.ParsePath(offer.Body.Bytes()))

	// Same root and child, but different signed proposal bytes.
	alternate := coreintro.New(rootInfo).Introduce(root, info,
		coreintro.WithPosition(1))
	signature := try.To1(saveExchangeAcceptance(t.Context(), alice,
		rootInfo.Public, alternate.Bytes(), io.Discard))
	assert.NoError(alternate.VerifyAcceptance(signature))
	rejected := postHTTPExchange(t.Context(), handler, "/intro/acceptance",
		wire.TryMarshal(signature))
	assert.Equal(rejected.Code, http.StatusUnprocessableEntity)

	// Each helper invocation owns a disposable Vault; only the original offer
	// is retained by Root. Rejection must leave that exact proposal usable.
	signature = try.To1(saveExchangeAcceptance(t.Context(), alice,
		rootInfo.Public, proposal.Bytes(), io.Discard))
	accepted := postHTTPExchange(t.Context(), handler, "/intro/acceptance",
		wire.TryMarshal(signature))
	assert.Equal(accepted.Code, http.StatusNoContent)
}

func TestHTTPExchangeSequence(t *testing.T) {
	defer assert.PushTester(t)()

	root := &exchangeObservedHandle{Handle: key.New()}
	alice, other := key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	handler := newHTTPExchangeHandler(root)
	info := try.To1(exchangePublicInfo(alice))
	otherInfo := try.To1(exchangePublicInfo(other))

	early := postHTTPExchange(t.Context(), handler, "/intro/acceptance",
		wire.TryMarshal([]byte("no offer yet")))
	assert.Equal(early.Code, http.StatusConflict)
	assert.Equal(root.signCalls, 0)
	offer := postHTTPExchange(t.Context(), handler, "/intro/offer",
		wire.TryMarshal(info))
	assert.Equal(offer.Code, http.StatusOK)
	second := postHTTPExchange(t.Context(), handler, "/intro/offer",
		wire.TryMarshal(otherInfo))
	assert.Equal(second.Code, http.StatusConflict)
	assert.Equal(root.signCalls, 1)

	signature := try.To1(saveExchangeAcceptance(t.Context(), alice,
		expectedRoot, offer.Body.Bytes(), io.Discard))
	accepted := postHTTPExchange(t.Context(), handler, "/intro/acceptance",
		wire.TryMarshal(signature))
	assert.Equal(accepted.Code, http.StatusNoContent)
	assert.Equal(root.signCalls, 1)
}

func TestHTTPExchangeInput(t *testing.T) {
	defer assert.PushTester(t)()

	root := &exchangeObservedHandle{Handle: key.New()}
	info := try.To1(exchangePublicInfo(key.New()))
	canonical := wire.TryMarshal(info)
	for _, tc := range []struct {
		name, path, method, media string
		body                      []byte
		status                    int
	}{
		{"unknown", "/other", "POST", "application/cbor", canonical, 404},
		{"method", "/intro/offer", "GET", "application/cbor", canonical, 405},
		{"media", "/intro/offer", "POST", "text/plain", canonical, 415},
		{"missing media", "/intro/acceptance", "POST", "", canonical, 415},
		{"malformed", "/intro/offer", "POST", "application/cbor", []byte{0xff}, 400},
		{"empty key", "/intro/offer", "POST", "application/cbor",
			wire.TryMarshal(key.Info{}), 400},
		{"noncanonical", "/intro/offer", "POST", "application/cbor",
			append([]byte{0xd9, 0xd9, 0xf7}, canonical...), 400},
		{"oversized offer", "/intro/offer", "POST", "application/cbor",
			make([]byte, exchangePayloadLimit+1), 413},
		{"oversized acceptance", "/intro/acceptance", "POST", "application/cbor",
			make([]byte, exchangePayloadLimit+1), 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			request := httptest.NewRequestWithContext(t.Context(), tc.method,
				tc.path, bytes.NewReader(tc.body))
			request.Header.Set("Content-Type", tc.media)
			request.ContentLength = 1 // Actual reads must enforce the limit.
			response := httptest.NewRecorder()
			newHTTPExchangeHandler(root).ServeHTTP(response, request)
			assert.Equal(response.Code, tc.status)
			assert.Equal(root.signCalls, 0)
			assert.Equal(
				response.Body.String(),
				http.StatusText(tc.status)+"\n",
			)
			if tc.status == http.StatusMethodNotAllowed {
				assert.Equal(
					response.Header().Get("Allow"),
					http.MethodPost,
				)
			}
		})
	}
}

func TestHTTPExchangeAcceptanceCarriage(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	handler := newHTTPExchangeHandler(root)
	info := try.To1(exchangePublicInfo(alice))
	offer := postHTTPExchange(t.Context(), handler, "/intro/offer",
		wire.TryMarshal(info))
	assert.Equal(offer.Code, http.StatusOK)
	signature := try.To1(saveExchangeAcceptance(t.Context(), alice,
		expectedRoot, offer.Body.Bytes(), io.Discard))

	for _, body := range [][]byte{
		{0xff}, {0xf6}, wire.TryMarshal("not a byte string"),
		append([]byte{0xd9, 0xd9, 0xf7}, wire.TryMarshal(signature)...),
	} {
		response := postHTTPExchange(
			t.Context(),
			handler,
			"/intro/acceptance",
			body,
		)
		assert.Equal(response.Code, http.StatusBadRequest)
	}
	accepted := postHTTPExchange(t.Context(), handler, "/intro/acceptance",
		wire.TryMarshal(signature))
	assert.Equal(accepted.Code, http.StatusNoContent)
}

type httpExchangeFailedWriter struct {
	*httptest.ResponseRecorder
	headerCalls int
}

func (w *httpExchangeFailedWriter) WriteHeader(status int) {
	w.headerCalls++
	w.ResponseRecorder.WriteHeader(status)
}

func (w *httpExchangeFailedWriter) Write([]byte) (int, error) {
	return 0, errors.New("response write failed")
}

func TestHTTPExchangeWriteFailureRetainsOffer(t *testing.T) {
	defer assert.PushTester(t)()

	root := &exchangeObservedHandle{Handle: key.New()}
	info := try.To1(exchangePublicInfo(key.New()))
	handler := newHTTPExchangeHandler(root)
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/intro/offer", bytes.NewReader(wire.TryMarshal(info)))
	request.Header.Set("Content-Type", "application/cbor")
	failed := &httpExchangeFailedWriter{
		ResponseRecorder: httptest.NewRecorder(),
	}
	handler.ServeHTTP(failed, request)
	assert.Equal(failed.Code, http.StatusOK)
	assert.Equal(failed.headerCalls, 1)

	second := postHTTPExchange(t.Context(), handler, "/intro/offer",
		wire.TryMarshal(info))
	assert.Equal(second.Code, http.StatusConflict)
	assert.Equal(root.signCalls, 1)
}

func TestHTTPExchangeConcurrentOffers(t *testing.T) {
	defer assert.PushTester(t)()

	root := &exchangeObservedHandle{Handle: key.New()}
	info := try.To1(exchangePublicInfo(key.New()))
	body := wire.TryMarshal(info)
	handler := newHTTPExchangeHandler(root)
	ctx := t.Context()
	start := make(chan struct{})
	results := make(chan int, 2)
	for range 2 {
		go func() {
			<-start
			results <- postHTTPExchange(ctx, handler, "/intro/offer", body).Code
		}()
	}
	close(start)
	first, second := <-results, <-results
	assert.That(first == http.StatusOK && second == http.StatusConflict ||
		first == http.StatusConflict && second == http.StatusOK)
	assert.Equal(root.signCalls, 1)
}
