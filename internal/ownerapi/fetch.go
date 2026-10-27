package ownerapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/localhttp"
	"github.com/lainio/ic/internal/onboarding"
)

const maxFetchRequestBytes = 2 * 1024

var (
	errInvalidFetch = errors.New("invalid introduction fetch request")
	errPeerFetch    = errors.New("peer introduction fetch failed")
)

func (h *statusHandler) serveFetchIntroduction(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawPath != "" {
		writeStatusError(w, http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeStatusError(w, http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" {
		writeStatusError(w, http.StatusBadRequest)
		return
	}
	endpoint, ok := readFetchRequest(w, r, "/peer/introduction")
	if !ok {
		return
	}
	document, err := fetchIntroduction(r.Context(), endpoint)
	if err != nil {
		writeStatusError(w, http.StatusBadGateway)
		return
	}
	// Admission validation is not VerifyReceived. Identify the subject from
	// the signed evidence, never the URL, and refuse PresentSelf to oneself.
	subject, err := onboarding.CheckIntroduction(document.Proposal, document.Acceptance, h.expectedRoot)
	if err != nil || r.Context().Err() != nil {
		writeStatusError(w, http.StatusBadGateway)
		return
	}
	if bytes.Equal(subject, h.expectedChild) {
		writeStatusError(w, http.StatusBadRequest)
		return
	}
	// Network I/O and complete decoding finish before any Vault transaction.
	subject, created, err := onboarding.SaveIntroduction(
		h.vault, h.expectedRoot, document.Proposal, document.Acceptance,
	)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, onboarding.ErrInvalidIntroduction):
			status = http.StatusBadGateway
		case errors.Is(err, onboarding.ErrDifferentIntroduction),
			errors.Is(err, onboarding.ErrIntroductionsFull):
			status = http.StatusConflict
		}
		writeStatusError(w, status)
		return
	}
	h.writeSavedIntroduction(w, subject, created)
}

func readFetchRequest(w http.ResponseWriter, r *http.Request, path string) (string, bool) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(r.Header.Values("Content-Type")) != 1 {
		writeStatusError(w, http.StatusUnsupportedMediaType)
		return "", false
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxFetchRequestBytes))
	if err != nil {
		status := http.StatusBadRequest
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeStatusError(w, status)
		return "", false
	}
	endpoint, err := decodeFetchRequest(data, path)
	if err != nil {
		writeStatusError(w, http.StatusBadRequest)
		return "", false
	}
	return endpoint, true
}

// Exactly one string field; token decoding rejects duplicates, extra fields,
// case aliases, and trailing input before any client or storage work.
func decodeFetchRequest(data []byte, path string) (_ string, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.That(utf8.Valid(data), errInvalidFetch)
	decoder := json.NewDecoder(bytes.NewReader(data))
	assert.Equal(try.To1(decoder.Token()), json.Token(json.Delim('{')), errInvalidFetch)
	assert.Equal(try.To1(decoder.Token()), json.Token("peer_url"), errInvalidFetch)
	value, ok := try.To1(decoder.Token()).(string)
	assert.That(ok && value != "", errInvalidFetch)
	assert.Equal(try.To1(decoder.Token()), json.Token(json.Delim('}')), errInvalidFetch)
	_, end := decoder.Token()
	assert.Equal(end, io.EOF, errInvalidFetch)
	return peerFetchURL(value, path)
}

// This is a destination for one operation, not a general URL fetcher. Reject
// even empty query/fragment delimiters and encoded spellings. Address performs
// the literal loopback/port check and normalizes localhost without DNS.
func peerIntroductionURL(value string) (_ string, err error) {
	return peerFetchURL(value, "/peer/introduction")
}

// Both concrete fetch routes use the same destination policy; path is fixed
// by the handler, never selected by the request or a peer response.
func peerFetchURL(value, path string) (_ string, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.That(strings.HasPrefix(value, "http://") && !strings.ContainsAny(value, "?#%\\"), errInvalidFetch)
	u, parseErr := url.Parse(value)
	assert.That(parseErr == nil, errInvalidFetch)
	assert.That(u.Scheme == "http" && u.User == nil && u.Opaque == "" &&
		u.Path == path && u.RawPath == "", errInvalidFetch)
	// Brackets are for IPv6 literals, not IPv4 addresses or localhost.
	assert.That(!strings.HasPrefix(u.Host, "[") || strings.Contains(u.Hostname(), ":"), errInvalidFetch)
	address := try.To1(localhttp.Address(u.Host, false))
	return "http://" + address + path, nil
}

func fetchIntroduction(ctx context.Context, endpoint string) (introductionResponse, error) {
	data, err := fetchPeerDocument(ctx, endpoint, maxIntroductionBytes)
	if err != nil {
		return introductionResponse{}, err
	}
	return decodeIntroduction(data)
}

// A fresh direct transport makes one GET: no environment proxy, redirects,
// cookies, credentials, compression, connection reuse, or automatic retries.
// Neither remote response bodies nor underlying errors escape this boundary.
func fetchPeerDocument(ctx context.Context, endpoint string, limit int64) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errPeerFetch })
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	transport := &http.Transport{
		DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 8 * 1024,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	r := try.To1(http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil))
	response, fetchErr := client.Do(r)
	// Discard raw HTTP errors before err2 tracing: malformed response headers
	// and status lines can otherwise embed peer-controlled text in diagnostics.
	assert.That(fetchErr == nil, errPeerFetch)
	defer func() {
		if response.Body.Close() != nil {
			err = errPeerFetch
		}
	}()
	assert.Equal(response.StatusCode, http.StatusOK, errPeerFetch)
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	assert.That(mediaErr == nil && mediaType == "application/json" &&
		len(response.Header.Values("Content-Type")) == 1, errPeerFetch)
	assert.That(response.ContentLength <= limit, errPeerFetch)
	data, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
	assert.That(readErr == nil && int64(len(data)) <= limit, errPeerFetch)
	try.To(ctx.Err())
	return data, nil
}
