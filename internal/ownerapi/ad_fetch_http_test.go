package ownerapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/onboarding"
)

func TestAdFetchStrictPeerEnvelope(t *testing.T) {
	defer assert.PushTester(t)()
	f := newAdFetchFixture(t)
	good := string(adDocument(t, f.choice, try.To1(wire.Marshal(f.current))))
	nested := string(try.To1(onboarding.EncodeIntroduction(f.choice)))
	ad := base64.StdEncoding.EncodeToString(try.To1(wire.Marshal(f.current)))
	proposal := base64.StdEncoding.EncodeToString(f.choice.Proposal.Bytes())
	acceptance := base64.StdEncoding.EncodeToString(f.choice.Acceptance)
	bad := map[string]string{
		"empty": "", "array": "[]", "null": "null", "missing": "{}",
		"truncated": good[:len(good)-1], "trailing object": good + " {}", "trailing text": good + "PRIVATE",
		"invalid UTF8":        strings.Replace(good, `"version"`, "\"\xff\"", 1),
		"ad CBOR junk":        strings.Replace(good, ad, "AA==", 1),
		"oversize decoded ad": strings.Replace(good, ad, base64.StdEncoding.EncodeToString(make([]byte, 1025)), 1),
	}
	for _, version := range []string{"0", "2", "1.0", "1e0", `"1"`, "null", "true", "[]", "{}"} {
		bad["outer version "+version] = strings.Replace(good, `"version":1`, `"version":`+version, 1)
		bad["inner version "+version] = strings.Replace(good, nested, strings.Replace(nested, `"version":1`, `"version":`+version, 1), 1)
	}
	for _, field := range []string{"version", "introduction", "ad"} {
		var fields map[string]json.RawMessage
		try.To(json.Unmarshal([]byte(good), &fields))
		bad["duplicate "+field] = good[:len(good)-1] + `,"` + field + `":` + string(fields[field]) + `}`
		delete(fields, field)
		bad["missing "+field] = string(try.To1(json.Marshal(fields)))
	}
	bad["unknown"] = good[:len(good)-1] + `,"authorization":"Bearer PRIVATE"}`
	for _, value := range []string{"null", "1", "[]", "{}", `""`, `"AA"`, `"AA==\n"`, `"AB=="`, `"__=="`, `"PRIVATE"`} {
		bad["ad "+value] = strings.Replace(good, `"`+ad+`"`, value, 1)
	}
	for _, field := range []string{"version", "proposal", "acceptance"} {
		var fields map[string]json.RawMessage
		try.To(json.Unmarshal([]byte(nested), &fields))
		duplicate := nested[:len(nested)-1] + `,"` + field + `":` + string(fields[field]) + `}`
		bad["inner duplicate "+field] = strings.Replace(good, nested, duplicate, 1)
		delete(fields, field)
		bad["inner missing "+field] = strings.Replace(good, nested, string(try.To1(json.Marshal(fields))), 1)
	}
	for _, value := range []string{"null", "1", "[]", `""`, `"AA"`, `"AB=="`, `"AA==\n"`} {
		bad["proposal "+value] = strings.Replace(good, `"`+proposal+`"`, value, 1)
		bad["acceptance "+value] = strings.Replace(good, `"`+acceptance+`"`, value, 1)
		bad["introduction "+value] = strings.Replace(good, nested, value, 1)
	}
	bad["inner unknown"] = strings.Replace(good, nested, nested[:len(nested)-1]+`,"owner":"PRIVATE"}`, 1)
	bad["inner size"] = strings.Replace(good, nested, "{"+strings.Repeat(" ", maxIntroductionBytes)+nested[1:], 1)
	for name, document := range bad {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			defer f.unchanged(t)()
			server := adServer(t, []byte(document))
			w := f.fetch(server.URL)
			assert.Equal(w.Code, 502)
			assert.Equal(w.Body.String(), "Bad Gateway\n")
		})
	}
	f.noAuthority(t)
}

func TestAdFetchDirectTransportHasNoAmbientAuthority(t *testing.T) {
	defer assert.PushTester(t)()
	f := newAdFetchFixture(t)
	var proxyCalls, requests, dials, lookups, reused atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxyCalls.Add(1) }))
	defer proxy.Close()
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(name, proxy.URL)
	}
	for _, name := range []string{"NO_PROXY", "no_proxy"} {
		t.Setenv(name, "")
	}
	document := adDocument(t, f.choice, try.To1(wire.Marshal(f.current)))
	observed := make(chan *http.Request, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		observed <- r.Clone(r.Context())
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "peer=PRIVATE; Domain=localhost; Path=/")
		w.Header().Set("Authorization", "Bearer PRIVATE")
		_, _ = w.Write(document)
	}))
	defer server.Close()
	ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) { dials.Add(1) },
		DNSStart:     func(httptrace.DNSStartInfo) { lookups.Add(1) },
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Reused {
				reused.Add(1)
			}
		},
	})
	for _, created := range []bool{true, false} {
		r := adFetchRequest(f.auth, strings.Replace(server.URL, "127.0.0.1", "localhost", 1)).WithContext(ctx)
		r.Header.Set("Cookie", "owner=PRIVATE")
		r.Header.Set("Proxy-Authorization", "Bearer PRIVATE")
		r.Header.Set("X-Owner-Secret", "PRIVATE")
		r.Header.Set("Accept-Encoding", "gzip")
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		assertAdFetchResult(t, w, f.subject, created, created)
		peerRequest := <-observed
		assert.Equal(peerRequest.Method, "GET")
		assert.Equal(peerRequest.URL.RequestURI(), "/peer/ad")
		assert.Equal(peerRequest.ContentLength, int64(0))
		assert.That(peerRequest.Close)
		for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-Owner-Secret", "Accept-Encoding"} {
			assert.Empty(peerRequest.Header.Get(name))
		}
	}
	assert.Equal(requests.Load(), int32(2))
	assert.Equal(dials.Load(), int32(2))
	assert.Equal(lookups.Load(), int32(0))
	assert.Equal(reused.Load(), int32(0))
	assert.Equal(proxyCalls.Load(), int32(0))
}

func TestAdFetchHTTPFailuresAreBoundedAndReadOnly(t *testing.T) {
	defer assert.PushTester(t)()
	f := newAdFetchFixture(t)
	document := adDocument(t, f.choice, try.To1(wire.Marshal(f.current)))
	var diagnostics bytes.Buffer
	oldError, oldReturn := err2.ErrorTracer(), err2.ErrRetTracer()
	err2.SetErrorTracer(&diagnostics)
	err2.SetErrRetTracer(&diagnostics)
	defer func() { err2.SetErrorTracer(oldError); err2.SetErrRetTracer(oldReturn) }()
	for _, scenario := range []string{"redirect external", "redirect loopback", "status", "missing media", "bad media", "duplicate media", "gzip", "large headers", "large content length", "chunked oversize", "truncated", "malformed status", "malformed header"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			defer f.unchanged(t)()
			var requests, redirectCalls, dials atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirectCalls.Add(1) }))
			defer target.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Content-Type", "application/json")
				switch scenario {
				case "redirect external":
					http.Redirect(w, r, "http://192.0.2.1:80/PRIVATE", 302)
				case "redirect loopback":
					http.Redirect(w, r, target.URL+"/peer/ad", 307)
				case "status":
					http.Error(w, "PRIVATE", 503)
				case "missing media":
					w.Header()["Content-Type"] = nil
					_, _ = w.Write(document)
				case "bad media":
					w.Header().Set("Content-Type", "text/plain")
					_, _ = w.Write(document)
				case "duplicate media":
					w.Header().Add("Content-Type", "application/json")
					_, _ = w.Write(document)
				case "gzip":
					w.Header().Set("Content-Encoding", "gzip")
					_, _ = w.Write([]byte{0x1f, 0x8b, 0x08})
				case "large headers":
					w.Header().Set("X-Padding", strings.Repeat("x", 9*1024))
					_, _ = w.Write(document)
				case "large content length":
					w.Header().Set("Content-Length", strconv.Itoa(maxAdResponseBytes+1))
				case "chunked oversize":
					w.(http.Flusher).Flush()
					_, _ = io.WriteString(w, strings.Repeat(" ", maxAdResponseBytes+1))
				case "truncated":
					w.Header().Set("Content-Length", strconv.Itoa(len(document)+1))
					_, _ = w.Write(document)
				case "malformed status", "malformed header":
					conn, rw, err := w.(http.Hijacker).Hijack()
					if err != nil {
						return
					}
					defer func() { _ = conn.Close() }()
					if scenario == "malformed status" {
						_, _ = rw.WriteString("HTTP/1.1 PRIVATE nope\r\n\r\n")
					} else {
						_, _ = rw.WriteString("HTTP/1.1 200 OK\r\nPRIVATE\x00: secret\r\n\r\n")
					}
					_ = rw.Flush()
				}
			}))
			defer server.Close()
			ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{ConnectStart: func(_, _ string) { dials.Add(1) }})
			w := httptest.NewRecorder()
			f.handler.ServeHTTP(w, adFetchRequest(f.auth, server.URL).WithContext(ctx))
			assert.Equal(w.Code, 502)
			assert.Equal(w.Body.String(), "Bad Gateway\n")
			assert.Equal(requests.Load(), int32(1))
			assert.Equal(dials.Load(), int32(1))
			assert.Equal(redirectCalls.Load(), int32(0))
		})
	}
	assert.ThatNot(strings.Contains(diagnostics.String(), "PRIVATE"))
}

func TestAdFetchCancellationAndFiveSecondDeadline(t *testing.T) {
	for _, cancelRequest := range []bool{true, false} {
		t.Run(fmt.Sprint(cancelRequest), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newAdFetchFixture(t)
			defer f.unchanged(t)()
			entered, closed := make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(closed)
				w.Header().Set("Content-Type", "application/json")
				w.(http.Flusher).Flush()
				close(entered)
				<-r.Context().Done()
			}))
			defer server.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result := make(chan int, 1)
			started := time.Now()
			go func() {
				w := httptest.NewRecorder()
				f.handler.ServeHTTP(w, adFetchRequest(f.auth, server.URL).WithContext(ctx))
				result <- w.Code
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("peer was not reached")
			}
			if cancelRequest {
				cancel()
			}
			select {
			case status := <-result:
				assert.Equal(status, 502)
			case <-time.After(7 * time.Second):
				t.Fatal("fetch exceeded its deadline")
			}
			if !cancelRequest {
				assert.That(time.Since(started) >= 4*time.Second)
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("response connection was not closed")
			}
		})
	}
}

func TestAdFetchDoesNotTracePeerBytes(t *testing.T) {
	defer assert.PushTester(t)()
	f := newAdFetchFixture(t)
	defer f.unchanged(t)()
	const sentinel = "PRIVATE_PEER_DIAGNOSTIC"
	var diagnostics bytes.Buffer
	oldError, oldReturn := err2.ErrorTracer(), err2.ErrRetTracer()
	err2.SetErrorTracer(&diagnostics)
	err2.SetErrRetTracer(&diagnostics)
	defer func() { err2.SetErrorTracer(oldError); err2.SetErrRetTracer(oldReturn) }()
	good := string(adDocument(t, f.choice, try.To1(wire.Marshal(f.current))))
	// A duplicate string key is echoed by raw CBOR decoder diagnostics.
	keyBytes := try.To1(wire.Marshal(sentinel))
	malformed := append([]byte{0xa2}, keyBytes...)
	malformed = append(malformed, 0)
	malformed = append(malformed, keyBytes...)
	malformed = append(malformed, 0)
	proposal := base64.StdEncoding.EncodeToString(f.choice.Proposal.Bytes())
	for _, document := range []string{
		`{"version":` + sentinel + `}`, `{"version":"` + sentinel + `"}`,
		strings.Replace(good, `"version":1`, `"version":1,"`+sentinel+`":null`, 1),
		strings.Replace(good, proposal, base64.StdEncoding.EncodeToString(malformed), 1),
		string(adDocument(t, f.choice, malformed)),
	} {
		server := adServer(t, []byte(document))
		w := f.fetch(server.URL)
		assert.Equal(w.Code, 502)
		assert.ThatNot(strings.Contains(w.Body.String(), sentinel))
	}
	assert.ThatNot(strings.Contains(diagnostics.String(), sentinel))
}
