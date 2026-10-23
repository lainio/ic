package intro

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
)

func newHTTPDemoClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         (&net.Dialer{}).DialContext,
			IdleConnTimeout:     httpDemoIdleTimeout,
			DisableCompression:  true,
			MaxIdleConnsPerHost: 1,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) (err error) {
			// net/http compares this control sentinel directly, without errors.Is.
			defer err2.Handle(&err, nil)

			return http.ErrUseLastResponse
		},
	}
}

// Borrows the client and handle. The CLI owns idle-connection cleanup and one
// context deadline spanning both requests and the unchanged stored-choice work.
func runHTTPDemoAlice(
	ctx context.Context, client *http.Client, alice key.Handle,
	expectedRoot key.Public, base string, out io.Writer,
) (acceptance key.Signature, err error) {
	defer err2.Handle(&err)

	return exchangeHTTPDemo(ctx, client, alice, base, out,
		func(data []byte) (signature key.Signature, err error) {
			defer err2.Handle(&err, nil)

			return saveExchangeAcceptance(ctx, alice, expectedRoot, data, out)
		})
}

// Shares the exact conversation across the two concrete Vault lifetimes.
func exchangeHTTPDemo(
	ctx context.Context, client *http.Client, alice key.Handle,
	base string, out io.Writer,
	save func([]byte) (key.Signature, error),
) (acceptance key.Signature, err error) {
	defer err2.Handle(&err, nil)

	try.To(ctx.Err())
	info := try.To1(exchangePublicInfo(alice))
	data := try.To1(postHTTPDemo(ctx, client, base, "offer",
		wire.TryMarshal(info), http.StatusOK))
	signature := try.To1(save(data))

	try.To(ctx.Err())
	try.To1(postHTTPDemo(ctx, client, base, "acceptance",
		wire.TryMarshal(signature), http.StatusNoContent))
	try.To(ctx.Err())
	try.To1(fmt.Fprintln(out, "issuer returned HTTP 204: true"))
	return signature, nil
}

func postHTTPDemo(
	ctx context.Context, client *http.Client, base, operation string,
	body []byte, wantStatus int,
) (data []byte, err error) {
	defer err2.Handle(&err)

	try.To(ctx.Err())
	try.To(checkExchangePayload(body))
	request := try.To1(http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/intro/"+operation, bytes.NewReader(body)))
	request.Header.Set("Content-Type", "application/cbor")
	response := try.To1(client.Do(request))
	data, readErr := readHTTPDemoResponse(response, operation, wantStatus)
	closeErr := response.Body.Close()
	try.To(errors.Join(readErr, closeErr))
	return data, nil
}

func readHTTPDemoResponse(
	response *http.Response, operation string, wantStatus int,
) (data []byte, err error) {
	defer err2.Handle(&err)

	if response.StatusCode != wantStatus {
		return nil, fmt.Errorf("%s returned HTTP %d", operation,
			response.StatusCode)
	}
	if wantStatus == http.StatusOK {
		media, _, mediaErr := mime.ParseMediaType(
			response.Header.Get("Content-Type"),
		)
		if mediaErr != nil || media != "application/cbor" {
			return nil, errors.New("offer response requires application/cbor")
		}
	}
	read, _, readErr := readHTTPExchangeBody(response.Body)
	try.T(readErr)("reading " + operation + " response")
	if wantStatus == http.StatusNoContent && len(read) != 0 {
		return nil, errors.New("acceptance HTTP 204 must have no body")
	}
	return read, nil
}
