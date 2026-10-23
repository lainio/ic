package intro

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
)

// Flags have been validated before creating Alice or any temporary resources.
func startHTTPOwner(
	ctx context.Context, expectedRoot key.Public, base, address string,
	timeout time.Duration, out io.Writer,
) (err error) {
	defer err2.Handle(&err)

	try.To(ctx.Err())
	alice := key.New()
	info := try.To1(exchangePublicInfo(alice))
	demo := try.To1(setupOwnerStatusResources(ctx, expectedRoot, info.Public))
	defer func() { try.Out(demo.close()).Logf() }()
	listener, listenErr := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if listenErr != nil {
		return errors.Join(listenErr, demo.close())
	}
	client := newHTTPDemoClient()
	defer client.CloseIdleConnections()
	return runHTTPOwner(ctx, listener, demo, client, alice, expectedRoot,
		base, timeout, out)
}

// Owns the bound listener and resources. Exchange failure closes the listener
// without serving or advertising. After success, Serve joins before storage
// cleanup; only the conversation is bounded by the exchange deadline.
func runHTTPOwner(
	ctx context.Context, listener net.Listener, demo *ownerStatusDemo,
	client *http.Client, alice key.Handle, expectedRoot key.Public,
	base string, timeout time.Duration, out io.Writer,
) (err error) {
	defer func() { try.Out(demo.close()).Logf() }()
	defer func() { err = errors.Join(err, demo.close()) }()
	owned := true
	defer func() {
		if owned {
			err = errors.Join(err, listener.Close())
		}
	}()
	defer err2.Handle(&err)

	exchangeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	try.To1(exchangeHTTPDemo(exchangeCtx, client, alice, base, out,
		func(data []byte) (acceptance key.Signature, err error) {
			defer err2.Handle(&err)

			proposal := try.To1(
				parseExchangeProposal(exchangeCtx, data, out),
			)
			signature := try.To1(signExchangeAcceptance(
				demo.vault, alice, expectedRoot, proposal,
			))
			try.To1(fmt.Fprint(out, exchangeAcceptanceSaved))
			return signature, nil
		}))
	cancel()

	try.To(ctx.Err())
	try.To1(fmt.Fprintf(out,
		"owner status URL: http://%s/owner/status\n"+
			"authorization header file: %s\nstop with Ctrl+C\n",
		listener.Addr().String(), demo.headerFile,
	))
	owned = false
	return serveHTTPDemo(ctx, listener, demo.handler)
}
