package intro

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
	"github.com/spf13/cobra"
)

// Private development defaults, not protocol policy.
const (
	httpDemoExchangeTimeout = 2 * time.Minute
	httpDemoHeaderTimeout   = 5 * time.Second
	httpDemoReadTimeout     = 15 * time.Second
	httpDemoWriteTimeout    = 15 * time.Second
	httpDemoIdleTimeout     = 30 * time.Second
	httpDemoShutdownTimeout = 5 * time.Second
)

func newHTTPDemoCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "http-demo",
		Short: "Exchange one direct proposal over local HTTP without a broker",
		Args:  cobra.NoArgs,
		Long: `Run Root and Alice in separate terminals with fresh signing handles.
Copy BOTH Root's endpoint and public key into accept --url and --root.
Root serves until Ctrl+C; restart Root for a fresh exchange and key.
Summaries go to stdout; errors exit nonzero via stderr.
HTTP 204 is an unsigned response, not membership or an authenticated receipt.
This disposable plain HTTP demo adds no Known, trust, or pairwise state.`,
	}
	cmd.AddCommand(newHTTPDemoRoleCommand("root"))
	cmd.AddCommand(newHTTPDemoRoleCommand("accept"))
	return cmd
}

func newHTTPDemoRoleCommand(role string) *cobra.Command {
	var listen, endpoint, rootHex string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   role,
		Short: "Serve one R -> Alice proposal until Ctrl+C",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) (err error) {
			defer err2.Handle(&err)

			if role == "root" {
				address := try.T1(httpDemoAddress(listen, true))(
					"checking --listen",
				)
				ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
				defer stop()
				root := key.New()
				listener := try.To1((&net.ListenConfig{}).Listen(
					ctx, "tcp", address,
				))
				return runHTTPDemoRoot(ctx, listener, root, cmd.OutOrStdout())
			}

			base := try.T1(httpDemoEndpoint(endpoint))("checking --url")
			if timeout <= 0 {
				return errors.New("--timeout must be positive")
			}
			expectedRoot := try.T1(
				parseExchangeRoot(rootHex),
			)(
				"checking --root",
			)
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			client := newHTTPDemoClient()
			defer client.CloseIdleConnections()
			_, err = runHTTPDemoAlice(
				ctx, client, key.New(), expectedRoot, base, cmd.OutOrStdout(),
			)
			return err
		},
	}
	flags := cmd.Flags()
	if role == "root" {
		flags.StringVar(
			&listen,
			"listen",
			"127.0.0.1:0",
			"Explicit loopback host and numeric port (zero selects a free port)",
		)
	} else {
		cmd.Short = "Accept one offer from an independently selected root"
		flags.StringVar(&endpoint, "url", "", "Required loopback HTTP base URL")
		flags.StringVar(&rootHex, "root", "",
			"Required full hex CBOR public key copied from Root")
		flags.DurationVar(&timeout, "timeout", httpDemoExchangeTimeout,
			"Positive timeout for the whole exchange")
		try.To(cmd.MarkFlagRequired("url"))
		try.To(cmd.MarkFlagRequired("root"))
	}
	return cmd
}

func httpDemoAddress(value string, allowZero bool) (address string, err error) {
	defer err2.Handle(&err)

	host, port := try.To2(net.SplitHostPort(value))
	if host == "localhost" {
		host = "127.0.0.1" // No DNS lookup, including for localhost.
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", errors.New("host must be explicit loopback")
	}
	if port == "" || strings.IndexFunc(port, func(c rune) bool {
		return c < '0' || c > '9'
	}) >= 0 {
		return "", errors.New("port must be numeric")
	}
	number := try.To1(strconv.ParseUint(port, 10, 16))
	if number == 0 && !allowZero {
		return "", errors.New("HTTP endpoint port must be nonzero")
	}
	return net.JoinHostPort(ip.String(), strconv.FormatUint(number, 10)), nil
}

func httpDemoEndpoint(value string) (endpoint string, err error) {
	defer err2.Handle(&err)

	u := try.To1(url.Parse(value))
	if u.Scheme != "http" || u.User != nil || u.Opaque != "" ||
		u.RawQuery != "" || u.ForceQuery || strings.Contains(value, "#") ||
		(u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return "", errors.New("--url requires one plain loopback HTTP base URL")
	}
	address := try.To1(httpDemoAddress(u.Host, false))
	return "http://" + address, nil
}

// Takes ownership of the already bound listener. Until Serve takes over, this
// function closes it, including on public-key or readiness-output failure.
func runHTTPDemoRoot(
	ctx context.Context, listener net.Listener, root key.Handle, out io.Writer,
) (err error) {
	owned := true
	defer func() {
		if owned {
			err = errors.Join(err, listener.Close())
		}
	}()
	defer err2.Handle(&err)

	public := try.To1(root.CBORPublicKey())
	try.To1(fmt.Fprintf(out,
		"root public key (hex): %s\nHTTP endpoint: http://%s\n"+
			"ready for Alice\nstop with Ctrl+C\n",
		hex.EncodeToString(public), listener.Addr().String(),
	))
	handler := newHTTPExchangeHandler(root)
	owned = false
	return serveHTTPDemo(ctx, listener, handler)
}

// Takes ownership of listener, joins Serve, and finishes bounded shutdown before
// returning. Callers retain ownership of their handler's underlying resources.
func serveHTTPDemo(
	ctx context.Context, listener net.Listener, handler http.Handler,
) error {
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: httpDemoHeaderTimeout,
		ReadTimeout:       httpDemoReadTimeout,
		WriteTimeout:      httpDemoWriteTimeout,
		IdleTimeout:       httpDemoIdleTimeout,
	}
	finished := make(chan error, 1)
	// Serve always closes its listener; never close it twice here.
	go func() { finished <- server.Serve(listener) }()

	select {
	case serveErr := <-finished:
		return errors.Join(
			fmt.Errorf("HTTP server exited unexpectedly: %w", serveErr),
			server.Close(),
		)
	case <-ctx.Done():
		// A completed Serve before our shutdown is still an unexpected exit,
		// even when its error happens to be http.ErrServerClosed.
		select {
		case serveErr := <-finished:
			return errors.Join(
				fmt.Errorf("HTTP server exited unexpectedly: %w", serveErr),
				server.Close(),
			)
		default:
		}
	}

	shutdownCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), httpDemoShutdownTimeout,
	)
	defer cancel()
	shutdownErr := server.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		shutdownErr = errors.Join(shutdownErr, server.Close())
	}
	serveErr := <-finished
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil // Only intentional shutdown may consume this sentinel.
	}
	return errors.Join(shutdownErr, serveErr)
}
