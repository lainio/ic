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
	"strings"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/localhttp"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/key"
	"github.com/spf13/cobra"
)

// Private development defaults, not protocol policy.
const (
	httpDemoExchangeTimeout = 2 * time.Minute
	httpDemoIdleTimeout     = 30 * time.Second // Also used by the demo client.
)

func newHTTPDemoCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "http-demo",
		Short: "Exchange one direct proposal over local HTTP without a broker",
		Args:  cobra.NoArgs,
		Long: `Run Root and Alice in separate terminals.
Copy BOTH Root's endpoint and public key into accept --url and --root.
Root serves until Ctrl+C; restart Root for a fresh exchange.
Root uses a fresh key unless --identity-dir and --unlock-file select a saved one.
Alice uses a fresh identity and temporary Vault unless all three saved-state
flags select an existing identity and initialized state. Keep Root running
when restarting saved Alice: its issued proposal remains in memory.
Summaries go to stdout; errors exit nonzero via stderr.
HTTP 204 is an unsigned response, not membership or an authenticated receipt.
This plain HTTP demo adds no Known, trust, or pairwise state.`,
	}
	cmd.AddCommand(newHTTPDemoRoleCommand("root"))
	cmd.AddCommand(newHTTPDemoRoleCommand("accept"))
	return cmd
}

func newHTTPDemoRoleCommand(role string) *cobra.Command {
	var listen, endpoint, rootHex, ownerListen string
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

				root := try.To1(selectHTTPDemoRoot(cmd))
				ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
				defer stop()
				try.To(ctx.Err())
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
			paths, saved := try.To2(httpSavedAlicePaths(cmd))
			var ownerAddress string
			if cmd.Flags().Changed("owner-listen") {
				ownerAddress = try.T1(httpDemoAddress(ownerListen, true))(
					"checking --owner-listen",
				)
			}
			if saved {
				ctx, stop := signal.NotifyContext(
					cmd.Context(),
					os.Interrupt,
				)
				defer stop()
				return startHTTPSavedAlice(ctx, paths, expectedRoot, base,
					ownerAddress, timeout, cmd.OutOrStdout())
			}
			if cmd.Flags().Changed("owner-listen") {
				ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
				defer stop()
				return startHTTPOwner(ctx, expectedRoot, base, ownerAddress,
					timeout, cmd.OutOrStdout())
			}
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
		flags.String("identity-dir", "",
			"Existing private Root identity directory (requires --unlock-file)")
		flags.String("unlock-file", "",
			"Separate private Root unlock file (requires --identity-dir)")
	} else {
		cmd.Short = "Accept one offer from an independently selected root"
		flags.StringVar(&endpoint, "url", "", "Required loopback HTTP base URL")
		flags.StringVar(&rootHex, "root", "",
			"Required full hex CBOR public key copied from Root")
		flags.DurationVar(&timeout, "timeout", httpDemoExchangeTimeout,
			"Positive timeout for the whole exchange")
		flags.StringVar(&ownerListen, "owner-listen", "",
			"Keep this Vault open for owner status at an explicit loopback address")
		flags.String("identity-dir", "",
			"Existing Alice directory (requires both key-file flags)")
		flags.String("unlock-file", "",
			"Existing separate private Alice identity unlock file")
		flags.String("storage-key-file", "",
			"Existing separate private Alice storage key file")
		try.To(cmd.MarkFlagRequired("url"))
		try.To(cmd.MarkFlagRequired("root"))
	}
	return cmd
}

// Select Root before allocating server resources; loading never falls back to
// generation. The caller validates --listen before invoking this helper.
func selectHTTPDemoRoot(cmd *cobra.Command) (handle key.Handle, err error) {
	defer err2.Handle(&err)

	flags := cmd.Flags()
	dirSet := flags.Changed("identity-dir")
	unlockSet := flags.Changed("unlock-file")
	if dirSet != unlockSet {
		return nil, errors.New(
			"--identity-dir and --unlock-file must both be supplied",
		)
	}
	dir := try.To1(flags.GetString("identity-dir"))
	unlock := try.To1(flags.GetString("unlock-file"))
	if dirSet &&
		(strings.TrimSpace(dir) == "" || strings.TrimSpace(unlock) == "") {
		return nil, errors.New(
			"--identity-dir and --unlock-file must be nonempty",
		)
	}

	try.To(cmd.Context().Err())
	if !dirSet {
		return key.New(), nil
	}
	return nodeidentity.OpenDirectory(dir, unlock)
}

func httpDemoAddress(value string, allowZero bool) (address string, err error) {
	return localhttp.Address(value, allowZero)
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
	return localhttp.Serve(ctx, listener, handler)
}
