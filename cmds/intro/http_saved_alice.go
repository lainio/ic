package intro

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/spf13/cobra"
)

type savedAlicePaths struct{ dir, unlock, storageKey string }

// Validate presence before loading identities, opening state or binding HTTP.
func httpSavedAlicePaths(
	cmd *cobra.Command,
) (paths savedAlicePaths, saved bool, err error) {
	defer err2.Handle(&err)

	flags := cmd.Flags()
	count := 0
	for _, name := range []string{"identity-dir", "unlock-file", "storage-key-file"} {
		if flags.Changed(name) {
			count++
		}
	}
	if count == 0 {
		return savedAlicePaths{}, false, nil
	}
	if count != 3 {
		return savedAlicePaths{}, false, errors.New(
			"--identity-dir, --unlock-file and --storage-key-file must all be supplied",
		)
	}
	paths.dir = try.To1(flags.GetString("identity-dir"))
	paths.unlock = try.To1(flags.GetString("unlock-file"))
	paths.storageKey = try.To1(flags.GetString("storage-key-file"))
	for _, value := range []string{paths.dir, paths.unlock, paths.storageKey} {
		if strings.TrimSpace(value) == "" {
			return savedAlicePaths{}, false, errors.New(
				"saved-state flags must be nonempty",
			)
		}
	}
	return paths, true, nil
}

// This invocation owns the Store and optional temporary credentials. Only the
// credential directory is removable; persistent paths are never cleanup inputs.
type httpSavedAlice struct {
	store                     *nodevault.Store
	alice                     key.Handle
	root, child               key.Public
	credentialDir, headerFile string
	handler                   http.Handler
}

func openHTTPSavedAlice(ctx context.Context, paths savedAlicePaths,
	expectedRoot key.Public) (_ *httpSavedAlice, err error) {
	defer err2.Handle(&err)

	try.To(ctx.Err())
	dir, unlock := try.To2(nodeidentity.ResolvePaths(paths.dir, paths.unlock))
	_, storageKey := try.To2(nodeidentity.ResolvePaths(dir, paths.storageKey))
	if storageKey == unlock {
		return nil, errors.New(
			"storage key file must differ from identity unlock file",
		)
	}
	alice := try.To1(nodeidentity.OpenDirectory(dir, unlock))
	child := try.To1(alice.CBORPublicKey())
	store := try.To1(
		nodevault.OpenForNode(ctx, dir, storageKey, expectedRoot, child),
	)
	return &httpSavedAlice{store: store, alice: alice,
		root: expectedRoot, child: child}, nil
}

func (a *httpSavedAlice) setupOwner(ctx context.Context) (err error) {
	defer err2.Handle(&err)

	try.To(ctx.Err())
	a.credentialDir = try.To1(os.MkdirTemp("", "intro-saved-alice-owner-"))
	a.handler, a.headerFile = try.To2(setupOwnerStatusCredentials(
		ctx, a.store.Vault(), a.root, a.child, a.credentialDir,
	))
	return nil
}

// Call only after HTTP has stopped and joined. Attempt every cleanup and keep
// its errors. Closing the Store releases its lock and retains all node files.
func (a *httpSavedAlice) close() error {
	closeErr := a.store.Close()
	var removeErr error
	if a.credentialDir != "" {
		removeErr = os.RemoveAll(a.credentialDir)
	}
	return errors.Join(closeErr, removeErr)
}

// Inputs have already been validated. Saved mode never generates an identity
// or provisions state; only owner credentials are temporary.
func startHTTPSavedAlice(ctx context.Context, paths savedAlicePaths,
	expectedRoot key.Public, base, ownerAddress string,
	timeout time.Duration, out io.Writer) (err error) {
	var a *httpSavedAlice
	defer func() {
		if a != nil {
			try.Out(a.close()).Logf()
		}
	}()
	defer func() {
		if a != nil {
			err = errors.Join(err, a.close())
		}
	}()
	defer err2.Handle(&err)

	a = try.To1(openHTTPSavedAlice(ctx, paths, expectedRoot))
	client := newHTTPDemoClient()
	defer client.CloseIdleConnections()
	if ownerAddress == "" {
		_, err = runHTTPSavedAliceOnce(ctx, client, a, base, timeout, out)
		return err
	}
	try.To(a.setupOwner(ctx))
	listener := try.To1((&net.ListenConfig{}).Listen(ctx, "tcp", ownerAddress))
	return runHTTPSavedAliceOwner(ctx, listener, a, client, base, timeout, out)
}

func runHTTPSavedAliceOnce(ctx context.Context, client *http.Client,
	a *httpSavedAlice, base string, timeout time.Duration, out io.Writer,
) (acceptance key.Signature, err error) {
	defer func() { try.Out(a.close()).Logf() }()
	defer func() {
		err = errors.Join(err, a.close())
		if err != nil {
			acceptance = nil
		}
	}()
	defer err2.Handle(&err)

	exchangeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return exchangeHTTPSavedAlice(exchangeCtx, client, a, base, out)
}

// Borrows this invocation's restored handle and Store. Read selection before
// the first peer request. Onboarding owns all choice/signature/retry decisions.
func exchangeHTTPSavedAlice(ctx context.Context, client *http.Client,
	a *httpSavedAlice, base string, out io.Writer,
) (acceptance key.Signature, err error) {
	defer err2.Handle(&err)

	try.To(ctx.Err())
	choice, found := try.To2(
		onboarding.ReadStoredChoice(a.store.Vault(), a.root, a.child),
	)
	try.To1(fmt.Fprintf(out, "node public key (hex): %x\n", a.child))
	if !found {
		return exchangeHTTPDemo(ctx, client, a.alice, base, out,
			func(data []byte) (signature key.Signature, err error) {
				defer err2.Handle(&err)

				proposal := try.To1(parseExchangeProposal(ctx, data, out))
				signed := try.To1(
					signExchangeAcceptance(
						a.store.Vault(),
						a.alice,
						a.root,
						proposal,
					),
				)
				try.To1(fmt.Fprint(out, exchangeAcceptanceSaved))
				return signed, nil
			})
	}

	proposal := try.To1(
		parseExchangeProposal(ctx, choice.Proposal.Bytes(), io.Discard),
	)
	try.To1(fmt.Fprintln(out, "using saved introduction: true"))
	signed := try.To1(
		signExchangeAcceptance(a.store.Vault(), a.alice, a.root, proposal),
	)
	try.To1(fmt.Fprint(out, exchangeAcceptanceSaved))
	try.To1(
		postHTTPDemo(
			ctx,
			client,
			base,
			"acceptance",
			wire.TryMarshal(signed),
			http.StatusNoContent,
		),
	)
	try.To(ctx.Err())
	try.To1(fmt.Fprintln(out, "issuer returned HTTP 204: true"))
	return signed, nil
}

// Owns the listener and resources. An exchange failure never starts serving;
// success ends only the exchange deadline, then uses the existing HTTP lifecycle.
func runHTTPSavedAliceOwner(ctx context.Context, listener net.Listener,
	a *httpSavedAlice, client *http.Client, base string,
	timeout time.Duration, out io.Writer) (err error) {
	defer func() { try.Out(a.close()).Logf() }()
	defer func() { err = errors.Join(err, a.close()) }()
	owned := true
	defer func() {
		if owned {
			err = errors.Join(err, listener.Close())
		}
	}()
	defer err2.Handle(&err)

	exchangeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	try.To1(exchangeHTTPSavedAlice(exchangeCtx, client, a, base, out))
	cancel()

	try.To(ctx.Err())
	try.To1(fmt.Fprintf(out,
		"owner status URL: http://%s/owner/status\n"+
			"authorization header file: %s\nstop with Ctrl+C\n",
		listener.Addr().String(), a.headerFile,
	))
	owned = false
	return serveHTTPDemo(ctx, listener, a.handler)
}
