package intro

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	coreintro "github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/ownerapi"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
	"github.com/spf13/cobra"
)

func newOwnerStatusDemoCommand() *cobra.Command {
	var listen string
	cmd := &cobra.Command{
		Use:   "owner-status-demo CASE",
		Short: "Inspect a temporary Vault through protected loopback HTTP",
		Long: `Serve owner status until Ctrl+C with a fresh private credential file.
Choose unselected or completed; completed signs and saves one R -> Alice offer
during setup. HTTP requests only inspect stored choice and cannot sign.
This disposable developer listener is separate from peer HTTP. It creates no
membership, Known, trust, device authority, or restartable operational identity.
Plaintext loopback requires a trusted local machine; do not forward or publish
this endpoint. Remote owner access and production provisioning are separate work.`,
		Example:   "  tdc intro owner-status-demo completed --listen 127.0.0.1:0",
		Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		ValidArgs: []string{"unselected", "completed"},
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			defer err2.Handle(&err)

			try.To(cmd.ValidateArgs(args))
			address := try.T1(
				httpDemoAddress(listen, true),
			)(
				"checking --listen",
			)
			try.To(cmd.Context().Err())
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()

			demo := try.To1(setupOwnerStatusDemo(ctx, args[0]))
			defer func() { try.Out(demo.close()).Logf() }()
			listener, listenErr := (&net.ListenConfig{}).Listen(
				ctx,
				"tcp",
				address,
			)
			if listenErr != nil {
				return errors.Join(listenErr, demo.close())
			}
			return runOwnerStatusDemo(ctx, listener, demo, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:0",
		"Explicit loopback host and numeric port (zero selects a free port)")
	return cmd
}

// Private, single-owner setup state. HTTP borrows only the configured handler;
// this holder keeps no signing handles.
type ownerStatusDemo struct {
	fixture, dir, headerFile string
	provider                 *storedChoiceProvider
	db                       *storage.Database
	vault                    *storage.Vault
	handler                  http.Handler
}

// Setup performs no listening. Fixture labels select setup work, never HTTP
// authorization. Expected public identities come from fresh local handles.
func setupOwnerStatusDemo(
	ctx context.Context, fixture string,
) (_ *ownerStatusDemo, err error) {
	var demo *ownerStatusDemo
	ready := false
	defer func() {
		if demo != nil && !ready {
			try.Out(demo.close()).Logf()
		}
	}()
	defer func() {
		if demo != nil && !ready {
			err = errors.Join(err, demo.close())
		}
	}()
	defer err2.Handle(&err)

	try.To(ctx.Err())
	if fixture != "unselected" && fixture != "completed" {
		return nil, errors.New("fixture must be unselected or completed")
	}
	root, alice := key.New(), key.New()
	rootInfo := try.To1(exchangePublicInfo(root))
	aliceInfo := try.To1(exchangePublicInfo(alice))
	expectedRoot := rootInfo.Public
	demo = try.To1(
		setupOwnerStatusResources(ctx, expectedRoot, aliceInfo.Public),
	)
	demo.fixture = fixture

	if fixture == "completed" {
		offer := coreintro.New(rootInfo).Introduce(root, aliceInfo)
		acceptance := try.To1(onboarding.SignAfterStoredChoice(
			demo.vault, alice, expectedRoot, expectedRoot, offer,
		))
		try.To(offer.VerifyAcceptance(acceptance))
	}
	try.To(ctx.Err())
	ready = true
	return demo, nil
}

// Creates an unselected Vault and independent credential for caller-selected
// public identities. No fixture or signing handle is constructed here.
func setupOwnerStatusResources(
	ctx context.Context, expectedRoot, expectedChild key.Public,
) (_ *ownerStatusDemo, err error) {
	demo := &ownerStatusDemo{}
	ready := false
	defer func() {
		if !ready {
			try.Out(demo.close()).Logf()
		}
	}()
	defer func() {
		if !ready {
			err = errors.Join(err, demo.close())
		}
	}()
	defer err2.Handle(&err)

	try.To(ctx.Err())
	demo.dir = try.To1(os.MkdirTemp("", "intro-owner-status-demo-"))
	demo.provider = newStoredChoiceProvider()
	try.To1(rand.Read(demo.provider.secret))
	demo.db = try.To1(storage.OpenBolt(filepath.Join(demo.dir, "vault.db")))
	p := demo.provider
	try.To(demo.db.CreateVault(ctx, p.vault, p.id, p))
	demo.vault = try.To1(demo.db.OpenVault(ctx, p.vault, p.id, p))
	demo.handler, demo.headerFile = try.To2(setupOwnerStatusCredentials(
		ctx, demo.vault, expectedRoot, expectedChild, demo.dir,
	))

	ready = true
	return demo, nil
}

// Borrows the open Vault and a caller-owned private directory. The caller owns
// HTTP shutdown and directory cleanup; this helper owns only credential setup.
func setupOwnerStatusCredentials(ctx context.Context, vault *storage.Vault,
	expectedRoot, expectedChild key.Public, dir string,
) (_ http.Handler, _ string, err error) {
	defer err2.Handle(&err)

	// This credential is independent of the provider secret and signing keys.
	token := make([]byte, 32)
	defer clear(token)
	try.To1(rand.Read(token))
	handler := try.To1(ownerapi.NewAuthenticatedStatusHandler(
		vault, expectedRoot, expectedChild, token,
	))
	headerFile := filepath.Join(dir, "owner.header")
	header := try.To1(os.OpenFile(
		headerFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600,
	))
	closed := false
	defer func() {
		if !closed {
			try.Out(header.Close()).Logf()
		}
	}()
	_, writeErr := fmt.Fprintf(header,
		"Authorization: Bearer %s\n", hex.EncodeToString(token),
	)
	closeErr := header.Close()
	closed = true
	try.To(errors.Join(writeErr, closeErr))
	try.To(ctx.Err())

	return handler, headerFile, nil
}

// Called only after HTTP has stopped. All cleanup is attempted and every cause
// is returned; deferred logging at callers is only a fallback.
func (d *ownerStatusDemo) close() error {
	var vaultErr, dbErr, removeErr error
	if d.vault != nil {
		vaultErr = d.vault.Close()
	}
	if d.db != nil {
		dbErr = d.db.Close()
	}
	if d.provider != nil {
		clear(d.provider.secret)
	}
	if d.dir != "" {
		removeErr = os.RemoveAll(d.dir)
	}
	return errors.Join(vaultErr, dbErr, removeErr)
}

// Owns both the bound listener and setup resources, including on readiness
// failure. Serve joins and shuts down before Vault/database cleanup begins.
func runOwnerStatusDemo(
	ctx context.Context, listener net.Listener, demo *ownerStatusDemo,
	out io.Writer,
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

	try.To(ctx.Err())
	try.To1(fmt.Fprintf(out,
		"fixture: %s\nowner status URL: http://%s/owner/status\n"+
			"authorization header file: %s\nstop with Ctrl+C\n",
		demo.fixture, listener.Addr().String(), demo.headerFile,
	))
	owned = false
	return serveHTTPDemo(ctx, listener, demo.handler)
}
