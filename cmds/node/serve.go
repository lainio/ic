package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/localhttp"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/lainio/ic/internal/ownerapi"
	"github.com/lainio/ic/key"
	"github.com/spf13/cobra"
)

func newServeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run an existing node's protected local owner reads",
		Long: `Reopen an existing identity and initialized local state until Ctrl+C.
Root can be stopped: --root is an independently supplied public-key pin,
not a peer address. GET /owner/status reads the local choice; authenticated
GET /owner/introduction exports its saved completed public evidence.
Startup and owner reads never contact peers, request introductions, sign,
or resubmit acceptances.
Saved unselected, pending, and completed choices remain as they are.

All four file/identity flags are required and nonempty. The identity unlock
and storage-key files must be distinct and outside the node directory.
Missing or invalid state fails without initialization or repair.

Use the printed owner status URL and authorization header file in another
terminal (keep the @):
  curl -q --noproxy '*' --max-time 5 --silent --show-error --include \
    --header '@HEADER_FILE' OWNER_STATUS_URL

Requires a trusted local host. HTTP is loopback plaintext only; do not forward
or expose it remotely. The credential now grants these two owner reads,
including disclosure of public keys, ancestor links, and signatures. It grants
no signing, mutation, peer access, or enrollment permission. The UI's explicit
Copy introduction action copies a development JSON transfer document (version,
base64 proposal, base64 acceptance), limited to 128 KiB; it is not a backup.
Ctrl+C removes only this invocation's temporary credentials; identity, state,
unlock and storage-key files persist. Opening the Store retains its existing
encryption block charge; individual owner reads perform no encryption.`,
		Example: `  tdc node serve --dir ALICE_DIR --unlock-file ALICE_UNLOCK_FILE \
    --storage-key-file ALICE_STORAGE_KEY_FILE --root ROOT_PUBLIC_KEY_HEX \
    --listen 127.0.0.1:0`,
		Args: cobra.NoArgs,
		RunE: runServe,
	}
	cmd.Flags().
		String("dir", "", "Existing private node directory with initialized state")
	cmd.Flags().
		String("unlock-file", "", "Existing separate private identity unlock file")
	cmd.Flags().
		String("storage-key-file", "", "Existing separate private storage key file")
	cmd.Flags().
		String("root", "", "Expected Root public-key hex (at most 16 KiB decoded)")
	cmd.Flags().String("listen", "127.0.0.1:0",
		"Explicit loopback host and numeric port; localhost normalizes to 127.0.0.1; zero selects a free port")
	for _, name := range []string{"dir", "unlock-file", "storage-key-file", "root"} {
		try.To(cmd.MarkFlagRequired(name))
	}
	return cmd
}

func runServe(cmd *cobra.Command, args []string) (err error) {
	defer err2.Handle(&err)

	try.To(cmd.ValidateArgs(args))
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
	defer stop()
	s, address := try.To2(setupNodeServe(ctx, cmd))
	defer func() { try.Out(s.close()).Logf() }()
	listener, listenErr := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if listenErr != nil {
		return errors.Join(listenErr, s.close())
	}
	return runNodeServe(ctx, listener, s, cmd.OutOrStdout())
}

// Owns only this invocation's Store and temporary credentials. Persistent paths
// are never cleanup inputs, and no signing handle reaches this holder or HTTP.
type nodeServe struct {
	store                     *nodevault.Store
	child                     key.Public
	credentialDir, headerFile string
	handler                   http.Handler
}

// Validate all inputs before restoring the identity or opening persistent
// state. Setup binds no listener and never provisions state or retries a choice.
func setupNodeServe(ctx context.Context, cmd *cobra.Command) (
	service *nodeServe, address string, err error,
) {
	s := &nodeServe{}
	defer func() {
		if service == nil {
			try.Out(s.close()).Logf()
		}
	}()
	defer func() {
		if service == nil {
			err = errors.Join(err, s.close())
		}
	}()
	defer err2.Handle(&err)

	try.To(cmd.ValidateRequiredFlags())
	for _, name := range []string{"dir", "unlock-file", "storage-key-file", "root"} {
		if strings.TrimSpace(try.To1(cmd.Flags().GetString(name))) == "" {
			return nil, "", fmt.Errorf("--%s must be nonempty", name)
		}
	}
	address = try.T1(localhttp.Address(
		try.To1(cmd.Flags().GetString("listen")), true,
	))("checking --listen")
	root := try.To1(parseRootHex(try.To1(cmd.Flags().GetString("root"))))
	dir, unlock := try.To2(commandPaths(cmd))
	dir, unlock = try.To2(nodeidentity.ResolvePaths(dir, unlock))
	keyFile := try.To1(cmd.Flags().GetString("storage-key-file"))
	_, keyFile = try.To2(nodeidentity.ResolvePaths(dir, keyFile))
	if keyFile == unlock {
		return nil, "", errors.New(
			"storage key file must differ from identity unlock file",
		)
	}
	try.To(ctx.Err())

	handle := try.To1(nodeidentity.OpenDirectory(dir, unlock))
	s.child = try.To1(handle.CBORPublicKey())
	s.store = try.To1(nodevault.OpenForNode(ctx, dir, keyFile, root, s.child))
	s.credentialDir = try.To1(os.MkdirTemp("", "node-owner-status-"))
	s.handler, s.headerFile = try.To2(ownerapi.NewReadCredentials(
		ctx, s.store.Vault(), root, s.child, s.credentialDir,
	))
	return s, address, nil
}

// Call after HTTP has stopped and joined. Attempt every cleanup and retain its
// errors; closing the Store releases the lock without removing persistent files.
func (s *nodeServe) close() error {
	var closeErr, removeErr error
	if s.store != nil {
		closeErr = s.store.Close()
	}
	if s.credentialDir != "" {
		removeErr = os.RemoveAll(s.credentialDir)
	}
	return errors.Join(closeErr, removeErr)
}

// Owns the bound listener and setup resources, including on output failure.
// localhttp.Serve joins HTTP before the Store is closed.
func runNodeServe(ctx context.Context, listener net.Listener, s *nodeServe,
	out io.Writer,
) (err error) {
	defer func() { try.Out(s.close()).Logf() }()
	defer func() { err = errors.Join(err, s.close()) }()
	owned := true
	defer func() {
		if owned {
			err = errors.Join(err, listener.Close())
		}
	}()
	defer err2.Handle(&err)

	try.To(ctx.Err())
	try.To1(fmt.Fprintf(out,
		"node public key (hex): %x\n"+
			"owner status URL: http://%s/owner/status\n"+
			"authorization header file: %s\nstop with Ctrl+C\n",
		s.child, listener.Addr().String(), s.headerFile,
	))
	owned = false
	return localhttp.Serve(ctx, listener, s.handler)
}
