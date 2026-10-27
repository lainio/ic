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
	"sync"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/localhttp"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/lainio/ic/internal/ownerapi"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/key"
	"github.com/spf13/cobra"
)

func newServeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Inspect and retain introductions on an existing local node",
		Long: `Reopen an existing identity and initialized local state until Ctrl+C.
Root can be stopped: --root is an independently supplied public-key pin,
not a peer address. GET /owner/status reads the local choice; authenticated
GET /owner/introduction exports its saved completed public evidence.
POST /owner/introduction/check checks a pasted public document's path and final
child acceptance against this node's configured Root, including other subjects.
POST /owner/introductions deliberately saves received evidence after rechecking;
GET /owner/introductions lists saved subject keys, including self evidence.
POST /owner/introductions/fetch explicitly fetches another node's completed
introduction and saves it in Received under this node's configured Root.
Its JSON body has only peer_url: http://LOOPBACK:PORT/peer/introduction.
Use a literal loopback IP or localhost (no DNS), with an explicit nonzero port.
The Go node makes one direct GET, limited to 5 seconds and 128 KiB, without
redirects, proxies, cookies, or owner credentials. Self-fetch is refused.
POST /owner/introductions/verify with {} explicitly verifies saved Received
evidence into local Known and returns newly_known and all known_subjects.
It makes no peer request. Fetch, save, list, and startup never promote evidence.
Startup and owner inspection never contact peers, request introductions, sign,
or resubmit acceptances.
Saved unselected, pending, and completed choices remain as they are.

All four file/identity flags are required and nonempty. The identity unlock
and storage-key files must be distinct and outside the node directory.
Missing or invalid state fails without initialization or repair.

--peer-listen explicitly opts in to a second plaintext loopback listener.
GET /peer/introduction makes only this node's completed introduction path
(public keys, ancestor links and signatures) available to any local caller,
without a bearer token. Disabled by default; no peer socket exists otherwise.
This is sender-side disclosure only, not discovery, an ad, present key control,
receiver Received/Known changes, mutual authentication, a connection, or chat.

Use the printed owner status URL and authorization header file in another
terminal (keep the @):
  curl -q --noproxy '*' --max-time 5 --silent --show-error --include \
    --header '@HEADER_FILE' OWNER_STATUS_URL

Requires a trusted local host. HTTP is loopback plaintext only; do not forward
or expose it remotely. The fresh operational credential grants the existing reads,
stateless check, and these exact save/list/fetch/verify routes, including public keys,
ancestor links, and signatures. Read/status credentials retain their old scope.
It additionally authorizes POST /owner/device/bootstrap with {}: one durable
first-device authorization using this node's restored software signer, after its
own evidence is Known. Success reports usability only at that call's probe.
Startup/restart never bootstrap or probe; a repeated POST returns 409 without
signing or writing, and does not establish current usability. After a lost
response, inspection/retry must be explicit. Evidence credentials keep their
old scope, as do device-only credentials.
POST /owner/ads/publish with {} explicitly signs and stores a fresh local ad for
this process's actual bound --peer-listen endpoint, after device bootstrap.
The operational bearer now authorizes this signing request. No endpoint or other
signing input is accepted. Slot 1, epoch 0, and a 15-minute TTL are fixed.
A second POST replaces the current ad; startup never publishes or renews it.
No peer ad serving, verified reachability, trust, or connection is created.
After a lost response, do not automatically retry publication.
The UI's explicit
Copy introduction action copies a development JSON transfer document (version,
base64 proposal, base64 acceptance), limited to 128 KiB; it is not a backup.
Check introduction returns the subject public key and labels self evidence.
Save retains the exact proposal and acceptance for at most 32 subjects.
A different proposal for an existing subject is refused locally; exact retries
retain the original acceptance without another encryption. Load explicitly to
refresh the saved list. Saved evidence creates no connection or Known state
and proves no present key control, freshness, revocation status, global uniqueness,
or live authenticated channel.
Explicit verification creates locally verified evidence, not connection or trust.
An explicit retry is safe and makes no write when nothing is newly Known.
Ctrl+C removes only this invocation's temporary credentials; identity, state,
unlock and storage-key files persist. Opening the Store retains its existing
encryption block charge; reads, checks, and duplicate saves use no encryption.
A new save uses the existing encrypted Vault and may fail if capacity is exhausted.`,
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
	cmd.Flags().String("peer-listen", "",
		"Opt in to disclosing your completed introduction to any local caller; explicit loopback host and numeric port")
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
	owner, peer, listenErr := bindNodeListeners(ctx, address, s.peerAddress)
	if listenErr != nil {
		return errors.Join(listenErr, s.close())
	}
	return runNodeServe(ctx, owner, peer, s, cmd.OutOrStdout())
}

// Owns only this invocation's Store and temporary credentials. Persistent paths
// are never cleanup inputs. Only the operational owner handler borrows the
// restored signing handle; the separate peer handler remains signer-free.
type nodeServe struct {
	store                     *nodevault.Store
	child                     key.Public
	credentialDir, headerFile string
	handler                   http.Handler
	peerAddress               string
	peerHandler               http.Handler
	configurePublication      func(net.Listener)
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
	if value := try.To1(cmd.Flags().GetString("peer-listen")); value != "" {
		s.peerAddress = try.T1(localhttp.Address(value, true))("checking --peer-listen")
		if s.peerAddress == address && !strings.HasSuffix(address, ":0") {
			return nil, "", errors.New("owner and peer listeners must use separate endpoints")
		}
	}
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
	s.handler, s.headerFile, s.configurePublication = try.To3(ownerapi.NewPublicationCredentials(
		ctx, s.store.Vault(), root, s.child, handle, s.credentialDir,
	))
	if s.peerAddress != "" {
		s.peerHandler = peerapi.NewHandler(s.store.Vault(), root, s.child)
	}
	return s, address, nil
}

// Bind both sockets before serving either. A failed second bind releases the
// first socket; the caller still owns setup resources and persistent files.
func bindNodeListeners(ctx context.Context, ownerAddress, peerAddress string) (
	owner, peer net.Listener, err error,
) {
	config := &net.ListenConfig{}
	owner, err = config.Listen(ctx, "tcp", ownerAddress)
	if err != nil || peerAddress == "" {
		return owner, nil, err
	}
	peer, err = config.Listen(ctx, "tcp", peerAddress)
	if err != nil {
		return nil, nil, errors.Join(err, owner.Close())
	}
	return owner, peer, nil
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

// Owns both bound listeners and setup resources, including on output failure.
// serveNodeListeners joins HTTP and admitted requests before the Store closes.
func runNodeServe(ctx context.Context, owner, peer net.Listener, s *nodeServe,
	out io.Writer,
) (err error) {
	defer func() { try.Out(s.close()).Logf() }()
	defer func() { err = errors.Join(err, s.close()) }()
	owned := true
	defer func() {
		if owned {
			err = errors.Join(err, owner.Close())
			if peer != nil {
				err = errors.Join(err, peer.Close())
			}
		}
	}()
	defer err2.Handle(&err)

	try.To(ctx.Err())
	try.To1(fmt.Fprintf(out,
		"node public key (hex): %x\n"+
			"owner status URL: http://%s/owner/status\n"+
			"authorization header file: %s\nstop with Ctrl+C\n",
		s.child, owner.Addr().String(), s.headerFile,
	))
	if peer != nil {
		try.To1(fmt.Fprintf(out, "peer introduction URL: http://%s/peer/introduction\n",
			peer.Addr().String()))
	}
	owned = false
	return serveNodeListeners(ctx, owner, peer, s)
}

// Each Serve owns one socket and performs bounded shutdown. Cancel the sibling
// on any exit, retaining both results and joining both before closing the Store.
func serveNodeListeners(ctx context.Context, owner, peer net.Listener, s *nodeServe) error {
	// Both sockets are bound before either HTTP server starts. Freeze the actual
	// peer endpoint (including the selected port), or disable publication.
	if s.configurePublication != nil {
		s.configurePublication(peer)
	}
	// Close after an unexpected Serve exit cancels connections but does not
	// join active handlers. Drain admitted requests before releasing the Vault,
	// and prevent a late HTTP goroutine from entering it after shutdown.
	var requests sync.RWMutex
	stopped := false
	join := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.RLock()
			defer requests.RUnlock()
			if stopped {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	defer func() {
		requests.Lock()
		stopped = true
		requests.Unlock()
	}()
	if peer == nil {
		return localhttp.Serve(ctx, owner, join(s.handler))
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	finished := make(chan error, 2)
	go func() { finished <- localhttp.Serve(ctx, owner, join(s.handler)) }()
	go func() { finished <- localhttp.Serve(ctx, peer, join(s.peerHandler)) }()
	first := <-finished
	cancel()
	return errors.Join(first, <-finished)
}
