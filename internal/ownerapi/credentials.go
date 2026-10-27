package ownerapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// NewStatusCredentials borrows the open Vault and a caller-owned private
// directory. The caller owns HTTP shutdown and directory cleanup; this helper
// owns only credential setup, exclusively creating a private owner.header file.
func NewStatusCredentials(ctx context.Context, vault *storage.Vault,
	expectedRoot, expectedChild key.Public, dir string,
) (http.Handler, string, error) {
	return newCredentials(ctx,
		NewStatusHandler(vault, expectedRoot, expectedChild), dir,
	)
}

// NewReadCredentials grants GET /owner/status, GET /owner/introduction, and
// stateless POST /owner/introduction/check.
// Unlike status-only credentials, possession permits disclosure of the saved
// completed public path and acceptance, and inspection of submitted evidence
// under the configured Root. POST carries input; it authorizes no persistence,
// signing, enrollment, peer access, or other writes or future POST operations.
// It borrows the open Vault without a signing handle and copies independently
// configured public identities. The caller owns HTTP shutdown, the Vault, and
// private-directory cleanup; owner.header is created exclusively with mode 0600.
func NewReadCredentials(ctx context.Context, vault *storage.Vault,
	expectedRoot, expectedChild key.Public, dir string,
) (http.Handler, string, error) {
	return newCredentials(ctx,
		newReadHandler(vault, expectedRoot, expectedChild), dir,
	)
}

// NewEvidenceCredentials grants the read/check surface plus exactly GET and
// POST /owner/introductions. POST may retain submitted received evidence after
// revalidation. POST /owner/introductions/fetch additionally permits one bounded
// direct loopback GET of /peer/introduction and a Received-only save under the
// configured Root. POST /owner/introductions/verify explicitly promotes valid
// Received evidence to local Known using VerifyReceived, without peer requests.
// It grants no other peer access, signing, trust, or future POST rights.
// Vault/identity ownership and private credential creation match NewReadCredentials.
func NewEvidenceCredentials(ctx context.Context, vault *storage.Vault,
	expectedRoot, expectedChild key.Public, dir string,
) (http.Handler, string, error) {
	return newCredentials(ctx,
		newEvidenceHandler(vault, expectedRoot, expectedChild), dir,
	)
}

// NewDeviceCredentials grants the evidence routes plus
// POST /owner/device/bootstrap, an explicit durable first
// authorization of the already restored local software signer. It borrows that
// signer exclusively for this route; construction never probes or bootstraps.
// The caller must keep configuration fixed, serialize any external evidence or
// signer use, and join HTTP before closing the Vault. Credential file ownership
// matches NewReadCredentials. Never mount this handler on a peer listener.
func NewDeviceCredentials(ctx context.Context, vault *storage.Vault,
	expectedRoot, expectedChild key.Public, signer key.Handle, dir string,
) (http.Handler, string, error) {
	return newCredentials(ctx,
		newDeviceHandler(vault, expectedRoot, expectedChild, signer), dir,
	)
}

// NewPublicationCredentials grants the device routes plus exactly
// POST /owner/ads/publish. Construction never probes, signs, or accesses Vault
// state. The returned one-shot closure must receive this service's bound peer
// listener before Serve starts; nil permanently disables publication. Until
// wired, publication returns 409. The endpoint is copied from Addr, never HTTP
// input, and cannot change during this invocation. The closure and publication
// share the device mutation lock, including if accidentally called concurrently.
// Caller ownership matches NewDeviceCredentials; never mount on a peer listener.
func NewPublicationCredentials(ctx context.Context, vault *storage.Vault,
	expectedRoot, expectedChild key.Public, signer key.Handle, dir string,
) (http.Handler, string, func(net.Listener), error) {
	h := &publicationHandler{deviceHandler: newDeviceHandler(vault, expectedRoot, expectedChild, signer)}
	handler, file, err := newCredentials(ctx, h, dir)
	if err != nil {
		return nil, "", nil, err
	}
	var once sync.Once
	configure := func(peer net.Listener) {
		once.Do(func() {
			h.mutations.Lock()
			defer h.mutations.Unlock()
			if peer != nil {
				h.endpoint = "http://" + peer.Addr().String() + "/peer/introduction"
			}
		})
	}
	return handler, file, configure, nil
}

func newCredentials(ctx context.Context, next http.Handler, dir string,
) (_ http.Handler, _ string, err error) {
	defer err2.Handle(&err)

	// This credential is independent of the provider secret and signing keys.
	token := make([]byte, ownerStatusTokenSize)
	defer clear(token)
	try.To1(rand.Read(token))
	handler := try.To1(newAuthenticatedHandler(next, token))
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
