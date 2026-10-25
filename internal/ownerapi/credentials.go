package ownerapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

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
// revalidation. It grants no signing, trust, peer access, or future POST rights.
// Vault/identity ownership and private credential creation match NewReadCredentials.
func NewEvidenceCredentials(ctx context.Context, vault *storage.Vault,
	expectedRoot, expectedChild key.Public, dir string,
) (http.Handler, string, error) {
	return newCredentials(ctx,
		newEvidenceHandler(vault, expectedRoot, expectedChild), dir,
	)
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
