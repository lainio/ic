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
) (_ http.Handler, _ string, err error) {
	defer err2.Handle(&err)

	// This credential is independent of the provider secret and signing keys.
	token := make([]byte, 32)
	defer clear(token)
	try.To1(rand.Read(token))
	handler := try.To1(NewAuthenticatedStatusHandler(
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
