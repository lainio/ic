// Package nodeidentity persists one software signer on a trusted local host.
// It creates no introduction, membership, or device authority.
package nodeidentity

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"

	"github.com/findy-network/findy-agent-auth/acator/enclave"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
)

const maxRecordBytes = 16 * 1024

type record struct {
	Version       int    `json:"version"`
	PublicKey     []byte `json:"public_key"`
	WrappedHandle []byte `json:"wrapped_handle"`
}

// Create exclusively creates a private version-1 record in an existing parent.
// The caller supplies a fresh 32-byte wrapping key for this identity only.
// Errors leave any partial record for operator inspection; they return no handle.
func Create(path string, unlockKey []byte) (handle key.Handle, err error) {
	defer err2.Handle(&err)

	backend := try.To1(newBackend(unlockKey))
	file := try.To1(os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600))
	closed := false
	defer func() {
		if !closed {
			try.Out(file.Close()).Logf()
		}
	}()

	created := try.To1(backend.NewKeyHandle())
	stored := record{
		Version:       1,
		PublicKey:     try.To1(created.CBORPublicKey()),
		WrappedHandle: created.ID(),
	}
	try.To(json.NewEncoder(file).Encode(stored))
	closed = true
	try.To(file.Close())

	return created, nil
}

// Open reads an existing private record without changing or replacing it.
// The backend is independently configured on every call; key.Enclave is unused.
func Open(path string, unlockKey []byte) (handle key.Handle, err error) {
	defer err2.Handle(&err)

	backend := try.To1(newBackend(unlockKey))
	data := try.To1(readRecord(path))
	defer clear(data)
	stored := try.To1(decodeRecord(data))
	try.To(preflight(backend, stored.WrappedHandle))

	ok, restored := backend.IsKeyHandle(stored.WrappedHandle)
	if !ok || restored == nil {
		return nil, errors.New("cannot restore identity handle")
	}
	public := try.To1(restored.CBORPublicKey())
	if !bytes.Equal(public, stored.PublicKey) {
		return nil, errors.New("identity public key mismatch")
	}
	return restored, nil
}

func newBackend(unlockKey []byte) (_ *enclave.Enclave, err error) {
	if len(unlockKey) != 32 {
		return nil, errors.New("unlock key must contain exactly 32 bytes")
	}
	return enclave.New(hex.EncodeToString(unlockKey)), nil
}

func readRecord(path string) (_ []byte, err error) {
	defer err2.Handle(&err)

	info := try.To1(os.Lstat(path))
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New(
			"identity record must be a private regular file",
		)
	}
	file := try.To1(os.OpenFile(path,
		os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0))
	closed := false
	defer func() {
		if !closed {
			try.Out(file.Close()).Logf()
		}
	}()

	opened := try.To1(file.Stat())
	if !os.SameFile(info, opened) || opened.Mode().Perm()&0077 != 0 {
		return nil, errors.New("identity record changed while opening")
	}
	data := try.To1(io.ReadAll(io.LimitReader(file, maxRecordBytes+1)))
	closed = true
	try.To(file.Close())
	if len(data) > maxRecordBytes {
		return nil, errors.New("identity record exceeds size limit")
	}
	return data, nil
}

func decodeRecord(data []byte) (_ record, err error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var stored record
	if decoder.Decode(&stored) != nil {
		// Decoder errors may quote private input, including unknown field names.
		return record{}, errors.New("invalid identity record JSON")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return record{}, errors.New("trailing identity record data")
	}
	if stored.Version != 1 {
		return record{}, errors.New("unsupported identity record version")
	}
	if len(stored.PublicKey) == 0 || len(stored.WrappedHandle) == 0 {
		return record{}, errors.New("missing identity record fields")
	}
	return stored, nil
}

func preflight(backend *enclave.Enclave, wrapped []byte) (err error) {
	defer err2.Handle(&err)

	// The pinned AES-GCM backend slices a 12-byte nonce before checking input.
	// Include its 16-byte authentication tag in this minimum length check.
	if len(wrapped) < 12+16 {
		return errors.New("short wrapped identity handle")
	}
	plain := backend.TryDecrypt(wrapped)
	defer clear(plain)
	private := try.To1(x509.ParseECPrivateKey(plain))
	if private.Curve != elliptic.P256() {
		return errors.New("identity handle requires P-256")
	}
	if private.D.Sign() <= 0 || private.D.Cmp(private.Params().N) >= 0 {
		return errors.New("invalid P-256 identity key")
	}
	// ParseECPrivateKey derives the public point from the private scalar.
	// Only validated material reaches IsKeyHandle's unsafe parse-error path.
	// Clearing plain does not erase all backend or Go-heap copies.
	return nil
}
