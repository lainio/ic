package nodeidentity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/findy-network/findy-agent-auth/acator/enclave"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/key"
)

func TestCreateReopenAcceptance(t *testing.T) {
	defer assert.PushTester(t)()

	path := filepath.Join(t.TempDir(), "identity.json")
	unlock := make([]byte, 32)
	try.To1(rand.Read(unlock))
	defer clear(unlock)

	var public []byte
	{
		original := try.To1(Create(path, unlock))
		public = try.To1(original.CBORPublicKey())
	}
	before := try.To1(os.ReadFile(path))
	statBefore := try.To1(os.Stat(path))
	assert.Equal(statBefore.Mode().Perm(), os.FileMode(0600))

	reopened := try.To1(Open(path, unlock))
	assert.DeepEqual(try.To1(reopened.CBORPublicKey()), public)
	assert.That(bytes.Equal(try.To1(os.ReadFile(path)), before))
	assert.Equal(try.To1(os.Stat(path)).ModTime(), statBefore.ModTime())

	parentUnlock := make([]byte, 32)
	try.To1(rand.Read(parentUnlock))
	defer clear(parentUnlock)
	parent := try.To1(
		enclave.New(hex.EncodeToString(parentUnlock)).NewKeyHandle(),
	)
	parentPublic := key.Public(try.To1(parent.CBORPublicKey()))
	proposal := intro.New(key.Info{Public: parentPublic}).Introduce(
		parent, key.Info{Public: public},
	)
	acceptance := try.To1(proposal.SignAcceptanceFor(
		reopened, parentPublic, parentPublic,
	))
	assert.NoError(proposal.VerifyAcceptance(acceptance))
}

func TestRejectedRecords(t *testing.T) {
	defer assert.PushTester(t)()

	unlock := make([]byte, 32)
	try.To1(rand.Read(unlock))
	defer clear(unlock)
	path := filepath.Join(t.TempDir(), "identity.json")
	try.To1(Create(path, unlock))
	original := try.To1(os.ReadFile(path))
	var valid record
	try.To(json.Unmarshal(original, &valid))
	backend := enclave.New(hex.EncodeToString(unlock))
	otherCurve := try.To1(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
	otherDER := try.To1(x509.MarshalECPrivateKey(otherCurve))
	defer clear(otherDER)
	zeroScalar := try.To1(asn1.Marshal(struct {
		Version       int
		PrivateKey    []byte
		NamedCurveOID asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	}{1, make([]byte, 32), asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}}))

	for _, tc := range []struct {
		name   string
		change func(*record)
		data   []byte
	}{
		{name: "empty", data: []byte{}},
		{name: "malformed", data: []byte("not JSON")},
		{name: "truncated", data: original[:len(original)/2]},
		{name: "trailing JSON", data: append(bytes.Clone(original), '{', '}')},
		{name: "oversized", data: []byte(strings.Repeat(" ", maxRecordBytes+1))},
		{name: "unknown field", data: []byte(`{"private-input": "secret"}`)},
		{name: "unknown version", change: func(r *record) { r.Version = 2 }},
		{name: "missing version", change: func(r *record) { r.Version = 0 }},
		{name: "missing public", change: func(r *record) { r.PublicKey = nil }},
		{name: "missing handle", change: func(r *record) { r.WrappedHandle = nil }},
		{name: "public mismatch", change: func(r *record) { r.PublicKey[0] ^= 1 }},
		{name: "short nonce", change: func(r *record) {
			r.WrappedHandle = r.WrappedHandle[:11]
		}},
		{name: "nonce only", change: func(r *record) {
			r.WrappedHandle = r.WrappedHandle[:12]
		}},
		{name: "short tag", change: func(r *record) {
			r.WrappedHandle = r.WrappedHandle[:27]
		}},
		{name: "tampered", change: func(r *record) { r.WrappedHandle[20] ^= 1 }},
		{name: "authenticated invalid key", change: func(r *record) {
			r.WrappedHandle = backend.Cipher.TryEncrypt([]byte("not an EC key"))
		}},
		{name: "authenticated wrong curve", change: func(r *record) {
			r.WrappedHandle = backend.Cipher.TryEncrypt(otherDER)
		}},
		{name: "authenticated zero scalar", change: func(r *record) {
			r.WrappedHandle = backend.TryEncrypt(zeroScalar)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			data := tc.data
			if tc.change != nil {
				candidate := record{
					valid.Version,
					bytes.Clone(valid.PublicKey),
					bytes.Clone(valid.WrappedHandle),
				}
				tc.change(&candidate)
				data = try.To1(json.Marshal(candidate))
			}
			try.To(os.WriteFile(path, data, 0600))

			handle, err := Open(path, unlock)
			assert.Error(err)
			assert.INil(handle)
			assert.That(bytes.Equal(try.To1(os.ReadFile(path)), data))
			assert.That(!strings.Contains(err.Error(), "private-input"))
		})
	}
}

func TestUnlockAndCreationFailures(t *testing.T) {
	defer assert.PushTester(t)()

	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	unlock := make([]byte, 32)
	try.To1(rand.Read(unlock))
	defer clear(unlock)
	try.To1(Create(path, unlock))
	before := try.To1(os.ReadFile(path))
	wrong := bytes.Clone(unlock)
	wrong[0] ^= 1
	defer clear(wrong)

	for _, candidate := range [][]byte{nil, make([]byte, 31), make([]byte, 33), wrong} {
		handle, err := Open(path, candidate)
		assert.Error(err)
		assert.INil(handle)
		assert.That(bytes.Equal(try.To1(os.ReadFile(path)), before))
	}
	for _, size := range []int{0, 31, 33} {
		newPath := filepath.Join(dir, "must-not-exist")
		handle, err := Create(newPath, make([]byte, size))
		assert.Error(err)
		assert.INil(handle)
		_, err = os.Lstat(newPath)
		assert.ErrorIs(err, os.ErrNotExist)
	}

	handle, err := Create(path, unlock)
	assert.ErrorIs(err, os.ErrExist)
	assert.INil(handle)
	assert.That(bytes.Equal(try.To1(os.ReadFile(path)), before))
	missing := filepath.Join(dir, "missing", "identity.json")
	handle, err = Create(missing, unlock)
	assert.ErrorIs(err, os.ErrNotExist)
	assert.INil(handle)
	handle, err = Open(missing, unlock)
	assert.ErrorIs(err, os.ErrNotExist)
	assert.INil(handle)
}

func TestPrivateRegularRecordRequired(t *testing.T) {
	defer assert.PushTester(t)()

	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	unlock := make([]byte, 32)
	try.To1(rand.Read(unlock))
	defer clear(unlock)
	try.To1(Create(path, unlock))
	before := try.To1(os.ReadFile(path))
	link := filepath.Join(dir, "link")
	try.To(os.Symlink(path, link))
	fifo := filepath.Join(dir, "fifo")
	try.To(syscall.Mkfifo(fifo, 0600))
	try.To(os.Chmod(path, 0640))

	for _, candidate := range []string{dir, link, fifo, path} {
		handle, err := Open(candidate, unlock)
		assert.Error(err)
		assert.INil(handle)
	}
	handle, err := Create(link, unlock)
	assert.ErrorIs(err, os.ErrExist)
	assert.INil(handle)
	assert.That(bytes.Equal(try.To1(os.ReadFile(path)), before))
	assert.Equal(try.To1(os.Stat(path)).Mode().Perm(), os.FileMode(0640))

	try.To(os.Chmod(path, 0400))
	assert.INotNil(try.To1(Open(path, unlock)))
}

func TestIdentityAcrossProcesses(t *testing.T) {
	defer assert.PushTester(t)()

	dir := t.TempDir()
	unlock := make([]byte, 32)
	try.To1(rand.Read(unlock))
	try.To(os.WriteFile(filepath.Join(dir, "unlock"), unlock, 0600))
	clear(unlock)
	executable := try.To1(os.Executable())
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	var before []byte

	for _, name := range []string{"TestProcessCreate", "TestProcessOpen"} {
		child := exec.CommandContext(ctx, executable, "-test.run=^"+name+"$",
			"--", dir)
		output, err := child.CombinedOutput()
		assert.NoError(err, "child %s: %s", name, output)
		recordBytes := try.To1(
			os.ReadFile(filepath.Join(dir, "identity.json")),
		)
		if before == nil {
			before = recordBytes
		} else {
			assert.That(bytes.Equal(recordBytes, before))
		}
	}
	created := try.To1(os.ReadFile(filepath.Join(dir, "created-public")))
	reopened := try.To1(os.ReadFile(filepath.Join(dir, "reopened-public")))
	assert.SNotEmpty(created)
	assert.DeepEqual(reopened, created)
}

func TestProcessCreate(t *testing.T) {
	defer assert.PushTester(t)()

	if len(flag.Args()) != 1 {
		t.Skip("invoked only by the bounded subprocess test")
	}
	dir := flag.Args()[0]
	unlock := try.To1(os.ReadFile(filepath.Join(dir, "unlock")))
	defer clear(unlock)
	handle := try.To1(Create(filepath.Join(dir, "identity.json"), unlock))
	public := try.To1(handle.CBORPublicKey())
	try.To(os.WriteFile(filepath.Join(dir, "created-public"), public, 0600))
}

func TestProcessOpen(t *testing.T) {
	defer assert.PushTester(t)()

	if len(flag.Args()) != 1 {
		t.Skip("invoked only by the bounded subprocess test")
	}
	dir := flag.Args()[0]
	unlock := try.To1(os.ReadFile(filepath.Join(dir, "unlock")))
	defer clear(unlock)
	handle := try.To1(Open(filepath.Join(dir, "identity.json"), unlock))
	public := try.To1(handle.CBORPublicKey())
	message := []byte("signing after process exit")
	signature := key.Signature(try.To1(handle.Sign(message)))
	assert.That(signature.Verify(public, message))
	try.To(os.WriteFile(filepath.Join(dir, "reopened-public"), public, 0600))
}
