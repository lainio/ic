// Package node provides local signing-identity initialization and inspection.
package node

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/cmds"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/key"
	"github.com/spf13/cobra"
)

func init() {
	cmds.RootCmd().AddCommand(newNodeCommand())
}

func newNodeCommand() *cobra.Command {
	parent := &cobra.Command{
		Use:   "node",
		Short: "Persist and inspect one local signing identity",
	}
	for _, cmd := range []*cobra.Command{
		{Use: "init", Short: "Create a new private identity", RunE: runInit},
		{Use: "info", Short: "Reopen the saved identity", RunE: runInfo},
	} {
		cmd.Args = cobra.NoArgs
		cmd.Flags().String("dir", "", "Private node directory")
		cmd.Flags().String("unlock-file", "", "Separate private unlock file")
		try.To(cmd.MarkFlagRequired("dir"))
		try.To(cmd.MarkFlagRequired("unlock-file"))
		parent.AddCommand(cmd)
	}
	return parent
}

func runInit(cmd *cobra.Command, args []string) (err error) {
	defer err2.Handle(&err)

	try.To(cmd.ValidateArgs(args))
	dir, unlockPath := try.To2(commandPaths(cmd))
	try.To(requireAbsent(dir))
	try.To(requireAbsent(unlockPath))

	try.To(os.Mkdir(dir, 0700))
	unlock := make([]byte, 32)
	defer clear(unlock)
	try.To1(rand.Read(unlock))
	try.To(writeUnlock(unlockPath, unlock))
	handle := try.To1(nodeidentity.Create(
		filepath.Join(dir, "identity.json"), unlock,
	))
	try.To(printPublic(cmd, handle))
	return nil
}

func runInfo(cmd *cobra.Command, args []string) (err error) {
	defer err2.Handle(&err)

	try.To(cmd.ValidateArgs(args))
	dir, unlockPath := try.To2(commandPaths(cmd))
	info := try.To1(os.Lstat(dir))
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("node directory must be a private directory")
	}
	unlock := try.To1(readUnlock(unlockPath))
	defer clear(unlock)
	handle := try.To1(nodeidentity.Open(
		filepath.Join(dir, "identity.json"), unlock,
	))
	try.To(printPublic(cmd, handle))
	return nil
}

func commandPaths(cmd *cobra.Command) (dir, unlock string, err error) {
	defer err2.Handle(&err)

	dir = try.To1(cmd.Flags().GetString("dir"))
	unlock = try.To1(cmd.Flags().GetString("unlock-file"))
	if strings.TrimSpace(dir) == "" || strings.TrimSpace(unlock) == "" {
		return "", "", errors.New("--dir and --unlock-file must be nonempty")
	}
	dir = try.To1(filepath.Abs(dir))
	unlock = try.To1(filepath.Abs(unlock))
	try.To(requireSeparate(dir, unlock))

	// Resolve existing parents to detect aliases, while retaining the final
	// components for exclusive creation or Lstat symlink rejection.
	dir = try.To1(resolveParent(dir))
	unlock = try.To1(resolveParent(unlock))
	try.To(requireSeparate(dir, unlock))
	return dir, unlock, nil
}

func resolveParent(path string) (_ string, err error) {
	defer err2.Handle(&err)

	parent := try.To1(filepath.EvalSymlinks(filepath.Dir(path)))
	if !try.To1(os.Stat(parent)).IsDir() {
		return "", errors.New("path parent must be an existing directory")
	}
	return filepath.Join(parent, filepath.Base(path)), nil
}

func requireSeparate(dir, unlock string) (err error) {
	defer err2.Handle(&err)

	rel := try.To1(filepath.Rel(dir, unlock))
	if rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("unlock file must be outside the node directory")
	}
	return nil
}

func requireAbsent(path string) (err error) {
	_, err = os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err == nil {
		return fmt.Errorf("path already exists: %w", os.ErrExist)
	}
	return err
}

func writeUnlock(path string, unlock []byte) (err error) {
	defer err2.Handle(&err)

	file := try.To1(os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600))
	closed := false
	defer func() {
		if !closed {
			try.Out(file.Close()).Logf()
		}
	}()

	n := try.To1(file.Write(unlock))
	if n != len(unlock) {
		return io.ErrShortWrite
	}
	closed = true
	try.To(file.Close())
	return nil
}

func readUnlock(path string) (_ []byte, err error) {
	defer err2.Handle(&err)

	info := try.To1(os.Lstat(path))
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("unlock file must be a private regular file")
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
		return nil, errors.New("unlock file changed while opening")
	}
	unlock := try.To1(io.ReadAll(io.LimitReader(file, 33)))
	closed = true
	closeErr := file.Close()
	if closeErr != nil || len(unlock) != 32 {
		clear(unlock)
		try.To(closeErr)
		return nil, errors.New("unlock file must contain exactly 32 bytes")
	}
	return unlock, nil
}

func printPublic(cmd *cobra.Command, handle key.Handle) (err error) {
	defer err2.Handle(&err)

	public := try.To1(handle.CBORPublicKey())
	try.To1(
		fmt.Fprintf(cmd.OutOrStdout(), "node public key (hex): %x\n", public),
	)
	return nil
}
