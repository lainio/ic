// Package node provides saved local identity, state, and owner status commands.
package node

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

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
		Short: "Initialize, inspect, and run one saved local node",
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
	parent.AddCommand(newInitStateCommand())
	parent.AddCommand(newServeCommand())
	return parent
}

func runInit(cmd *cobra.Command, args []string) (err error) {
	defer err2.Handle(&err)

	try.To(cmd.ValidateArgs(args))
	dir, unlockPath := try.To2(commandPaths(cmd))
	dir, unlockPath = try.To2(nodeidentity.ResolvePaths(dir, unlockPath))
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
	handle := try.To1(nodeidentity.OpenDirectory(dir, unlockPath))
	try.To(printPublic(cmd, handle))
	return nil
}

func commandPaths(cmd *cobra.Command) (dir, unlock string, err error) {
	defer err2.Handle(&err)

	dir = try.To1(cmd.Flags().GetString("dir"))
	unlock = try.To1(cmd.Flags().GetString("unlock-file"))
	return dir, unlock, nil
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

func printPublic(cmd *cobra.Command, handle key.Handle) (err error) {
	defer err2.Handle(&err)

	public := try.To1(handle.CBORPublicKey())
	try.To1(
		fmt.Fprintf(cmd.OutOrStdout(), "node public key (hex): %x\n", public),
	)
	return nil
}
