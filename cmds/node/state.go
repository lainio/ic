package node

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/spf13/cobra"
)

func newInitStateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "init-state", Short: "Prepare local state for an existing identity",
		Args: cobra.NoArgs, RunE: runInitState,
	}
	cmd.Flags().String("dir", "", "Existing private node directory")
	cmd.Flags().
		String("unlock-file", "", "Existing separate identity unlock file")
	cmd.Flags().
		String("storage-key-file", "", "New separate private storage key file")
	cmd.Flags().
		String("root", "", "Expected Root public-key bytes in hex (not proof of authority)")
	for _, name := range []string{"dir", "unlock-file", "storage-key-file", "root"} {
		try.To(cmd.MarkFlagRequired(name))
	}
	return cmd
}

func runInitState(cmd *cobra.Command, args []string) (err error) {
	defer err2.Handle(&err)

	try.To(cmd.ValidateArgs(args))
	try.To(cmd.ValidateRequiredFlags())
	for _, name := range []string{"dir", "unlock-file", "storage-key-file", "root"} {
		if strings.TrimSpace(try.To1(cmd.Flags().GetString(name))) == "" {
			return fmt.Errorf("--%s must be nonempty", name)
		}
	}
	rootHex := try.To1(cmd.Flags().GetString("root"))
	if len(rootHex) > 2*16*1024 {
		return errors.New("--root exceeds 16 KiB of public-key bytes")
	}
	root, decodeErr := hex.DecodeString(rootHex)
	if decodeErr != nil || len(root) == 0 {
		return errors.New("--root requires nonempty hex public-key bytes")
	}
	dir, unlock := try.To2(commandPaths(cmd))
	dir, unlock = try.To2(nodeidentity.ResolvePaths(dir, unlock))
	keyFile := try.To1(cmd.Flags().GetString("storage-key-file"))
	_, keyFile = try.To2(nodeidentity.ResolvePaths(dir, keyFile))
	if keyFile == unlock {
		return errors.New(
			"storage key file must differ from identity unlock file",
		)
	}
	try.To(cmd.Context().Err())

	handle := try.To1(nodeidentity.OpenDirectory(dir, unlock))
	child := try.To1(handle.CBORPublicKey())
	store := try.To1(
		nodevault.CreateForNode(cmd.Context(), dir, keyFile, root, child),
	)
	defer func() { try.Out(store.Close()).Logf() }()
	try.To(store.Close())

	try.To(printPublic(cmd, handle))
	try.To1(fmt.Fprintln(cmd.OutOrStdout(), "local state initialized: true"))
	return nil
}
