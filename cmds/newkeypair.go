package cmds

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
	"github.com/spf13/cobra"
)

var newKeyPairDoc = `Create a new key pair to use its public key only.

The public key can be used ,e.g., as a Anchor key wher we aren't needing private
key currently.`

var newKeyPairCmd = &cobra.Command{
	Use:   "new-public-key",
	Short: "Create a new key pair and print public key",
	Long:  newKeyPairDoc,
	RunE: func(*cobra.Command, []string) (err error) {
		defer err2.Handle(&err)

		key := key.NewHand()
		kpb := try.To1(key.CBORPublicKey())
		if wantBase58 {
			fmt.Println(base58.Encode(kpb))
			return nil
		}
		fmt.Println(hex.EncodeToString(kpb))

		return nil
	},
}

func init() {
	defer err2.Catch()

	flags := newKeyPairCmd.PersistentFlags()
	flags.BoolVarP(&wantBase58, "base58", "b", false,
		"wants key output format to be base58 (default is hex)")

	rootCmd.AddCommand(newKeyPairCmd)
}
