package cmds

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/spf13/cobra"
)

var newKeyDoc = `Create a new key for enlave use.

Returns a hex/base58 code 32 byte random secret to be used e.g. stateless key
storage.`

var newKeyCmd = &cobra.Command{
	Use:   "new-key",
	Short: "Create a new key to be used for a secure enclave",
	Long:  newKeyDoc,
	RunE: func(*cobra.Command, []string) (err error) {
		defer err2.Handle(&err)

		key := make([]byte, 32)
		try.To1(rand.Read(key))
		if wantBase58 {
			fmt.Println(base58.Encode(key))
			return nil
		}
		fmt.Println(hex.EncodeToString(key))

		return nil
	},
}

var wantBase58 bool

func init() {
	defer err2.Catch()

	flags := newKeyCmd.PersistentFlags()
	flags.BoolVarP(&wantBase58, "base58", "b", false,
		"wants key output format to be base58 (default is hex)")

	rootCmd.AddCommand(newKeyCmd)
}
