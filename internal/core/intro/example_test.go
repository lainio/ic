package intro_test

import (
	"fmt"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/key"
)

// ExamplePath_Introduce demonstrates signature verification with an explicitly
// constructed test root. It does not select a trusted root, establish full path
// acceptance, or change evidence to Known.
func ExamplePath_Introduce() {
	defer err2.Catch(err2.Stdout)

	root, alice, bob := key.New(), key.New(), key.New()
	rootPublic := try.T1(root.CBORPublicKey())("reading root public key")
	alicePublic := try.T1(alice.CBORPublicKey())("reading Alice public key")

	rootPath := intro.New(key.InfoFromHandle(root))
	alicePath := rootPath.Introduce(
		root, key.InfoFromHandle(alice), intro.WithPosition(1),
	)
	bobPath := alicePath.Introduce(
		alice, key.InfoFromHandle(bob), intro.WithPosition(2),
	)

	encoded := bobPath.Bytes()
	decoded := intro.NewPathFromData(encoded)
	aliceVerified := decoded[1].VerifySignature(rootPublic)
	bobVerified := decoded[2].VerifySignature(alicePublic)

	modified := intro.NewPathFromData(decoded.Bytes())
	modified[2].Body.Options.Position++
	modifiedAccepted := modified[2].VerifySignature(alicePublic)

	fmt.Println("path entries:", len(decoded))
	fmt.Println("signatures verified:", aliceVerified && bobVerified)
	fmt.Println("modified edge accepted:", modifiedAccepted)
	// Output:
	// path entries: 3
	// signatures verified: true
	// modified edge accepted: false
}
