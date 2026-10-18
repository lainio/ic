package intro_test

import (
	"errors"
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

// ExamplePath_Prove demonstrates structural checks under an explicitly
// constructed fixture root. It does not select a trusted root, implement
// complete V19 introduction acceptance, or promote evidence to Known.
func ExamplePath_Prove() {
	defer err2.Catch(err2.Stdout)

	root, alice, bob := key.New(), key.New(), key.New()
	alicePublic := try.T1(alice.CBORPublicKey())("reading Alice public key")
	rootPath := intro.New(key.InfoFromHandle(root))

	alicePath := rootPath.Introduce(root, key.InfoFromHandle(alice))
	bobPath := alicePath.Introduce(alice, key.InfoFromHandle(bob))
	modified := intro.NewPathFromData(bobPath.Bytes())
	modified[2].Body.Prev[0] ^= 1
	modified[2].ParentSig = try.T1(alice.Sign(modified[2].ExcludeBytes()))(
		"signing Bob's edge with a wrong predecessor",
	)

	linkedErr := bobPath.Prove()
	wrongLinkSignatureVerified := modified[2].VerifySignature(alicePublic)
	wrongLinkErr := modified.Prove()
	wrongLinkRejected := errors.Is(wrongLinkErr, intro.ErrBrokenPath)

	fmt.Println("linked path passes:", linkedErr == nil)
	fmt.Println("wrong-link signature verifies:", wrongLinkSignatureVerified)
	fmt.Println("wrong-link path rejected:", wrongLinkRejected)
	// Output:
	// linked path passes: true
	// wrong-link signature verifies: true
	// wrong-link path rejected: true
}

// ExamplePath_ProveFromRoot checks a caller-selected fixture root. It does not
// provision a production root, establish all V19 introduction rules, change
// Known, or prove that the presenter controls the leaf's private key.
func ExamplePath_ProveFromRoot() {
	defer err2.Catch(err2.Stdout)

	root, otherRoot, alice := key.New(), key.New(), key.New()
	expectedRoot := try.T1(root.CBORPublicKey())(
		"reading the caller-selected fixture root public key",
	)
	aliceInfo := key.InfoFromHandle(alice)

	path := intro.New(key.InfoFromHandle(root)).Introduce(root, aliceInfo)
	otherPath := intro.New(key.InfoFromHandle(otherRoot)).Introduce(
		otherRoot, aliceInfo,
	)

	expectedErr := path.ProveFromRoot(expectedRoot)
	structuralErr := otherPath.Prove()
	otherErr := otherPath.ProveFromRoot(expectedRoot)
	otherRejected := errors.Is(otherErr, intro.ErrWrongRoot)

	fmt.Println("expected-root path passes:", expectedErr == nil)
	fmt.Println("other-root path passes structural checks:", structuralErr == nil)
	fmt.Println("other-root path rejected:", otherRejected)
	// Output:
	// expected-root path passes: true
	// other-root path passes structural checks: true
	// other-root path rejected: true
}

// ExamplePath_ProveFromRoot_cycle shows that valid signatures and correct root
// selection do not permit introducing the root again.
func ExamplePath_ProveFromRoot_cycle() {
	defer err2.Catch(err2.Stdout)

	root, alice := key.New(), key.New()
	rootInfo, aliceInfo := key.InfoFromHandle(root), key.InfoFromHandle(alice)
	expectedRoot := try.T1(root.CBORPublicKey())(
		"reading the independently selected root public key",
	)
	alicePublic := try.T1(alice.CBORPublicKey())("reading Alice public key")

	alicePath := intro.New(rootInfo).Introduce(root, aliceInfo)
	path := alicePath.Introduce(alice, rootInfo)

	aliceVerified := path[1].VerifySignature(expectedRoot)
	rootVerified := path[2].VerifySignature(alicePublic)
	startsAtExpectedRoot := path.FirstEdge().Public().Equal(expectedRoot)
	returnRejected := errors.Is(
		path.ProveFromRoot(expectedRoot), intro.ErrCycleOrDuplicate,
	)

	fmt.Println("signatures verified:", aliceVerified && rootVerified)
	fmt.Println("starts at expected root:", startsAtExpectedRoot)
	fmt.Println("return to root rejected:", returnRejected)
	// Output:
	// signatures verified: true
	// starts at expected root: true
	// return to root rejected: true
}
