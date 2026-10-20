package intro_test

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
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

// ExamplePath_canonicalEncoding separates wire representation from path proof.
// Canonical here means the bytes reproduced by the current typed encoder.
func ExamplePath_canonicalEncoding() {
	defer err2.Catch(err2.Stdout)

	root, alice := key.New(), key.New()
	expectedRoot := try.T1(root.CBORPublicKey())(
		"reading the independently selected root public key",
	)
	path := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	assert.SLen(path, 2)
	encoded := path.Bytes()
	assert.SLonger(encoded, 0)
	assert.Equal(encoded[0], byte(0x82))

	// Both 0x82 and 0x98, 0x02 describe two entries; the latter is longer.
	// No signed content or model state changes: no Received/Known transition.
	alternate := append([]byte{0x98, 0x02}, encoded[1:]...)
	var decoded, decodedAlternate intro.Path
	try.To(wire.Unmarshal(&decoded, encoded))
	try.To(wire.Unmarshal(&decodedAlternate, alternate))

	samePath := bytes.Equal(decoded.Bytes(), decodedAlternate.Bytes())
	proofErr := decodedAlternate.ProveFromRoot(expectedRoot)
	canonicalErr := wire.UnmarshalCanonical(new(intro.Path), alternate)
	rejected := errors.Is(canonicalErr, wire.ErrNonCanonicalCBOR)

	fmt.Println("same path after decoding:", samePath)
	fmt.Println("path proof still passes:", proofErr == nil)
	fmt.Println("noncanonical encoding rejected:", rejected)
	// Output:
	// same path after decoding: true
	// path proof still passes: true
	// noncanonical encoding rejected: true
}

// ExampleParsePath shows strict decoding; parsing does not establish valid
// evidence. Proof remains a separate operation.
func ExampleParsePath() {
	defer err2.Catch(err2.Stdout)

	root, alice := key.New(), key.New()
	path := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	encoded := path.Bytes()
	assert.SLonger(encoded, 0)
	assert.Equal(encoded[0], byte(0x82))
	alternate := append([]byte{0x98, 0x02}, encoded[1:]...)

	decoded := try.To1(intro.ParsePath(encoded))
	rejected, err := intro.ParsePath(alternate)

	fmt.Println("canonical input parsed:", len(decoded) == 2)
	fmt.Println("noncanonical input rejected:",
		errors.Is(err, wire.ErrNonCanonicalCBOR))
	fmt.Println("rejected parse returns no path:", rejected == nil)
	// Output:
	// canonical input parsed: true
	// noncanonical input rejected: true
	// rejected parse returns no path: true
}

// ExampleInbox_ReceivePath stores claims on receipt, then separately proves
// returned copies. Neither operation promotes evidence to Known.
func ExampleInbox_ReceivePath() {
	defer err2.Catch(err2.Stdout)

	root, alice := key.New(), key.New()
	expectedRoot := try.T1(root.CBORPublicKey())(
		"reading the independently selected fixture root public key",
	)
	genuine := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	forged := try.To1(intro.ParsePath(genuine.Bytes()))
	forged[1].Body.Options.Position++

	var inbox intro.Inbox
	try.To(inbox.ReceivePath(forged.Bytes()))
	try.To(inbox.ReceivePath(genuine.Bytes()))
	received := inbox.Paths()

	forgedErr := received[0].ProveFromRoot(expectedRoot)
	genuineErr := received[1].ProveFromRoot(expectedRoot)

	fmt.Println("received paths:", len(received))
	fmt.Println("forged path rejected by proof:",
		errors.Is(forgedErr, intro.ErrBadSignature))
	fmt.Println("genuine path passes proof:", genuineErr == nil)
	// Output:
	// received paths: 2
	// forged path rejected by proof: true
	// genuine path passes proof: true
}

// ExampleInbox_conflictingParents shows that individual proofs do not resolve
// contradictory parent claims. It neither selects a winner nor updates Known.
func ExampleInbox_conflictingParents() {
	defer err2.Catch(err2.Stdout)

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := try.T1(root.CBORPublicKey())(
		"reading the independently selected fixture root public key",
	)
	aliceInfo := key.InfoFromHandle(alice)

	rootPath := intro.New(key.InfoFromHandle(root))
	direct := rootPath.Introduce(root, aliceInfo)
	bobPath := rootPath.Introduce(root, key.InfoFromHandle(bob))
	indirect := bobPath.Introduce(bob, aliceInfo)

	var inbox intro.Inbox
	try.To(inbox.ReceivePath(direct.Bytes()))
	try.To(inbox.ReceivePath(indirect.Bytes()))
	received := inbox.Paths()

	assert.SLen(received, 2)
	first, second := received[0], received[1]
	assert.SLen(first, 2)
	assert.SLen(second, 3)
	firstErr := first.ProveFromRoot(expectedRoot)
	secondErr := second.ProveFromRoot(expectedRoot)
	firstChild := first.LastEdge().Public()
	secondChild := second.LastEdge().Public()
	firstParent := first.SecondLastEdge().Public()
	secondParent := second.SecondLastEdge().Public()
	sameChild := bytes.Equal(firstChild, secondChild)
	differentParents := !bytes.Equal(firstParent, secondParent)

	fmt.Println("received paths:", len(received))
	fmt.Println("both path proofs pass:", firstErr == nil && secondErr == nil)
	fmt.Println("same child:", sameChild)
	fmt.Println("different parents:", differentParents)
	// Output:
	// received paths: 2
	// both path proofs pass: true
	// same child: true
	// different parents: true
}

// ExamplePath_parentAcceptance is a detached acceptance experiment, not
// one-time enrollment, a human-consent ceremony, or promotion into Known.
func ExamplePath_parentAcceptance() {
	defer err2.Catch(err2.Stdout)

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := try.T1(root.CBORPublicKey())(
		"reading the independently selected fixture root public key",
	)
	aliceInfo := key.InfoFromHandle(alice)

	rootPath := intro.New(key.InfoFromHandle(root))
	direct := rootPath.Introduce(root, aliceInfo)
	bobPath := rootPath.Introduce(root, key.InfoFromHandle(bob))
	indirect := bobPath.Introduce(bob, aliceInfo)
	directBytes, indirectBytes := direct.Bytes(), indirect.Bytes()
	direct = try.To1(intro.ParsePath(directBytes))
	indirect = try.To1(intro.ParsePath(indirectBytes))
	assert.SLen(direct, 2)
	assert.SLen(indirect, 3)
	directErr := direct.ProveFromRoot(expectedRoot)
	indirectErr := indirect.ProveFromRoot(expectedRoot)
	assert.NoError(directErr)
	assert.NoError(indirectErr)

	// Choose the direct proposal and its parent explicitly in this fixture.
	offered := direct
	assert.DeepEqual(offered.LastEdge().Body.Child, aliceInfo)
	assert.That(offered.SecondLastEdge().Public().Equal(expectedRoot))

	// Experimental transcript; not a production protocol identifier.
	digest := key.HashTagged("test/intro-acceptance/v1", offered.Bytes())
	acceptance := key.Signature(try.To1(alice.Sign(digest[:])))

	directDigest := key.HashTagged("test/intro-acceptance/v1", direct.Bytes())
	directVerified := acceptance.Verify(
		direct.LastEdge().Public(), directDigest[:],
	)
	indirectDigest := key.HashTagged(
		"test/intro-acceptance/v1",
		indirect.Bytes(),
	)
	indirectVerified := acceptance.Verify(
		indirect.LastEdge().Public(), indirectDigest[:],
	)
	assert.DeepEqual(direct.Bytes(), directBytes)
	assert.DeepEqual(indirect.Bytes(), indirectBytes)

	fmt.Println("both proposal proofs pass:",
		directErr == nil && indirectErr == nil)
	fmt.Println("Alice's acceptance matches R -> Alice:", directVerified)
	fmt.Println("same acceptance matches R -> Bob -> Alice:", indirectVerified)
	// Output:
	// both proposal proofs pass: true
	// Alice's acceptance matches R -> Alice: true
	// same acceptance matches R -> Bob -> Alice: false
}

// ExamplePath_SignAcceptance keeps proof and parent choice with the caller.
// The detached signature does not enroll Alice or change Known.
func ExamplePath_SignAcceptance() {
	defer err2.Catch(err2.Stdout)

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	aliceInfo := key.InfoFromHandle(alice)

	rootPath := intro.New(key.InfoFromHandle(root))
	direct := rootPath.Introduce(root, aliceInfo)
	bobPath := rootPath.Introduce(root, key.InfoFromHandle(bob))
	indirect := bobPath.Introduce(bob, aliceInfo)
	try.To(direct.ProveFromRoot(expectedRoot))
	try.To(indirect.ProveFromRoot(expectedRoot))

	// Select the direct proposal and its proposed parent before signing.
	offered := direct
	expectedParent := expectedRoot
	assert.That(offered.LastEdge().Public().Equal(aliceInfo.Public))
	assert.That(offered.SecondLastEdge().Public().Equal(expectedParent))

	acceptance := try.To1(offered.SignAcceptance(alice))
	directErr := direct.VerifyAcceptance(acceptance)
	indirectErr := indirect.VerifyAcceptance(acceptance)
	try.To(directErr)
	assert.ErrorIs(indirectErr, intro.ErrBadAcceptance)

	fmt.Println("Alice's acceptance verifies:", directErr == nil)
	fmt.Println("acceptance transfers to other parent:", indirectErr == nil)
	// Output:
	// Alice's acceptance verifies: true
	// acceptance transfers to other parent: false
}
