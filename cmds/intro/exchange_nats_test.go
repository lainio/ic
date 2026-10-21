package intro

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	coreintro "github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/nats-io/nats.go"
)

var introDemoNATSURL = flag.String("intro-demo-nats-url", "",
	"Opt in to exchange-demo integration against an existing loopback broker")

func TestExchangeDemoNATS(t *testing.T) {
	if *introDemoNATSURL == "" {
		t.Skip(
			"live broker test requires -intro-demo-nats-url; no connection attempted",
		)
	}
	defer assert.PushTester(t)()

	endpoint := try.To1(exchangeEndpoint(*introDemoNATSURL))
	for _, scenario := range []string{"accepted", "wrong root", "invalid acceptance"} {
		t.Run(scenario, func(t *testing.T) {
			testExchangeNATSPair(t, endpoint, scenario)
		})
	}
}

type exchangeRootResult struct {
	proposal coreintro.Path
	err      error
}

// The channel is a test observation of actual readiness output, which the
// production runner writes only after both subscriptions have flushed.
type exchangeReadyOutput struct {
	bytes.Buffer
	ready chan struct{}
}

func (out *exchangeReadyOutput) Write(data []byte) (int, error) {
	n, err := out.Buffer.Write(data)
	if bytes.Contains(data, []byte("ready for Alice\n")) {
		close(out.ready)
	}
	return n, err
}

func testExchangeNATSPair(t *testing.T, endpoint, scenario string) {
	t.Helper()
	defer assert.PushTester(t)()

	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	// Generate all fixture handles before starting any worker.
	root, alice, other := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	selectedRoot := expectedRoot
	if scenario == "wrong root" {
		selectedRoot = try.To1(other.CBORPublicKey())
	}
	signer := &exchangeObservedHandle{Handle: alice}
	var token [12]byte
	try.To1(rand.Read(token[:]))
	session := "test_" + hex.EncodeToString(token[:])
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	rootConn := try.To1(connectExchange(ctx, endpoint))
	defer rootConn.Close()
	aliceConn := try.To1(connectExchange(ctx, endpoint))
	defer aliceConn.Close()
	assert.That(rootConn != aliceConn)
	rootOut := &exchangeReadyOutput{ready: make(chan struct{})}
	finished := make(chan exchangeRootResult, 1)
	go func() {
		proposal, err := runExchangeRoot(ctx, rootConn, root, session, rootOut)
		finished <- exchangeRootResult{proposal, err}
		close(finished)
	}()
	// Also join on assertion failure: no worker outlives fixture cleanup.
	defer func() {
		cancel()
		rootConn.Close()
		<-finished
	}()
	select {
	case <-rootOut.ready:
	case result := <-finished:
		t.Fatalf("root stopped before readiness: %v", result.err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	var aliceOut bytes.Buffer
	var signature key.Signature
	var aliceErr error
	if scenario == "invalid acceptance" {
		aliceErr = requestInvalidExchangeAcceptance(
			ctx,
			aliceConn,
			alice,
			session,
		)
	} else {
		signature, aliceErr = runExchangeAlice(
			ctx, aliceConn, signer, selectedRoot, session, &aliceOut,
		)
	}
	if scenario == "wrong root" {
		assert.ErrorIs(aliceErr, coreintro.ErrWrongRoot)
		assert.Equal(signer.signCalls, 0)
		cancel() // Alice refused locally; Root has no acceptance to receive.
	}
	var result exchangeRootResult
	select {
	case result = <-finished:
	case <-time.After(6 * time.Second):
		t.Fatal("root failed to finish within its deadline")
	}
	switch scenario {
	case "accepted":
		assert.NoError(aliceErr)
		assert.NoError(result.err)
		assert.NoError(result.proposal.VerifyAcceptance(signature))
		assert.NoError(result.proposal.ProveFromRoot(expectedRoot))
		assert.Equal(signer.signCalls, 1)
		assert.Equal(rootOut.String(),
			"root public key (hex): "+hex.EncodeToString(expectedRoot)+"\n"+
				"ready for Alice\nproposal sent: R -> Alice\n"+
				"Alice's acceptance verifies: true\n")
		assert.Equal(
			aliceOut.String(),
			"proposal received: R -> Alice\nchoice and acceptance saved: true\n"+
				"local acceptance verifies: true\n"+
				"issuer reported acceptance verified: true\n",
		)
	case "wrong root":
		assert.ErrorIs(result.err, context.Canceled)
	case "invalid acceptance":
		assert.Error(aliceErr)
		assert.That(
			strings.Contains(aliceErr.Error(), "peer rejected exchange"),
		)
		assert.ErrorIs(result.err, coreintro.ErrBadAcceptance)
	}
	assert.SEmpty(try.To1(os.ReadDir(parent)))
	aliceConn.Close()
	rootConn.Close()
	assert.That(aliceConn.IsClosed())
	assert.That(rootConn.IsClosed())
}

// Use the same request path to observe an application error header over NATS.
func requestInvalidExchangeAcceptance(
	ctx context.Context, nc *nats.Conn, alice key.Handle, session string,
) (err error) {
	defer err2.Handle(&err)

	info := try.To1(exchangePublicInfo(alice))
	offerSubject, acceptanceSubject := exchangeSubjects(session)
	data := try.To1(
		requestExchange(ctx, nc, offerSubject, wire.TryMarshal(info)),
	)
	proposal := try.To1(coreintro.ParsePath(data))
	// A real signature on a different message must not verify as acceptance.
	invalid := try.To1(alice.Sign([]byte("not the issued proposal")))
	if proposal.VerifyAcceptance(invalid) == nil {
		return errors.New("invalid acceptance unexpectedly verified locally")
	}
	reply := try.To1(nc.RequestWithContext(ctx, acceptanceSubject, invalid))
	if len(reply.Data) != 0 || reply.Header.Get(exchangeErrorHeader) == "" {
		return errors.New("rejection must have only a diagnostic header")
	}
	return checkExchangeMessage(reply)
}
