package intro

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/cmds"
	coreintro "github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/nats-io/nats.go"
)

func TestExchangeDemoRegistrationAndFlags(t *testing.T) {
	defer assert.PushTester(t)()

	for _, role := range []string{"root", "accept"} {
		registered, args, err := cmds.RootCmd().Find(
			[]string{"intro", "exchange-demo", role},
		)
		assert.NoError(err)
		assert.SEmpty(args)
		assert.Equal(registered.Name(), role)
		assert.Equal(registered.Parent().Name(), "exchange-demo")
		assert.That(registered.RunE != nil)

		// Callbacks avoid Cobra's process-wide legacy initializers.
		cmd := newExchangeRoleCommand(role)
		assert.Error(cmd.ValidateRequiredFlags())
		assert.NoError(cmd.ValidateArgs(nil))
		assert.Error(cmd.ValidateArgs([]string{"extra"}))
		flags := cmd.Flags()
		assert.Equal(try.To1(flags.GetDuration("timeout")), 2*time.Minute)
		assert.Equal(try.To1(flags.GetString("nats-url")),
			"nats://127.0.0.1:4222")
		assert.NoError(flags.Set("session", "demo1"))
		if role == "accept" {
			assert.Error(cmd.ValidateRequiredFlags())
			assert.NoError(flags.Set("root", "selected-public-key"))
		}
		assert.NoError(cmd.ValidateRequiredFlags())
		var help bytes.Buffer
		cmd.SetOut(&help)
		assert.NoError(cmd.Help())
		for _, flag := range []string{"--session", "--nats-url", "--timeout"} {
			assert.That(strings.Contains(help.String(), flag))
		}
	}
	var help bytes.Buffer
	cmd := newExchangeDemoCommand()
	cmd.SetOut(&help)
	assert.NoError(cmd.Help())
	for _, text := range []string{
		"root", "accept", "stdout", "stderr", "Known", "unsigned",
	} {
		assert.That(strings.Contains(help.String(), text), text)
	}
}

func TestExchangeDemoInvalidCommandInputs(t *testing.T) {
	for _, tc := range []struct {
		name, role string
		flags      []string
	}{
		{"missing session", "root", nil},
		{"wildcard", "root", []string{"--session", "*"}},
		{"separator", "root", []string{"--session", "a.b"}},
		{"unicode", "root", []string{"--session", "ä"}},
		{"too long", "root", []string{"--session", strings.Repeat("a", 65)}},
		{"zero timeout", "root", []string{"--session", "ok", "--timeout", "0s"}},
		{"negative timeout", "root", []string{"--session", "ok", "--timeout", "-1s"}},
		{"public host", "root", []string{"--session", "ok", "--nats-url", "nats://demo.nats.io:4222"}},
		{"missing root", "accept", []string{"--session", "ok"}},
		{"bad root hex", "accept", []string{"--session", "ok", "--root", "xyz"}},
		{"short root", "accept", []string{"--session", "ok", "--root", "a1"}},
		{"not a key", "accept", []string{"--session", "ok", "--root", "a0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			parent := t.TempDir()
			t.Setenv("TMPDIR", parent)
			cmd := newExchangeRoleCommand(tc.role)
			cmd.SetContext(t.Context())
			var output bytes.Buffer
			cmd.SetOut(&output)
			assert.NoError(cmd.ParseFlags(tc.flags))
			// Even direct RunE calls reject before connecting or creating storage.
			assert.Error(cmd.RunE(cmd, nil))
			assert.Empty(output.String())
			assert.SEmpty(try.To1(os.ReadDir(parent)))
		})
	}
}

func TestExchangeDemoEndpointAndRoot(t *testing.T) {
	defer assert.PushTester(t)()

	for _, value := range []string{
		"nats://127.0.0.1:4222", "nats://[::1]:4222", "nats://localhost",
	} {
		assert.NotEmpty(try.To1(exchangeEndpoint(value)))
	}
	for _, value := range []string{
		"nats://0.0.0.0:4222", "nats://192.168.1.1:4222",
		"nats://127.0.0.1:4222,nats://127.0.0.2:4222",
		"nats://user:secret@127.0.0.1:4222", "tls://127.0.0.1:4222",
		"nats://127.0.0.1:4222/path", "nats://127.0.0.1:4222?x=y",
		"nats://127.0.0.1:4222#x", "nats://127.0.0.1:0",
		"nats://127.0.0.1:65536", "nats://127.0.0.1:bad",
	} {
		_, err := exchangeEndpoint(value)
		assert.Error(err, value)
	}
	public := try.To1(key.New().CBORPublicKey())
	decoded := try.To1(parseExchangeRoot(hex.EncodeToString(public)))
	assert.DeepEqual([]byte(decoded), public)
	offer, acceptance := exchangeSubjects("Demo_1-ok")
	assert.Equal(offer, "ic.intro-demo.Demo_1-ok.offer")
	assert.Equal(acceptance, "ic.intro-demo.Demo_1-ok.acceptance")
}

// Test observation only: every successful Sign still uses the real handle.
type exchangeObservedHandle struct {
	key.Handle
	signCalls int
}

func (h *exchangeObservedHandle) Sign(data []byte) ([]byte, error) {
	h.signCalls++
	return h.Handle.Sign(data)
}

func (*exchangeObservedHandle) ID() []byte {
	panic("exchange must not access a serialized private handle")
}

func TestExchangeDemoProposalAndRetainedAcceptance(t *testing.T) {
	defer assert.PushTester(t)()

	root := &exchangeObservedHandle{Handle: key.New()}
	alice := &exchangeObservedHandle{Handle: key.New()}
	child := try.To1(exchangePublicInfo(alice))
	child.ID = []byte("untrusted storage locator")
	request := &nats.Msg{Reply: "_INBOX.offer", Data: wire.TryMarshal(child)}
	issued := try.To1(newExchangeProposal(root, request))
	assert.Equal(root.signCalls, 1)
	assert.SLen(issued, 2)
	assert.DeepEqual(issued.LastEdge().Public(), child.Public)
	assert.SEmpty(issued[0].Body.Child.ID)
	assert.SEmpty(issued[1].Body.Child.ID)
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	assert.NoError(issued.ProveFromRoot(expectedRoot))
	signature := try.To1(
		issued.SignAcceptanceFor(alice, expectedRoot, expectedRoot),
	)
	assert.NoError(verifyExchangeAcceptance(issued,
		&nats.Msg{Reply: "_INBOX.acceptance", Data: signature}))
	assert.ErrorIs(verifyExchangeAcceptance(issued,
		&nats.Msg{Reply: "_INBOX.acceptance"}), coreintro.ErrBadAcceptance)
	assert.ErrorIs(verifyExchangeAcceptance(issued,
		&nats.Msg{Data: signature}), nats.ErrMsgNoReply)

	// Same root/child, different signed proposal: no substitute offer is sent.
	rootInfo := try.To1(exchangePublicInfo(root))
	alternate := coreintro.New(rootInfo).Introduce(root, child,
		coreintro.WithPosition(1))
	transferred := try.To1(
		alternate.SignAcceptanceFor(alice, expectedRoot, expectedRoot),
	)
	assert.ErrorIs(verifyExchangeAcceptance(issued,
		&nats.Msg{Reply: "_INBOX.acceptance", Data: transferred}),
		coreintro.ErrBadAcceptance)
}

func TestExchangeDemoRejectBeforeProposalSigning(t *testing.T) {
	defer assert.PushTester(t)()

	root := &exchangeObservedHandle{Handle: key.New()}
	info := try.To1(exchangePublicInfo(key.New()))
	canonical := wire.TryMarshal(info)
	for _, request := range []*nats.Msg{
		{Data: canonical},
		{Reply: "_INBOX.x", Data: []byte{0xff}},
		{Reply: "_INBOX.x", Data: wire.TryMarshal(key.Info{})},
		{Reply: "_INBOX.x", Data: append([]byte{0xd9, 0xd9, 0xf7}, canonical...)},
		{Reply: "_INBOX.x", Data: make([]byte, exchangePayloadLimit+1)},
		{Reply: "_INBOX.x", Data: canonical,
			Header: nats.Header{exchangeErrorHeader: {"refused"}}},
	} {
		proposal, err := newExchangeProposal(root, request)
		assert.Error(err)
		assert.SNil(proposal)
		assert.Equal(root.signCalls, 0)
	}
}

func TestExchangeDemoStoredChoiceAndCleanup(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, other := key.New(), key.New(), key.New()
	rootInfo := try.To1(exchangePublicInfo(root))
	childInfo := try.To1(exchangePublicInfo(alice))
	direct := coreintro.New(rootInfo).Introduce(root, childInfo)
	wrongRoot := key.Public(try.To1(other.CBORPublicKey()))
	outputErr := errors.New("exchange output failed")
	for _, tc := range []struct {
		name string
		root key.Public
		data []byte
		out  io.Writer
		want error
	}{
		{"accepted", rootInfo.Public, direct.Bytes(), &bytes.Buffer{}, nil},
		{"wrong root", wrongRoot, direct.Bytes(), io.Discard, coreintro.ErrWrongRoot},
		{"wrong child", rootInfo.Public,
			coreintro.New(rootInfo).Introduce(root, try.To1(exchangePublicInfo(other))).Bytes(),
			io.Discard, coreintro.ErrBadAcceptance},
		{"output failure", rootInfo.Public, direct.Bytes(),
			&exchangeFailSavedOutput{err: outputErr}, outputErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			parent := t.TempDir()
			t.Setenv("TMPDIR", parent)
			signer := &exchangeObservedHandle{Handle: alice}
			signature, err := saveExchangeAcceptance(
				t.Context(), signer, tc.root, tc.data, tc.out,
			)
			if tc.want == nil {
				assert.NoError(err)
				assert.NoError(direct.VerifyAcceptance(signature))
				assert.Equal(signer.signCalls, 1)
				assert.Equal(tc.out.(*bytes.Buffer).String(),
					"proposal received: R -> Alice\n"+
						"choice and acceptance saved: true\n"+
						"local acceptance verifies: true\n")
			} else {
				assert.ErrorIs(err, tc.want)
				assert.SNil(signature)
				if tc.name != "output failure" {
					assert.Equal(signer.signCalls, 0)
				}
			}
			assert.SEmpty(try.To1(os.ReadDir(parent)))
		})
	}
}

type exchangeFailSavedOutput struct{ err error }

func (w *exchangeFailSavedOutput) Write(data []byte) (int, error) {
	if bytes.Contains(data, []byte("choice and acceptance saved")) {
		return 0, w.err
	}
	return len(data), nil
}

func TestExchangeDemoShapeAndCancellation(t *testing.T) {
	defer assert.PushTester(t)()

	fixtures := try.To1(newStoredChoiceFixtures())
	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	signer := &exchangeObservedHandle{Handle: fixtures.alice}
	for _, data := range [][]byte{
		nil, wire.TryMarshal(coreintro.Path{}), fixtures.indirect.Bytes(),
	} {
		signature, err := saveExchangeAcceptance(
			t.Context(), signer, fixtures.rootPublic, data, io.Discard,
		)
		assert.Error(err)
		assert.SNil(signature)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := saveExchangeAcceptance(ctx, signer,
		fixtures.rootPublic, fixtures.direct.Bytes(), io.Discard)
	assert.ErrorIs(err, context.Canceled)
	assert.Equal(signer.signCalls, 0)
	assert.SEmpty(try.To1(os.ReadDir(parent)))
}
