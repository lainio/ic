package intro

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	coreintro "github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
	"github.com/nats-io/nats.go"
	"github.com/spf13/cobra"
)

type exchangeConfig struct {
	session, natsURL, rootHex string
	timeout                   time.Duration
}

func newExchangeDemoCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exchange-demo",
		Short: "Exchange one direct proposal and detached acceptance locally",
		Long: `Run Root and Alice in separate processes with fresh signing handles.
Copy Root's printed public key into accept --root before accepting R -> Alice.
The accept invocation authorizes this one direct-root demo offer.
Summaries go to stdout; rejections and timeouts exit nonzero via stderr.
This disposable exchange creates no membership, Known, trust, or pairwise state.
It is not a human consent ceremony or a secure channel. NATS carries bytes;
the acknowledgement is only the issuer's unsigned verification report.`,
	}
	cmd.AddCommand(newExchangeRoleCommand("root"))
	cmd.AddCommand(newExchangeRoleCommand("accept"))
	return cmd
}

func newExchangeRoleCommand(role string) *cobra.Command {
	cfg := exchangeConfig{}
	cmd := &cobra.Command{
		Use:   role,
		Short: "Serve one R -> Alice proposal",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) (err error) {
			defer err2.Handle(&err)

			endpoint := try.To1(cfg.validate())
			var expectedRoot key.Public
			if role == "accept" {
				expectedRoot = try.T1(parseExchangeRoot(cfg.rootHex))(
					"checking --root",
				)
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.timeout)
			defer cancel()
			nc := try.T1(connectExchange(ctx, endpoint))("connecting to NATS")
			defer nc.Close() // NATS Close has no error result.
			handle := key.New()

			if role == "root" {
				_, err = runExchangeRoot(
					ctx, nc, handle, cfg.session, cmd.OutOrStdout(),
				)
			} else {
				_, err = runExchangeAlice(
					ctx, nc, handle, expectedRoot, cfg.session, cmd.OutOrStdout(),
				)
			}
			return err
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&cfg.session, "session", "", "Required ASCII session token")
	flags.StringVar(&cfg.natsURL, "nats-url", "nats://127.0.0.1:4222",
		"One loopback Core NATS endpoint")
	flags.DurationVar(&cfg.timeout, "timeout", 2*time.Minute,
		"Positive total exchange timeout")
	try.To(cmd.MarkFlagRequired("session"))
	if role == "accept" {
		cmd.Short = "Accept one offer from an independently selected root"
		flags.StringVar(&cfg.rootHex, "root", "",
			"Required full hex CBOR public key copied from Root")
		try.To(cmd.MarkFlagRequired("root"))
	}
	return cmd
}

func parseExchangeRoot(value string) (public key.Public, err error) {
	defer err2.Handle(&err)

	if value == "" || len(value) > 2*exchangePayloadLimit {
		return nil, errors.New("--root requires full hex CBOR public-key bytes")
	}
	decoded := try.To1(hex.DecodeString(value))
	// The existing handle emits a COSE EC2/P-256 key. Validate the selected
	// key here; ProveFromRoot deliberately only compares its bytes.
	var publicKey webauthncose.EC2PublicKeyData
	try.To(wire.Unmarshal(&publicKey, decoded))
	if publicKey.KeyType != int64(webauthncose.EllipticKey) ||
		publicKey.Algorithm != int64(webauthncose.AlgES256) ||
		publicKey.Curve != int64(webauthncose.P256) ||
		len(publicKey.XCoord) == 0 || len(publicKey.XCoord) > 32 ||
		len(publicKey.YCoord) == 0 || len(publicKey.YCoord) > 32 {
		return nil, errors.New("--root requires a valid EC2/P-256 public key")
	}
	// Validate the point without changing the independently selected bytes.
	var point [65]byte
	point[0] = 4
	copy(point[33-len(publicKey.XCoord):33], publicKey.XCoord)
	copy(point[65-len(publicKey.YCoord):], publicKey.YCoord)
	try.T1(ecdh.P256().NewPublicKey(point[:]))("checking --root curve point")
	return decoded, nil
}

// Root owns exactly the proposal returned by newExchangeProposal. Only the
// detached signature arrives in the second request; no replacement path/key.
func runExchangeRoot(
	ctx context.Context, nc *nats.Conn, root key.Handle,
	session string, out io.Writer,
) (issued coreintro.Path, err error) {
	defer err2.Handle(&err)

	offerSubject, acceptanceSubject := exchangeSubjects(session)
	offers := try.To1(nc.SubscribeSync(offerSubject))
	defer func() { try.Out(offers.Unsubscribe()).Logf() }()
	acceptances := try.To1(nc.SubscribeSync(acceptanceSubject))
	defer func() { try.Out(acceptances.Unsubscribe()).Logf() }()
	try.T(nc.FlushWithContext(ctx))("flushing both subscriptions")
	public := try.To1(root.CBORPublicKey())
	try.To1(fmt.Fprintf(out,
		"root public key (hex): %s\nready for Alice\n",
		hex.EncodeToString(public),
	))

	request := try.T1(offers.NextMsgWithContext(ctx))("waiting for Alice")
	proposal, proposalErr := newExchangeProposal(root, request)
	var data []byte
	if proposalErr == nil {
		data = proposal.Bytes()
	}
	try.To(replyExchange(ctx, nc, request, data, proposalErr))
	try.To1(fmt.Fprintln(out, "proposal sent: R -> Alice"))

	request = try.T1(acceptances.NextMsgWithContext(ctx))(
		"waiting for detached acceptance",
	)
	verifyErr := verifyExchangeAcceptance(proposal, request)
	try.To(replyExchange(ctx, nc, request, []byte(exchangeVerified), verifyErr))
	try.To1(fmt.Fprintln(out, "Alice's acceptance verifies: true"))
	return proposal, nil
}

func newExchangeProposal(
	root key.Handle, request *nats.Msg,
) (proposal coreintro.Path, err error) {
	defer err2.Handle(&err)

	try.To(checkExchangeRequest(request)) // Before any signing.
	return newExchangeProposalFromBytes(root, request.Data)
}

func newExchangeProposalFromBytes(
	root key.Handle, data []byte,
) (proposal coreintro.Path, err error) {
	defer err2.Handle(&err, nil) // Preserve the NATS wrapper's error annotation.

	var child key.Info
	try.T(wire.UnmarshalCanonical(&child, data))("decoding Alice's key")
	if len(child.Public) == 0 {
		return nil, errors.New("alice public key is empty")
	}
	// IDs are not authority. Do not reflect a supplied storage ID into evidence.
	child.ID = nil
	rootInfo := try.To1(exchangePublicInfo(root))
	return coreintro.New(rootInfo).Introduce(root, child), nil
}

func verifyExchangeAcceptance(
	issued coreintro.Path, request *nats.Msg,
) (err error) {
	defer err2.Handle(&err)

	try.To(checkExchangeRequest(request))
	return issued.VerifyAcceptance(request.Data)
}

func runExchangeAlice(
	ctx context.Context, nc *nats.Conn, alice key.Handle,
	expectedRoot key.Public, session string, out io.Writer,
) (acceptance key.Signature, err error) {
	defer err2.Handle(&err)

	info := try.To1(exchangePublicInfo(alice))
	offerSubject, acceptanceSubject := exchangeSubjects(session)
	data := try.To1(
		requestExchange(ctx, nc, offerSubject, wire.TryMarshal(info)),
	)
	signature := try.To1(saveExchangeAcceptance(
		ctx, alice, expectedRoot, data, out,
	))

	report := try.To1(requestExchange(ctx, nc, acceptanceSubject, signature))
	if string(report) != exchangeVerified {
		return nil, errors.New("unexpected issuer verification report")
	}
	try.To1(fmt.Fprintln(out, "issuer reported acceptance verified: true"))
	return signature, nil
}

// No ID() call: the pinned development backend encodes an encrypted private
// key in its ID. Only public CBOR bytes may leave this process.
func exchangePublicInfo(handle key.Handle) (info key.Info, err error) {
	defer err2.Handle(&err)

	public := try.To1(handle.CBORPublicKey())
	return key.Info{Public: public}, nil
}

func saveExchangeAcceptance(
	ctx context.Context, alice key.Handle, expectedRoot key.Public,
	data []byte, out io.Writer,
) (acceptance key.Signature, err error) {
	defer err2.Handle(&err)

	proposal := try.To1(parseExchangeProposal(ctx, data, out))

	dir := try.To1(os.MkdirTemp("", "intro-exchange-demo-"))
	defer func() { try.Out(os.RemoveAll(dir)).Logf() }()
	provider := newStoredChoiceProvider()
	defer clear(provider.secret)
	try.To1(rand.Read(provider.secret))
	db := try.To1(storage.OpenBolt(filepath.Join(dir, "vault.db")))
	defer func() { try.Out(db.Close()).Logf() }()
	try.To(db.CreateVault(ctx, provider.vault, provider.id, provider))
	vault := try.To1(db.OpenVault(ctx, provider.vault, provider.id, provider))
	defer func() { try.Out(vault.Close()).Logf() }()

	signature, signErr := signExchangeAcceptance(
		vault, alice, expectedRoot, proposal,
	)
	// Attempt all normal-path cleanup even on refusal, retaining its cause.
	closeErr := errors.Join(vault.Close(), db.Close())
	clear(provider.secret)
	removeErr := os.RemoveAll(dir)
	try.To(errors.Join(signErr, closeErr, removeErr))
	try.To1(fmt.Fprint(out, exchangeAcceptanceSaved))
	return signature, nil
}

const exchangeAcceptanceSaved = "choice and acceptance saved: true\n" +
	"local acceptance verifies: true\n"

func parseExchangeProposal(
	ctx context.Context, data []byte, out io.Writer,
) (proposal coreintro.Path, err error) {
	defer err2.Handle(&err, nil)

	try.To(ctx.Err())
	try.To(checkExchangePayload(data))
	proposal = try.T1(coreintro.ParsePath(data))("parsing proposal")
	if len(proposal) != 2 {
		return nil, errors.New("demo requires exactly R -> Alice")
	}
	for _, edge := range proposal {
		if edge.Body.Options.BackupKeyIndex != 0 ||
			edge.Body.Options.Rotation {
			return nil, errors.New(
				"demo does not support backup or rotation",
			)
		}
	}
	try.To1(fmt.Fprintln(out, "proposal received: R -> Alice"))
	return proposal, nil
}

// Borrows the Vault. Onboarding alone owns selection, signing, and saved results.
func signExchangeAcceptance(
	vault *storage.Vault, alice key.Handle, expectedRoot key.Public,
	proposal coreintro.Path,
) (acceptance key.Signature, err error) {
	defer err2.Handle(&err, nil)

	// Root AND parent come from --root, never from the received path.
	signature := try.To1(onboarding.SignAfterStoredChoice(
		vault, alice, expectedRoot, expectedRoot, proposal,
	))
	try.To(proposal.VerifyAcceptance(signature))
	return signature, nil
}
