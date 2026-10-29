package pw

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

var (
	ErrAdEvidence = errors.New(
		"missing, changed or expired acceptance ad evidence",
	)
	ErrRemoteAcceptance = errors.New("remote acceptance exchange failed")
)

// RequestRemoteAcceptance executes one explicit challenge/acceptance exchange.
// Nil observes two opposite-role purpose-bound signatures for this exchange;
// it is NEVER permission to open/create a PW, durable consent or reachability.
// Historical VerifiedAd admits the exact received ad, not global CurrentAd.
// A key holder can sign without honestly following policy. V19 CreatePW still
// requires stronger final guards and atomic pairwise state transitions.
//
// The caller borrows a Vault independently bound to immutable Root/local config
// and its installed signer, and joins calls before closing them. Inputs are
// copied; callers must not mutate them concurrently with entry. Local checks
// are momentary, not an atomic snapshot or a history of intervening mutations.
// No transaction, signer callback or service mutation lock may span HTTP I/O.
// The installed software signer must complete synchronously; the context bounds
// the exchange but cannot interrupt key.Handle's context-free methods.
//
// Only the signed literal loopback endpoint is used. There is no fetch,
// promotion, ledger, retry or durable write. Loss of a reply can follow a remote
// signature and nonce consumption; failure cannot roll that back. A future
// explicit invocation obtains a new challenge, never reuses this one.
func RequestRemoteAcceptance(
	ctx context.Context,
	vault *storage.Vault,
	expectedRoot, expectedLocal, peer key.Public,
	signer key.Handle,
) (err error) {
	defer err2.Handle(&err, nil)

	if ctx == nil || vault == nil || !validPublic(expectedRoot) ||
		!validPublic(expectedLocal) || !validPublic(peer) ||
		bytes.Equal(expectedLocal, peer) {
		return ErrInvalidInput
	}
	root, local := bytes.Clone(expectedRoot), bytes.Clone(expectedLocal)
	peer = bytes.Clone(peer)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	try.To(ctx.Err())

	// Authenticate evidence before any signer callback or network request.
	ad, current := try.To2(readAcceptanceAd(vault, root, peer, nil))
	try.To(CheckLocalAcceptor(vault, root, local, peer, signer))
	try.To2(readAcceptanceAd(vault, root, peer, ad))
	try.To(ctx.Err())

	transport := &http.Transport{
		DisableKeepAlives: true, DisableCompression: true,
		MaxResponseHeaderBytes: 1024, ReadBufferSize: 1024,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	base := strings.TrimSuffix(current.Payload.PeerIntroductionURL,
		"/peer/introduction")
	request := exchangeRequest{
		Version: 1, Requester: hex.EncodeToString(local), Ad: ad,
	}
	data := try.To1(postExchange(ctx, client, base+"/peer/pw/challenge",
		request, 2*1024))
	challenge := try.To1(decodeExchangeResponse(data, true))
	try.To(checkChallengeTime(challenge.expires))

	try.To(CheckLocalAcceptor(vault, root, local, peer, signer))
	try.To2(readAcceptanceAd(vault, root, peer, ad))
	try.To(ctx.Err())
	try.To(checkChallengeTime(challenge.expires))
	proof := try.To1(ProveLocalAcceptance(vault, root, local, peer,
		signer, challenge.nonce))
	try.To(VerifyLocalAcceptanceProof(root, local, peer, challenge.nonce,
		proof))
	// Reject changes/expiry during signing too, before disclosing its result.
	try.To2(readAcceptanceAd(vault, root, peer, ad))
	try.To(ctx.Err())
	try.To(checkChallengeTime(challenge.expires))

	request.Challenge, request.Proof = challenge.nonce, proof
	data = try.To1(postExchange(ctx, client, base+"/peer/pw/accept",
		request, 3*1024))
	accepted := try.To1(decodeExchangeResponse(data, false))
	if VerifyLocalAcceptanceProof(root, peer, local, challenge.nonce,
		accepted.proof) != nil {
		return ErrRemoteAcceptance
	}
	try.To(CheckLocalAcceptor(vault, root, local, peer, signer))
	try.To2(readAcceptanceAd(vault, root, peer, ad))
	try.To(checkChallengeTime(challenge.expires))
	return ctx.Err()
}

// Both readers validate whole collections. The historical reader authenticates
// the original signature and v1 Root/Node/Device/slot/epoch/endpoint binding.
// No new crypto or currentness interpretation belongs in this package.
func readAcceptanceAd(vault *storage.Vault, root, peer key.Public,
	expected []byte,
) ([]byte, ads.Current, error) {
	ad, received, err := ads.ReadReceivedClaim(vault, root, peer)
	if err != nil {
		return nil, ads.Current{}, ErrLocalState
	}
	verified, historical, err := ads.ReadVerifiedClaim(vault, root, peer)
	if err != nil {
		return nil, ads.Current{}, ErrLocalState
	}
	if !received || !historical || !bytes.Equal(ad, verified) ||
		(expected != nil && !bytes.Equal(ad, expected)) {
		return nil, ads.Current{}, ErrAdEvidence
	}
	if ads.ValidateClaim(root, peer, ad) != nil {
		return nil, ads.Current{}, ErrLocalState
	}
	var current ads.Current
	if wire.DecMode.Unmarshal(ad, &current) != nil {
		return nil, ads.Current{}, ErrLocalState
	}
	if time.Now().UnixNano() >= current.Payload.ExpiresUnixNano {
		return nil, ads.Current{}, ErrAdEvidence
	}
	return ad, current, nil
}

// The peer publishes a 30-second TTL. Permit at most one second of forward
// clock skew; accept no expired claim. This untrusted value never extends the
// independent five-second context deadline and is neither cached nor authority.
func checkChallengeTime(expires int64) error {
	now := time.Now()
	if expires <= now.UnixNano() ||
		expires > now.Add(31*time.Second).UnixNano() {
		return ErrRemoteAcceptance
	}
	return nil
}
