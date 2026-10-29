package node

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const peerChallengePath = "/peer/pw/challenge"

func peerChallengeBody(t *testing.T, requester key.Public, ad []byte) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	return try.To1(json.Marshal(map[string]any{
		"version": 1, "requester_public_key_hex": hex.EncodeToString(requester),
		"ad": ad,
	}))
}

// Reuse the real node/Vault and completed-introduction fixtures. Receipt and
// promotion remain explicit, independently of publication and challenge calls.
func saveChallengeRequester(
	t *testing.T,
	s *nodeServe,
	f serveFixture,
	known bool,
) key.Public {
	t.Helper()
	defer assert.PushTester(t)()
	parent := try.To1(nodeidentity.OpenDirectory(f.dir, f.unlock))
	requester := key.New()
	public := key.Public(try.To1(requester.CBORPublicKey()))
	path := f.proposal.Introduce(parent, key.Info{Public: public})
	try.To2(onboarding.SaveIntroduction(s.store.Vault(), f.root, path.Bytes(),
		try.To1(path.SignAcceptance(requester))))
	if known {
		try.To1(onboarding.VerifyReceived(s.store.Vault(), f.root))
	}
	return public
}

func assertPeerChallenge(
	t *testing.T,
	result peerHTTPResult,
	before time.Time,
) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	assert.NoError(result.err)
	assert.Equal(result.status, 200)
	assert.That(len(result.body) <= 1024)
	var fields map[string]json.RawMessage
	try.To(json.Unmarshal(result.body, &fields))
	assert.Equal(len(fields), 3)
	assert.Equal(string(fields["version"]), "1")
	var encoded string
	var expires int64
	try.To(json.Unmarshal(fields["challenge"], &encoded))
	try.To(json.Unmarshal(fields["expires_unix_nano"], &expires))
	nonce := try.To1(base64.StdEncoding.Strict().DecodeString(encoded))
	assert.SLen(nonce, 32)
	assert.Equal(base64.StdEncoding.EncodeToString(nonce), encoded)
	assert.That(expires >= before.Add(30*time.Second).UnixNano())
	assert.That(expires <= time.Now().Add(30*time.Second).UnixNano())
	return nonce
}

func TestServePeerChallengeLifecycleAndRestart(t *testing.T) {
	defer assert.PushTester(t)()
	f := prepareServeFixture(t)
	choice := saveServeChoice(t, f, "completed")
	s := setupPeerServe(t, f)
	auth := serveAuthorization(t, s)
	try.To2(
		onboarding.SaveIntroduction(
			s.store.Vault(),
			f.root,
			choice.Proposal.Bytes(),
			choice.Acceptance,
		),
	)
	requester := saveChallengeRequester(t, s, f, true)
	assert.Equal(
		serveDeviceRequest(
			s.handler,
			auth,
			"POST",
			ownerBootstrapPath,
			[]byte("{}"),
		).Code,
		200,
	)
	owner, peer := try.To2(
		bindNodeListeners(t.Context(), "127.0.0.1:0", s.peerAddress),
	)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	var result error
	var output bytes.Buffer
	go func() { result = runNodeServe(ctx, owner, peer, s, &output); close(done) }()
	defer func() { cancel(); waitNodeServe(t, done) }()
	ownerURL, peerURL := "http://"+owner.Addr().
		String(),
		"http://"+peer.Addr().
			String()
	published := postDeviceHTTP(t.Context(), ownerURL+ownerPublishPath, auth)
	assert.NoError(published.err)
	assert.Equal(published.status, 200)
	current, found := try.To2(
		ads.ReadCurrentLocal(s.store.Vault(), f.root, f.child, time.Now()),
	)
	assert.That(found)
	assert.Equal(
		current.Payload.PeerIntroductionURL,
		peerURL+"/peer/introduction",
	)
	ad := try.To1(wire.Marshal(current))
	body := peerChallengeBody(t, requester, ad)
	t.Run(
		"unsigned ephemeral issuance and preserved routes",
		func(t *testing.T) {
			defer assert.PushTester(t)()
			assertPeerFilesUnchanged(
				t,
				f,
			) // Entire encrypted Vault and usage files.
			before := try.To1(verificationUnrelatedState(s.store.Vault()))
			started := time.Now()
			first := assertPeerChallenge(
				t,
				postPeerProofHTTP(
					t.Context(),
					peerURL+peerChallengePath,
					"",
					body,
					false,
				),
				started,
			)
			second := assertPeerChallenge(
				t,
				postPeerProofHTTP(
					t.Context(),
					peerURL+peerChallengePath,
					"",
					body,
					true,
				),
				started,
			)
			assert.ThatNot(bytes.Equal(first, second))
			assert.DeepEqual(
				try.To1(verificationUnrelatedState(s.store.Vault())),
				before,
			)
			for _, route := range []string{"/peer/introduction", "/peer/ad"} {
				response := waitPeerHTTP(
					t,
					peerHTTPRequest(t.Context(), peerURL+route, ""),
				)
				assert.NoError(response.err)
				assert.Equal(response.status, 200)
			}
			nonce := peerProofNonce(t)
			assertOnlineProof(
				t,
				postPeerProofHTTP(
					t.Context(),
					peerURL+peerProofPath,
					"",
					peerProofBody(t, ad, nonce),
					false,
				),
				f,
				ad,
				nonce,
			)
			for _, credential := range []string{"", auth} {
				refused := postPeerProofHTTP(
					t.Context(),
					ownerURL+peerChallengePath,
					credential,
					body,
					false,
				)
				assert.NoError(refused.err)
				assert.Equal(refused.status, 404)
			}
			for _, route := range []string{
				ownerPublishPath, ownerBootstrapPath, ownerAdVerifyPath,
				"/owner/introductions", "/owner/introductions/verify",
				"/peer/pw/consume",
			} {
				refused := postPeerProofHTTP(
					t.Context(),
					peerURL+route,
					auth,
					body,
					false,
				)
				assert.NoError(refused.err)
				assert.Equal(refused.status, 404)
			}
			oversize := postPeerProofHTTP(
				t.Context(),
				peerURL+peerChallengePath,
				"",
				bytes.Repeat([]byte(" "), 2049),
				true,
			)
			assert.NoError(oversize.err)
			assert.Equal(oversize.status, 413)
		},
	)
	// Reserve a different actual port before stopping the first invocation.
	nextOwner, nextPeer := try.To2(
		bindNodeListeners(t.Context(), "127.0.0.1:0", s.peerAddress),
	)
	defer func() { try.Out(nextOwner.Close()).Logf(); try.Out(nextPeer.Close()).Logf() }()
	cancel()
	waitNodeServe(t, done)
	assert.NoError(result)
	assert.ThatNot(strings.Contains(output.String(), auth))
	after := postPeerProofHTTP(
		t.Context(),
		peerURL+peerChallengePath,
		"",
		body,
		false,
	)
	assert.Error(after.err)
	s = setupPeerServe(t, f)
	auth = serveAuthorization(t, s)
	ctx, stopRestart := context.WithCancel(t.Context())
	restarted := make(chan struct{})
	go func() { result = runNodeServe(ctx, nextOwner, nextPeer, s, &output); close(restarted) }()
	defer func() { stopRestart(); waitNodeServe(t, restarted) }()
	peerURL = "http://" + nextPeer.Addr().String()
	t.Run(
		"restart refuses old endpoint without publication",
		func(t *testing.T) {
			defer assert.PushTester(t)()
			assertPeerFilesUnchanged(t, f)
			refused := postPeerProofHTTP(
				t.Context(),
				peerURL+peerChallengePath,
				"",
				body,
				false,
			)
			assert.NoError(refused.err)
			assert.Equal(refused.status, 409)
			assert.Equal(string(refused.body), "Conflict\n")
			got, exists := try.To2(
				ads.ReadCurrentLocal(
					s.store.Vault(),
					f.root,
					f.child,
					time.Now(),
				),
			)
			assert.That(exists)
			assert.DeepEqual(got, current)
		},
	)
	stopRestart()
	waitNodeServe(t, restarted)
	assert.NoError(result)
}

func TestServeChallengeKnownDenyAndCapacity(t *testing.T) {
	defer assert.PushTester(t)()
	n := startVerificationNode(t, prepareServeFixture(t), true)
	s, f := n.service, n.fixture
	requester := saveChallengeRequester(t, s, f, false)
	body := peerChallengeBody(t, requester, n.ad)
	request := func() peerHTTPResult {
		return postPeerProofHTTP(
			t.Context(),
			n.peer.URL+peerChallengePath,
			"",
			body,
			false,
		)
	}
	t.Run("Received alone refuses without changes", func(t *testing.T) {
		defer assert.PushTester(t)()
		assertPeerFilesUnchanged(t, f)
		refused := request()
		assert.NoError(refused.err)
		assert.Equal(refused.status, 409)
		assert.Equal(string(refused.body), "Conflict\n")
	})
	try.To1(onboarding.VerifyReceived(s.store.Vault(), f.root))
	started := time.Now()
	assertPeerChallenge(t, request(), started)
	try.To1(policy.DenyLocal(s.store.Vault(), f.root, f.child, requester))
	t.Run("Deny after issuance is not a grant", func(t *testing.T) {
		defer assert.PushTester(t)()
		assertPeerFilesUnchanged(t, f)
		refused := request()
		assert.NoError(refused.err)
		assert.Equal(refused.status, 409)
		assert.Equal(string(refused.body), "Conflict\n")
	})
	try.To1(policy.AllowLocal(s.store.Vault(), f.root, f.child, requester))
	try.To(s.store.Vault().Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return try.To1(tx.ChildForUpdate([]byte("known-introductions-v1"))).
			Delete(requester)
	}))
	t.Run("Known removal after issuance is not a grant", func(t *testing.T) {
		defer assert.PushTester(t)()
		assertPeerFilesUnchanged(t, f)
		refused := request()
		assert.NoError(refused.err)
		assert.Equal(refused.status, 409)
	})
	try.To1(onboarding.VerifyReceived(s.store.Vault(), f.root))
	t.Run("32 outstanding and no eviction", func(t *testing.T) {
		defer assert.PushTester(t)()
		assertPeerFilesUnchanged(t, f)
		for range 31 {
			assertPeerChallenge(t, request(), started)
		}
		refused := request()
		assert.NoError(refused.err)
		assert.Equal(refused.status, 429)
		assert.Equal(string(refused.body), "Too Many Requests\n")
	})
	assert.Equal(
		n.calls.Load(),
		int32(0),
	) // Never entered the signing proof route.
}

func TestServeChallengeRefusesChangedOrCorruptState(t *testing.T) {
	for _, scenario := range []string{
		"unknown requester", "expired ad", "replaced ad",
		"wrong endpoint", "corrupt ad", "corrupt Known", "corrupt denial",
		"local no longer Known", "closed Vault",
	} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			n := startVerificationNode(t, prepareServeFixture(t), true)
			s, f := n.service, n.fixture
			requester := saveChallengeRequester(t, s, f, true)
			ad := bytes.Clone(n.ad)
			want := 409
			switch scenario {
			case "unknown requester":
				requester = try.To1(key.New().CBORPublicKey())
			case "expired ad", "wrong endpoint":
				signer := try.To1(nodeidentity.OpenDirectory(f.dir, f.unlock))
				now, endpoint := time.Now(), n.peer.URL+"/peer/introduction"
				if scenario == "expired ad" {
					now = now.Add(-2 * ads.TTL)
				} else {
					endpoint = peerAdEndpoint
				}
				ad = try.To1(wire.Marshal(try.To1(ads.PublishLocal(
					s.store.Vault(), f.root, f.child, signer, endpoint, now))))
			case "replaced ad":
				n.publish(
					t,
				) // The request deliberately retains the original bytes.
			case "corrupt ad",
				"corrupt Known",
				"corrupt denial",
				"local no longer Known":
				try.To(
					s.store.Vault().
						Update(func(tx storage.WriteTx) (err error) {
							defer err2.Handle(&err, nil)
							switch scenario {
							case "corrupt ad":
								return try.To1(tx.ChildForUpdate([]byte("local-current-ad-v1"))).
									Put([]byte("slot-1"), []byte("private corrupt ad"))
							case "corrupt Known":
								return try.To1(tx.ChildForUpdate([]byte("known-introductions-v1"))).
									Put(requester, []byte("private corrupt Known"))
							case "corrupt denial":
								return tx.Put(
									[]byte("local-denied-peers-v1"),
									[]byte("private corrupt denial"),
								)
							default:
								return try.To1(tx.ChildForUpdate([]byte("known-introductions-v1"))).
									Delete(f.child)
							}
						}),
				)
			}
			if strings.HasPrefix(scenario, "corrupt") ||
				scenario == "closed Vault" {
				want = 500
			}
			assertPeerFilesUnchanged(t, f)
			if scenario == "closed Vault" {
				try.To(s.store.Close())
			}
			for range 2 {
				response := postPeerProofHTTP(
					t.Context(),
					n.peer.URL+peerChallengePath,
					"",
					peerChallengeBody(t, requester, ad),
					false,
				)
				assert.NoError(response.err)
				assert.Equal(response.status, want)
				assert.Equal(string(response.body), http.StatusText(want)+"\n")
			}
			assert.Equal(n.calls.Load(), int32(0))
		})
	}
}

func TestServeChallengeSignerIsolationAndCopiedConfiguration(t *testing.T) {
	defer assert.PushTester(t)()
	n := startVerificationNode(t, prepareServeFixture(t), true)
	s, f := n.service, n.fixture
	requester := saveChallengeRequester(t, s, f, true)
	root, child := bytes.Clone(f.root), bytes.Clone(f.child)
	endpoint := n.peer.URL + "/peer/introduction"
	proofCalls := 0
	next := peerapi.NewProofHandler(s.store.Vault(), root, child, endpoint,
		func([]byte, []byte) (key.Signature, error) {
			proofCalls++
			return nil, ads.ErrUnusable
		})
	h := peerapi.NewChallengeHandler(
		s.store.Vault(),
		root,
		child,
		endpoint,
		next,
	)
	clear(root)
	clear(child)
	assertPeerFilesUnchanged(t, f)
	started := time.Now()
	w := serveDeviceRequest(
		h,
		"",
		"POST",
		peerChallengePath,
		peerChallengeBody(t, requester, n.ad),
	)
	assertPeerChallenge(
		t,
		peerHTTPResult{status: w.Code, body: w.Body.Bytes()},
		started,
	)
	assert.Equal(proofCalls, 0)
	assert.Equal(w.Header().Get("Cache-Control"), "no-store")
	for _, name := range []string{"Authorization", "WWW-Authenticate", "Set-Cookie", "Access-Control-Allow-Origin"} {
		assert.Empty(w.Header().Get(name))
	}
}

func TestServeChallengeDisabledAndUnpublishedChoices(t *testing.T) {
	for _, stage := range []string{"unselected", "pending", "completed"} {
		t.Run(stage, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := prepareServeFixture(t)
			saveServeChoice(t, f, stage)
			s := setupPeerServe(t, f)
			requester := saveChallengeRequester(t, s, f, true)
			// A genuine signed claim is still not a saved current publication.
			signer := try.To1(nodeidentity.OpenDirectory(f.dir, f.unlock))
			payload := ads.Payload{
				Version:             1,
				Root:                f.root,
				Node:                f.child,
				Device:              f.child,
				Slot:                1,
				Token:               make([]byte, 32),
				ExpiresUnixNano:     time.Now().Add(ads.TTL).UnixNano(),
				PeerIntroductionURL: peerAdEndpoint,
			}
			digest := key.HashTagged(
				ads.SignaturePurpose,
				try.To1(wire.Marshal(payload)),
			)
			ad := try.To1(
				wire.Marshal(
					ads.Current{
						Payload:   payload,
						Signature: try.To1(signer.Sign(digest[:])),
					},
				),
			)
			body := peerChallengeBody(t, requester, ad)
			t.Run("unpublished claim", func(t *testing.T) {
				defer assert.PushTester(t)()
				assertPeerFilesUnchanged(t, f)
				h := peerapi.NewChallengeHandler(
					s.store.Vault(),
					f.root,
					f.child,
					peerAdEndpoint,
					s.peerHandler,
				)
				w := serveDeviceRequest(h, "", "POST", peerChallengePath, body)
				assert.Equal(w.Code, 409)
			})
			// No peer socket, no challenge route, including on the owner listener.
			try.To(s.close())
			s, _ = try.To2(setupNodeServe(t.Context(), serveCommand(t, f)))
			defer func() { try.Out(s.close()).Logf() }()
			owner, peer := try.To2(
				bindNodeListeners(t.Context(), "127.0.0.1:0", s.peerAddress),
			)
			assert.INil(peer)
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			var result error
			var output bytes.Buffer
			go func() { result = runNodeServe(ctx, owner, peer, s, &output); close(done) }()
			defer func() { cancel(); waitNodeServe(t, done) }()
			response := postPeerProofHTTP(
				t.Context(),
				"http://"+owner.Addr().String()+peerChallengePath,
				"",
				body,
				false,
			)
			assert.NoError(response.err)
			assert.Equal(response.status, 404)
			cancel()
			waitNodeServe(t, done)
			assert.NoError(result)
			assert.INil(s.peerHandler)
		})
	}
}
