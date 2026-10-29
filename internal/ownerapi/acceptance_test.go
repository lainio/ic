package ownerapi

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
)

const acceptancePath = "/peer/pw/accept"

// Independent requester storage and Known/device state, never the acceptor's
// Vault or signer substituted into the requester proof. Restored software
// signers and real dual HTTP listeners are additionally exercised in cmds/node.
type acceptanceFixture struct {
	proofFixture
	requesterVault deviceFixture
	requester      key.Public
	requesterKey   key.Handle
	prove          LocalAcceptanceProver
	publisher      *publicationHandler
}

func newAcceptanceFixture(t *testing.T) acceptanceFixture {
	t.Helper()
	defer assert.PushTester(t)()
	f := acceptanceFixture{proofFixture: newProofFixture(t),
		requesterVault: newDeviceFixture(t), requesterKey: key.New()}
	f.requester = try.To1(f.requesterKey.CBORPublicKey())
	choice, _ := try.To2(onboarding.ReadStoredChoice(f.vault, f.root, f.child))
	path := choice.Proposal.Introduce(f.signer.Handle,
		key.Info{Public: f.requester})
	acceptance := try.To1(path.SignAcceptance(f.requesterKey))
	for _, vault := range []deviceFixture{f.deviceFixture, f.requesterVault} {
		try.To2(onboarding.SaveIntroduction(vault.vault, f.root,
			choice.Proposal.Bytes(), choice.Acceptance))
		try.To2(onboarding.SaveIntroduction(vault.vault, f.root,
			path.Bytes(), acceptance))
		try.To1(onboarding.VerifyReceived(vault.vault, f.root))
	}
	try.To1(device.BootstrapLocal(f.requesterVault.vault, f.root,
		f.requester, f.requesterKey))
	owner, file, bind := try.To3(NewAcceptanceCredentials(t.Context(), f.vault,
		f.root, f.child, f.signer, t.TempDir()))
	f.owner = owner
	f.publisher = owner.(*authenticatedStatusHandler).
		next.(*acceptanceExchangeHandler).publicationHandler
	f.auth = strings.TrimSpace(strings.TrimPrefix(
		string(try.To1(os.ReadFile(file))), "Authorization: "))
	adProver, accept := bind(f.listener)
	f.prove = accept
	f.peer = peerapi.NewAcceptanceHandler(f.vault, f.root, f.child, f.endpoint,
		accept, peerapi.NewProofHandler(f.vault, f.root, f.child,
			f.endpoint, adProver))
	return f
}

func (f acceptanceFixture) challenge(t *testing.T) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	body := string(try.To1(json.Marshal(map[string]any{
		"version": 1, "requester_public_key_hex": hex.EncodeToString(f.requester),
		"ad": f.ad,
	})))
	w := deviceRequest(f.peer, "", "POST", "/peer/pw/challenge", body)
	assert.Equal(w.Code, 200)
	var reply struct{ Challenge []byte }
	try.To(json.Unmarshal(w.Body.Bytes(), &reply))
	assert.SLen(reply.Challenge, 32)
	return reply.Challenge
}

func (f acceptanceFixture) requesterProof(t *testing.T, nonce []byte) key.Signature {
	t.Helper()
	defer assert.PushTester(t)()
	return try.To1(pw.ProveLocalAcceptance(f.requesterVault.vault,
		f.root, f.requester, f.child, f.requesterKey, nonce))
}

func (f acceptanceFixture) body(t *testing.T, nonce []byte,
	proof key.Signature,
) string {
	t.Helper()
	defer assert.PushTester(t)()
	return string(try.To1(json.Marshal(map[string]any{
		"version": 1, "requester_public_key_hex": hex.EncodeToString(f.requester),
		"ad": f.ad, "challenge": nonce, "requester_proof": proof,
	})))
}

func checkAcceptanceResponse(t *testing.T, w *httptest.ResponseRecorder,
	root, acceptor, requester key.Public, nonce []byte,
) key.Signature {
	t.Helper()
	defer assert.PushTester(t)()
	assert.Equal(w.Code, 200)
	assert.Equal(w.Header().Get("Content-Type"), "application/json")
	assert.Equal(w.Header().Get("Cache-Control"), "no-store")
	assert.That(w.Body.Len() <= 1024)
	var fields map[string]json.RawMessage
	try.To(json.Unmarshal(w.Body.Bytes(), &fields))
	assert.Equal(len(fields), 2)
	assert.Equal(string(fields["version"]), "1")
	var encoded string
	try.To(json.Unmarshal(fields["acceptor_proof"], &encoded))
	proof := key.Signature(try.To1(base64.StdEncoding.Strict().DecodeString(encoded)))
	assert.Equal(base64.StdEncoding.EncodeToString(proof), encoded)
	try.To(pw.VerifyLocalAcceptanceProof(root, acceptor, requester, nonce, proof))
	return proof
}

func TestAcceptanceTwoLocalProofsAndOneUse(t *testing.T) {
	defer assert.PushTester(t)()
	f := newAcceptanceFixture(t)
	f.lease.remaining.Store(0)
	f.requesterVault.lease.remaining.Store(0)
	defer f.unchanged(t)()
	defer f.requesterVault.unchanged(t)()
	nonce := f.challenge(t)
	requesterProof := f.requesterProof(t, nonce)
	try.To(pw.VerifyLocalAcceptanceProof(f.root, f.requester, f.child,
		nonce, requesterProof))
	body := f.body(t, nonce, requesterProof)
	// Invalid signatures cannot burn the legitimate outstanding nonce.
	for range 2 {
		w := deviceRequest(f.peer, "", "POST", acceptancePath,
			f.body(t, nonce, key.Signature{1}))
		assert.Equal(w.Code, 400)
		assert.Equal(w.Body.String(), "Bad Request\n")
		assert.Equal(f.signer.signs.Load(), int32(0))
	}
	w := deviceRequest(f.peer, "", "POST", acceptancePath, body)
	proof := checkAcceptanceResponse(t, w, f.root, f.child, f.requester, nonce)
	assert.ThatNot(bytes.Equal(proof, requesterProof))
	assert.Error(pw.VerifyLocalAcceptanceProof(f.root, f.requester, f.child,
		nonce, proof))
	assert.Error(pw.VerifyLocalAcceptanceProof(f.child, f.child, f.requester,
		nonce, proof))
	assert.Error(pw.VerifyLocalAcceptanceProof(f.root, f.child, f.root,
		nonce, proof))
	assert.Error(pw.VerifyLocalAcceptanceProof(f.root, f.child, f.requester,
		currentProofNonce(t), proof))
	assert.Equal(f.signer.signs.Load(), int32(2)) // One probe + one acceptance.
	w = deviceRequest(f.peer, "", "POST", acceptancePath, body)
	assert.Equal(w.Code, 409)
	assert.Equal(f.signer.signs.Load(), int32(2))
}

func TestAcceptanceConcurrentReplay(t *testing.T) {
	defer assert.PushTester(t)()
	f := newAcceptanceFixture(t)
	defer f.unchanged(t)()
	nonce := f.challenge(t)
	body := f.body(t, nonce, f.requesterProof(t, nonce))
	results := make(chan *httptest.ResponseRecorder, 16)
	var workers sync.WaitGroup
	for range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			results <- deviceRequest(f.peer, "", "POST", acceptancePath, body)
		}()
	}
	workers.Wait()
	close(results)
	successes := 0
	for w := range results {
		if w.Code == 200 {
			successes++
			checkAcceptanceResponse(t, w, f.root, f.child, f.requester, nonce)
		} else {
			assert.Equal(w.Code, 409)
			assert.Equal(w.Body.String(), "Conflict\n")
		}
	}
	assert.Equal(successes, 1)
	assert.Equal(f.signer.signs.Load(), int32(2))
}

func TestAcceptanceLostWriteAndInvalidReplyRemainSpent(t *testing.T) {
	defer assert.PushTester(t)()
	f := newAcceptanceFixture(t)
	defer f.unchanged(t)()
	nonce := f.challenge(t)
	body := f.body(t, nonce, f.requesterProof(t, nonce))
	failed := &ownerStatusFailedWriter{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest("POST", acceptancePath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	f.peer.ServeHTTP(failed, r)
	assert.Equal(failed.headerCalls, 1)
	assert.Equal(failed.writeCalls, 1)
	assert.Equal(deviceRequest(f.peer, "", "POST", acceptancePath, body).Code, 409)
	assert.Equal(f.signer.signs.Load(), int32(2))
	// A buggy capability returning the requester's proof must not escape as
	// an acceptor proof. The peer independently verifies the opposite roles.
	calls := 0
	var wrong key.Signature
	f.peer = peerapi.NewAcceptanceHandler(f.vault, f.root, f.child, f.endpoint,
		func(key.Public, []byte, []byte) (key.Signature, error) {
			calls++
			return wrong, nil
		}, f.peer)
	nonce = f.challenge(t)
	wrong = f.requesterProof(t, nonce)
	body = f.body(t, nonce, wrong)
	w := deviceRequest(f.peer, "", "POST", acceptancePath, body)
	assert.Equal(w.Code, 500)
	assert.Equal(w.Body.String(), "Internal Server Error\n")
	assert.Equal(deviceRequest(f.peer, "", "POST", acceptancePath, body).Code, 409)
	assert.Equal(calls, 1)
}

func TestAcceptanceBinderIsOneShotAndOwnerRoutesStaySeparate(t *testing.T) {
	defer assert.PushTester(t)()
	f := newAcceptanceFixture(t)
	defer f.unchanged(t)()
	_, _, disabled := try.To3(NewAcceptanceCredentials(t.Context(), f.vault,
		f.root, f.child, f.signer, t.TempDir()))
	adProver, accept := disabled(nil)
	assert.That(adProver == nil && accept == nil)
	adProver, accept = disabled(publicationListener(t))
	assert.That(adProver == nil && accept == nil)
	root, local := bytes.Clone(f.root), bytes.Clone(f.child)
	_, _, bind := try.To3(NewAcceptanceCredentials(t.Context(), f.vault,
		root, local, f.signer, t.TempDir()))
	clear(root)
	clear(local)
	_, accept = bind(f.listener)
	bind(publicationListener(t))
	bind(nil)
	nonce := currentProofNonce(t)
	proof := try.To1(accept(f.requester, f.ad, nonce))
	try.To(pw.VerifyLocalAcceptanceProof(f.root, f.child, f.requester,
		nonce, proof))
	assert.Equal(deviceRequest(f.owner, f.auth, "POST", acceptancePath, "{}").Code,
		http.StatusNotFound)
}
