package pw_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/ownerapi"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
)

const ownerDenyPath = "/owner/policy/deny"
const deniedPolicyKey = "local-denied-peers-v1"

// Sequential owner action on real independent nodevault stores. The surrounding
// byte snapshots include both nodes' usage files, identities and encrypted DBs.
func denyExchangePeer(t *testing.T, f *exchangeFixture, n *exchangeNode,
	peer key.Public, changed bool,
) {
	t.Helper()
	defer assert.PushTester(t)()
	before := f.snapshot(t)
	records := exchangeHeldState(t, n.store.Vault())
	signs := len(n.signer.signed())
	h, file, bind := try.To3(ownerapi.NewFirstUseCredentials(t.Context(),
		n.store.Vault(), f.root, n.public, n.signer, t.TempDir()))
	bind(nil)
	assert.DeepEqual(f.snapshot(t), before)
	auth := strings.TrimSpace(strings.TrimPrefix(
		string(try.To1(os.ReadFile(file))), "Authorization:"))
	body := `{"peer_public_key_hex":"` + hex.EncodeToString(peer) + `"}`
	r := httptest.NewRequest("POST", ownerDenyPath, strings.NewReader(body))
	r.Header.Set("Authorization", auth)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(w.Code, http.StatusOK)
	want := `{"changed":false}`
	if changed {
		want = `{"changed":true}`
	}
	assert.Equal(w.Body.String(), want)
	assert.Equal(w.Header().Get("Cache-Control"), "no-store")
	assert.Equal(len(n.signer.signed()), signs)
	assert.That(
		try.To1(policy.IsDenied(n.store.Vault(), f.root, n.public, peer)),
	)
	after := f.snapshot(t)
	if changed {
		current := exchangeHeldState(t, n.store.Vault())
		assert.SNotEmpty(current["root"][deniedPolicyKey])
		delete(current["root"], deniedPolicyKey)
		delete(records["root"], deniedPolicyKey)
		assert.DeepEqual(current, records)
		// Only the local encrypted DB (and a possible lease reservation) may
		// change. No other record or file, especially the peer's, may change.
		for _, name := range []string{"vault.db", "usage.db"} {
			delete(before, filepath.Join(n.dir, "state", name))
			delete(after, filepath.Join(n.dir, "state", name))
		}
	}
	assert.DeepEqual(after, before)
}

func TestDenyBobPreemptsInvitationConsumption(t *testing.T) {
	for _, afterIssue := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "before issue", true: "after issue"}[afterIssue],
			func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newExchange(t, nil)
				if !afterIssue {
					denyExchangePeer(t, f, f.b, f.a.public, true)
				}
				row := try.To1(pw.IssueInvitation(f.b.store.Vault(), f.root,
					f.b.public, f.a.public))
				if afterIssue {
					denyExchangePeer(t, f, f.b, f.a.public, true)
				}
				try.To1(pw.SaveAttempt(f.a.store.Vault(), f.root, f.a.public,
					f.b.public, f.a.signer, row.ID, row.Audience))
				request := try.To1(exchangeRecords(f.a.store.Vault()))[0]
				before := f.snapshot(t)
				endpoint := f.server.URL + "/peer/introduction"
				assert.Equal(pw.BobAccept(
					f.b.store.Vault(),
					f.root,
					f.b.public,
					f.b.signer,
					endpoint,
					request,
				), pw.ErrEstablishment)
				response, err := pw.BobReply(f.b.store.Vault(), f.root,
					f.b.public, f.b.signer, endpoint, request)
				assert.Equal(err, pw.ErrEstablishment)
				assert.SNil(response)
				assert.DeepEqual(f.snapshot(t), before)
				current, found := try.To2(pw.ReadInvitation(f.b.store.Vault(),
					f.root, f.b.public))
				assert.That(found)
				assert.DeepEqual(current, row)
				assert.SNil(try.To1(exchangeRecords(f.b.store.Vault()))[1])
				assert.SNil(try.To1(exchangeRecords(f.b.store.Vault()))[2])
			},
		)
	}
}

func TestDenyBobCannotRecallTransmittedAcceptance(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRedemption(t, true)
	f.drop = true
	assert.Equal(f.invoke().Code, 502)
	f.mu.Lock()
	assert.NoError(f.failure)
	var sent struct {
		Version    int
		Acceptance []byte
	}
	try.To(json.Unmarshal(f.responses[0], &sent))
	f.mu.Unlock()
	alice := try.To1(exchangeRecords(f.a.store.Vault()))
	denyExchangePeer(t, f.exchangeFixture, f.b, f.a.public, true)
	bob := exchangeHeldState(t, f.b.store.Vault())
	before := f.snapshot(t)
	response, err := pw.BobReply(f.b.store.Vault(), f.root, f.b.public,
		f.b.signer, f.server.URL+"/peer/introduction", alice[0])
	assert.Equal(err, pw.ErrEstablishment)
	assert.SNil(response)
	assert.DeepEqual(f.snapshot(t), before)
	// Alice's own unchanged permission authorizes these already emitted bytes.
	// This creates only her local holding, with no remote policy oracle.
	assert.That(try.To1(pw.ReceiveAcceptance(f.a.store.Vault(), f.root,
		f.a.public, f.a.signer, sent.Acceptance)))
	assert.SNotEmpty(try.To1(exchangeRecords(f.a.store.Vault()))[2])
	assert.SNotEmpty(bob["root"]["local-pw-held-v1"])
	try.To1(pw.SaveFirstUse(f.a.store.Vault(), f.root, f.a.public, f.a.signer))
	var pending observedUseRecord
	try.To(wire.UnmarshalCanonical(&pending,
		try.To1(readUseRecord(f.a.store.Vault(), aliceUseKey))))
	response, err = pw.BobFirstUse(f.b.store.Vault(), f.root, f.b.public,
		f.b.signer, pending.Request)
	assert.Equal(err, pw.ErrFirstUse)
	assert.SNil(response)
	assert.Equal(pending.State, "Await")
	assert.DeepEqual(exchangeHeldState(t, f.b.store.Vault()), bob)
}

func TestDenyRequesterPreemptsAttemptAndDelayedAcceptance(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "no attempt", true: "saved attempt"}[pending],
			func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRedemption(t, true)
				var sent struct {
					Version    int
					Acceptance []byte
				}
				if pending {
					f.drop = true
					assert.Equal(f.invoke().Code, 502)
					f.mu.Lock()
					assert.NoError(f.failure)
					try.To(json.Unmarshal(f.responses[0], &sent))
					f.mu.Unlock()
				}
				denyExchangePeer(t, f.exchangeFixture, f.a, f.b.public, true)
				before := f.snapshot(t)
				assert.Equal(
					f.invoke().Code,
					409,
				) // SaveAttempt's own current guard.
				if pending {
					accepted, err := pw.ReceiveAcceptance(
						f.a.store.Vault(),
						f.root,
						f.a.public,
						f.a.signer,
						sent.Acceptance,
					)
					assert.Equal(err, pw.ErrEstablishment)
					assert.ThatNot(accepted)
					assert.SNotEmpty(
						try.To1(exchangeRecords(f.a.store.Vault()))[0],
					)
				}
				assert.SNil(try.To1(exchangeRecords(f.a.store.Vault()))[1])
				assert.SNil(try.To1(exchangeRecords(f.a.store.Vault()))[2])
				assert.DeepEqual(f.snapshot(t), before)
			},
		)
	}
}

func TestDenyRetainsHoldingAndHistoryAcrossRestart(t *testing.T) {
	for _, role := range []string{"Alice", "Bob"} {
		for _, state := range []string{"Idle", "Await", "Ready", "Expired"} {
			t.Run(role+"/"+state, func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newFirstUseExchange(t)
				if state != "Idle" {
					f.drop = state == "Await"
					status, _ := try.To2(
						f.post(t.Context(), ownerUsePath, []byte("{}")),
					)
					want := 200
					if f.drop {
						want = 502
					}
					assert.Equal(status, want)
					f.mu.Lock()
					assert.NoError(f.failure)
					f.mu.Unlock()
					if state == "Expired" {
						assert.That(try.To1(pw.ExpireFirstUse(f.a.store.Vault(),
							f.root, f.a.public, true)))
					}
					var observed observedUseRecord
					try.To(wire.UnmarshalCanonical(&observed,
						try.To1(readUseRecord(f.a.store.Vault(), aliceUseKey))))
					assert.Equal(observed.State, state)
				}
				n, peer := f.a, f.b
				if role == "Bob" {
					n, peer = f.b, f.a
				}
				denyExchangePeer(t, f.exchangeFixture, n, peer.public, true)
				alice := exchangeHeldState(t, f.a.store.Vault())
				bob := exchangeHeldState(t, f.b.store.Vault())
				assert.SNotEmpty(alice["root"]["local-pw-held-v1"])
				assert.SNotEmpty(bob["root"]["local-pw-held-v1"])
				f.reopen(t)
				assert.DeepEqual(exchangeHeldState(t, f.a.store.Vault()), alice)
				assert.DeepEqual(exchangeHeldState(t, f.b.store.Vault()), bob)
				denyExchangePeer(t, f.exchangeFixture, n, peer.public, false)
				before := f.snapshot(t)
				if role == "Alice" {
					var accepted observedUseReceipt // Same v1 request/response array.
					try.To(wire.UnmarshalCanonical(&accepted,
						alice["root"]["local-pw-accepted-v1"]))
					held, err := pw.ReceiveAcceptance(f.a.store.Vault(), f.root,
						f.a.public, f.a.signer, accepted.Response)
					assert.Equal(err, pw.ErrEstablishment)
					assert.ThatNot(held)
					_, err = pw.SaveFirstUse(f.a.store.Vault(), f.root,
						f.a.public, f.a.signer)
					assert.Equal(err, pw.ErrFirstUse)
					if state != "Idle" {
						var receipt observedUseReceipt
						try.To(
							wire.UnmarshalCanonical(
								&receipt,
								bob["root"][bobUseKey],
							),
						)
						ready, err := pw.ReceiveFirstUse(
							f.a.store.Vault(),
							f.root,
							f.a.public,
							f.a.signer,
							receipt.Response,
						)
						assert.Equal(err, pw.ErrFirstUse)
						assert.ThatNot(ready)
					}
				} else {
					_, err := pw.BobReply(f.b.store.Vault(), f.root, f.b.public,
						f.b.signer, f.server.URL+"/peer/introduction",
						alice["root"]["local-pw-attempt-v1"])
					assert.Equal(err, pw.ErrEstablishment)
				}
				assert.DeepEqual(f.snapshot(t), before)
			})
		}
	}
}

func TestDenyBobCannotRecallTransmittedFirstUse(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseExchange(t)
	body := []byte(`{"peer_public_key_hex":"` +
		hex.EncodeToString(f.a.public) + `"}`)
	// The fixture has received Bob's authentic first-use response. Commit his
	// Deny through the same operational owner before delivering those bytes.
	f.after = func() (err error) {
		defer err2.Handle(&err, nil)
		status, response := try.To2(useHTTP(t.Context(),
			f.bobOwner.URL+ownerDenyPath, f.bobAuth, body))
		if status != 200 || string(response) != `{"changed":true}` {
			return errors.New("owner denial failed")
		}
		return nil
	}
	status, _ := try.To2(f.post(t.Context(), ownerUsePath, []byte("{}")))
	assert.Equal(status, 200)
	f.mu.Lock()
	assert.NoError(f.failure)
	f.mu.Unlock()
	assert.That(try.To1(policy.IsDenied(f.b.store.Vault(), f.root,
		f.b.public, f.a.public)))
	var observed observedUseRecord
	try.To(wire.UnmarshalCanonical(&observed,
		try.To1(readUseRecord(f.a.store.Vault(), aliceUseKey))))
	assert.Equal(observed.State, "Ready")
	// Ready is historical Alice-local evidence, not mutual current readiness.
	before := f.snapshot(t)
	response, err := pw.BobFirstUse(f.b.store.Vault(), f.root, f.b.public,
		f.b.signer, observed.Request)
	assert.Equal(err, pw.ErrFirstUse)
	assert.SNil(response)
	assert.DeepEqual(f.snapshot(t), before)
}

func TestDenyRequesterPreemptsInFlightFirstUseReady(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseExchange(t)
	assert.That(f.a.store.Vault() != f.b.store.Vault())
	alice := exchangeHeldState(t, f.a.store.Vault())
	bob := exchangeHeldState(t, f.b.store.Vault())
	for _, records := range []map[string]map[string][]byte{alice, bob} {
		assert.SNotEmpty(records["root"]["local-pw-accepted-v1"])
		assert.SNotEmpty(records["root"]["local-pw-held-v1"])
		assert.SNil(records["root"][deniedPolicyKey])
	}
	assert.SNotEmpty(alice["root"]["local-pw-attempt-v1"])
	assert.SNil(alice["root"][aliceUseKey])
	assert.SNil(bob["root"][bobUseKey])

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	body := []byte(`{"peer_public_key_hex":"` +
		hex.EncodeToString(f.b.public) + `"}`)
	var awaiting, committed, denied []byte
	// Bob has committed his receipt and authorized his response. Capture
	// both records, then commit Alice's owner Deny before forwarding it.
	f.after = func() (err error) {
		defer err2.Handle(&err, nil)
		awaiting, err = readUseRecord(f.a.store.Vault(), aliceUseKey)
		if err != nil {
			return fmt.Errorf("Alice Await before Deny: %w", err)
		}
		committed, err = readUseRecord(f.b.store.Vault(), bobUseKey)
		if err != nil {
			return fmt.Errorf("Bob receipt before Deny: %w", err)
		}
		status, response, err := useHTTP(ctx,
			f.aliceOwner.URL+ownerDenyPath, f.aliceAuth, body)
		if err != nil {
			return fmt.Errorf("Alice owner Deny: %w", err)
		}
		if status != http.StatusOK || string(response) != `{"changed":true}` {
			return fmt.Errorf("Alice owner Deny: status %d, body %q",
				status, response)
		}
		denied, err = readUseRecord(f.a.store.Vault(), deniedPolicyKey)
		if err != nil {
			return fmt.Errorf("Alice committed Deny: %w", err)
		}
		return nil
	}
	status, response := try.To2(f.post(ctx, ownerUsePath, []byte("{}")))
	f.mu.Lock()
	defer f.mu.Unlock()
	assert.NoError(f.failure)
	assert.Equal(status, http.StatusConflict)
	assert.Equal(string(response),
		"Local first use refused; peer outcome unknown\n")
	assert.Equal(len(f.requests), 1)
	assert.Equal(len(f.responses), 1)

	var pending observedUseRecord
	try.To(wire.UnmarshalCanonical(&pending, awaiting))
	assert.Equal(pending.Version, 1)
	assert.Equal(pending.State, "Await")
	assert.SNil(pending.Response)
	assert.DeepEqual(pending.Request, f.requests[0])
	var receipt observedUseReceipt
	try.To(wire.UnmarshalCanonical(&receipt, committed))
	assert.Equal(receipt.Version, 1)
	assert.DeepEqual(receipt.Request, pending.Request)
	assert.SNotEmpty(receipt.Response)
	var sent struct {
		Version  int
		Response []byte
	}
	try.To(json.Unmarshal(f.responses[0], &sent))
	assert.Equal(sent.Version, 1)
	assert.DeepEqual(sent.Response, receipt.Response)

	// Verify the exact session, establishment and Bob signature independently
	// of Alice's refusal: these valid bytes lost only her current permission.
	var request pw.SignedFirstUse
	try.To(wire.UnmarshalCanonical(&request, pending.Request))
	var accepted observedUseReceipt
	try.To(wire.UnmarshalCanonical(&accepted,
		alice["root"]["local-pw-accepted-v1"]))
	var establishment pw.SignedAccepted
	try.To(wire.UnmarshalCanonical(&establishment, accepted.Response))
	assert.DeepEqual(request.Payload.Established, establishment.Payload)
	var signed pw.SignedFirstUseResponse
	try.To(wire.UnmarshalCanonical(&signed, receipt.Response))
	assert.Equal(signed.Payload.Version, 1)
	assert.DeepEqual(signed.Payload.Request, request.Payload)
	requestDigest := key.HashTagged("pw-first-use-request-digest/v1",
		pending.Request)
	assert.DeepEqual(signed.Payload.RequestDigest, requestDigest[:])
	digest := key.HashTagged(pw.FirstUseResponsePurpose,
		try.To1(wire.Marshal(signed.Payload)))
	assert.That(signed.Signature.Verify(f.b.public, digest[:]))
	assert.That(time.Now().UnixNano() < request.Payload.ExpiresUnixNano)

	assert.SNotEmpty(denied)
	assert.That(try.To1(policy.IsDenied(f.a.store.Vault(), f.root,
		f.a.public, f.b.public)))
	assert.ThatNot(try.To1(policy.IsDenied(f.b.store.Vault(), f.root,
		f.b.public, f.a.public)))
	// Only Alice's Await/Deny and Bob's one-time receipt were added. Both
	// holdings and all establishment, invitation and unrelated bytes remain.
	alice["root"][aliceUseKey] = awaiting
	alice["root"][deniedPolicyKey] = denied
	bob["root"][bobUseKey] = committed
	assert.DeepEqual(exchangeHeldState(t, f.a.store.Vault()), alice)
	assert.DeepEqual(exchangeHeldState(t, f.b.store.Vault()), bob)

	// Re-delivery under Deny cannot write, create Ready or resurrect authority.
	// No third ACK, retry or new session follows; neither receipt grants Trust
	// or a shared persisted PWOpen.
	before := f.snapshot(t)
	ready, err := pw.ReceiveFirstUse(f.a.store.Vault(), f.root, f.a.public,
		f.a.signer, sent.Response)
	assert.Equal(err, pw.ErrFirstUse)
	assert.ThatNot(ready)
	assert.DeepEqual(f.snapshot(t), before)
	assert.DeepEqual(exchangeHeldState(t, f.a.store.Vault()), alice)
	assert.DeepEqual(exchangeHeldState(t, f.b.store.Vault()), bob)
	assert.Equal(len(f.requests), 1)
	assert.Equal(len(f.responses), 1)
}

func TestDenyAndDeleteAreDistinctLocalOperations(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseExchange(t)
	denyExchangePeer(t, f.exchangeFixture, f.a, f.b.public, true)
	// This Deny-then-Delete sequence is engineering behavior beyond the
	// invitation model's one-fault-per-Vault bound, not a refinement claim.
	deleteExchangeHolding(t, f.exchangeFixture, f.a)
	assert.That(try.To1(policy.IsDenied(f.a.store.Vault(), f.root,
		f.a.public, f.b.public)))
	denyExchangePeer(t, f.exchangeFixture, f.a, f.b.public, false)
	assert.SNil(try.To1(exchangeRecords(f.a.store.Vault()))[2])
	// Bob performs only Delete: it must not create Deny.
	deleteExchangeHolding(t, f.exchangeFixture, f.b)
	assert.ThatNot(try.To1(policy.IsDenied(f.b.store.Vault(), f.root,
		f.b.public, f.a.public)))
}
