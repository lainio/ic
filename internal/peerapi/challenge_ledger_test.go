package peerapi

import (
	"bytes"
	"crypto/rand"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
)

func TestChallengeConsumeExactBindingOnce(t *testing.T) {
	defer assert.PushTester(t)()
	public, ad, _ := proofInput(t)
	requester := key.Public(try.To1(key.New().CBORPublicKey()))
	h := boundaryChallengeHandler(public)
	now := time.Now()
	h.challenges.now = func() time.Time { return now }
	inputKey, inputAd := bytes.Clone(requester), bytes.Clone(ad)
	nonce, expires, status := h.challenges.issue(inputKey, inputAd)
	assert.Equal(status, 0)
	assert.Equal(expires, now.Add(30*time.Second))
	clear(inputKey)
	clear(inputAd)
	otherNonce := bytes.Clone(nonce)
	otherNonce[0] ^= 1
	otherAd := bytes.Clone(ad)
	otherAd[0] ^= 1
	for _, tc := range []struct{ requester, ad, nonce []byte }{
		{public, ad, nonce}, {requester, otherAd, nonce},
		{requester, ad, otherNonce}, {requester, ad, nonce[:31]},
		{requester, ad, append(bytes.Clone(nonce), 0)},
	} {
		assert.ThatNot(h.consumeChallenge(tc.requester, tc.ad, tc.nonce))
		assert.Equal(len(h.challenges.entries), 1)
	}
	// Same configured identities and endpoint still mean a fresh invocation.
	fresh := boundaryChallengeHandler(public)
	assert.ThatNot(fresh.consumeChallenge(requester, ad, nonce))
	assert.That(h.consumeChallenge(requester, ad, nonce))
	assert.ThatNot(h.consumeChallenge(requester, ad, nonce))
	assert.MEmpty(h.challenges.entries)
}

func TestChallengeLedgerCapacityExpiryAndFailure(t *testing.T) {
	defer assert.PushTester(t)()
	public, ad, _ := proofInput(t)
	requester := key.Public(try.To1(key.New().CBORPublicKey()))
	h := boundaryChallengeHandler(public)
	now := time.Now()
	h.challenges.now = func() time.Time { return now }
	seen := make(map[string]bool)
	var first []byte
	for i := range 32 {
		nonce, _, status := h.challenges.issue(requester, ad)
		assert.Equal(status, 0)
		assert.SLen(nonce, 32)
		assert.ThatNot(seen[string(nonce)])
		seen[string(nonce)] = true
		if i == 0 {
			first = nonce
		}
	}
	assert.Equal(len(h.challenges.entries), 32)
	h.challenges.random = nil // Full refusal must not consult randomness.
	nonce, expires, status := h.challenges.issue(requester, ad)
	assert.Equal(status, http.StatusTooManyRequests)
	assert.SNil(nonce)
	assert.That(expires.IsZero())
	now = now.Add(challengeTTL - time.Nanosecond)
	assert.That(h.consumeChallenge(requester, ad, first))
	now = now.Add(time.Nanosecond)
	assert.ThatNot(h.consumeChallenge(requester, ad, first))
	assert.MEmpty(h.challenges.entries) // Even a failed check prunes expiry.
	h.challenges.random = rand.Reader
	nonce, _, status = h.challenges.issue(requester, ad)
	assert.Equal(status, 0)
	now = now.Add(challengeTTL)
	assert.ThatNot(h.consumeChallenge(requester, ad, nonce))
	assert.MEmpty(h.challenges.entries)
	_, _, status = h.challenges.issue(requester, ad)
	assert.Equal(status, 0)
	now = now.Add(challengeTTL)
	_, _, status = h.challenges.issue(requester, ad)
	assert.Equal(status, 0)
	assert.Equal(len(h.challenges.entries), 1) // Issuance also prunes expiry.
}

func TestChallengeRandomFailureAndBoundedCollisions(t *testing.T) {
	defer assert.PushTester(t)()
	public, ad, _ := proofInput(t)
	requester := key.Public(try.To1(key.New().CBORPublicKey()))
	h := boundaryChallengeHandler(public)
	for _, input := range [][]byte{nil, bytes.Repeat([]byte{1}, 31)} {
		h.challenges.random = bytes.NewReader(input)
		nonce, expires, status := h.challenges.issue(requester, ad)
		assert.Equal(status, 500)
		assert.SNil(nonce)
		assert.That(expires.IsZero())
		assert.MEmpty(h.challenges.entries)
	}
	first := bytes.Repeat([]byte{1}, 32)
	second := bytes.Repeat([]byte{2}, 32)
	h.challenges.random = bytes.NewReader(first)
	nonce, _, status := h.challenges.issue(requester, ad)
	assert.Equal(status, 0)
	assert.DeepEqual(nonce, first)
	collisions := bytes.NewReader(bytes.Repeat(first, 4))
	h.challenges.random = collisions
	nonce, expires, status := h.challenges.issue(requester, ad)
	assert.Equal(status, 500)
	assert.SNil(nonce)
	assert.That(expires.IsZero())
	assert.Equal(collisions.Len(), 32) // Exactly three attempts, no retry loop.
	assert.Equal(len(h.challenges.entries), 1)
	h.challenges.random = io.MultiReader(
		bytes.NewReader(first),
		bytes.NewReader(second),
	)
	nonce, _, status = h.challenges.issue(requester, ad)
	assert.Equal(status, 0)
	assert.DeepEqual(nonce, second)
	// An error after a collision must preserve the outstanding original.
	h.challenges.random = bytes.NewReader(first)
	_, _, status = h.challenges.issue(requester, ad)
	assert.Equal(status, 500)
	assert.Equal(len(h.challenges.entries), 2)
	assert.That(h.consumeChallenge(requester, ad, first))
	assert.That(h.consumeChallenge(requester, ad, second))
}

func TestChallengeConcurrentCapacityAndConsume(t *testing.T) {
	defer assert.PushTester(t)()
	public, ad, _ := proofInput(t)
	requester := key.Public(try.To1(key.New().CBORPublicKey()))
	h := boundaryChallengeHandler(public)
	type issued struct {
		nonce  []byte
		status int
	}
	results := make(chan issued, 64)
	var workers sync.WaitGroup
	for range 64 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			nonce, _, status := h.challenges.issue(requester, ad)
			results <- issued{nonce, status}
		}()
	}
	workers.Wait()
	close(results)
	seen := make(map[string]bool)
	var nonce []byte
	for result := range results {
		if result.status == 0 {
			assert.ThatNot(seen[string(result.nonce)])
			seen[string(result.nonce)] = true
			nonce = result.nonce
		} else {
			assert.Equal(result.status, 429)
			assert.SNil(result.nonce)
		}
	}
	assert.Equal(len(seen), 32)
	consumed := make(chan bool, 32)
	for range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			consumed <- h.consumeChallenge(requester, ad, nonce)
		}()
	}
	workers.Wait()
	close(consumed)
	successes := 0
	for success := range consumed {
		if success {
			successes++
		}
	}
	assert.Equal(successes, 1)
	assert.Equal(len(h.challenges.entries), 31)
}
