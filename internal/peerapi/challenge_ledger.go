package peerapi

import (
	"crypto/sha256"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/lainio/ic/key"
)

const (
	challengeTTL  = 30 * time.Second
	maxChallenges = 32
)

type challengeEntry struct {
	requester string
	adDigest  [32]byte
	expires   time.Time
}

// Private to one challengeHandler and therefore one immutable Root/acceptor/
// bound-endpoint context. No goroutines, durable records or process globals.
// Clock and randomness injection exist only here for deterministic tests.
type challengeLedger struct {
	mu      sync.Mutex
	entries map[[32]byte]challengeEntry
	now     func() time.Time
	random  io.Reader
}

func (l *challengeLedger) issue(
	requester key.Public,
	ad []byte,
) ([]byte, time.Time, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.prune(now)
	if len(l.entries) >= maxChallenges {
		return nil, time.Time{}, http.StatusTooManyRequests
	}
	for range 3 {
		var nonce [32]byte
		if _, err := io.ReadFull(l.random, nonce[:]); err != nil {
			return nil, time.Time{}, http.StatusInternalServerError
		}
		if _, collision := l.entries[nonce]; collision {
			continue
		}
		expires := now.Add(challengeTTL)
		l.entries[nonce] = challengeEntry{
			requester: string(requester), adDigest: sha256.Sum256(ad),
			expires: expires,
		}
		return nonce[:], expires, 0
	}
	return nil, time.Time{}, http.StatusInternalServerError
}

// consumeChallenge checks only a nonce binding, atomically and at most once.
// The acceptance handler must first authenticate requester-owned key control with
// pw.VerifyLocalAcceptanceProof(root, requester, local, nonce, requesterProof),
// and obtain currentAd from a fresh local read under this handler's pinned
// identities/endpoint. It MUST recheck Known, Deny, device usability and ad
// currentness before signing, and bind the response to the live transcript.
// Neither a nonce nor its consumption is bearer authority or acceptance.
// This primitive is intentionally private and has no standalone HTTP route.
func (h *challengeHandler) consumeChallenge(
	requester key.Public,
	currentAd, nonce []byte,
) bool {
	l := &h.challenges
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(l.now())
	if len(nonce) != 32 {
		return false
	}
	id := [32]byte(nonce)
	entry, found := l.entries[id]
	if !found || entry.requester != string(requester) ||
		entry.adDigest != sha256.Sum256(currentAd) {
		return false
	}
	delete(l.entries, id)
	return true
}

func (l *challengeLedger) prune(now time.Time) {
	for nonce, entry := range l.entries {
		if !now.Before(entry.expires) {
			delete(l.entries, nonce)
		}
	}
}
