package peerapi

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// Each handler owns one ledger. Its copied Root/local keys and actual bound
// endpoint are immutable context, never selectors supplied by a request.
type challengeHandler struct {
	vault       *storage.Vault
	root, local key.Public
	endpoint    string
	next        http.Handler
	challenges  challengeLedger
	accept      func(key.Public, []byte, []byte) (key.Signature, error)
}

// NewChallengeHandler adds only POST /peer/pw/challenge to the existing peer
// handler. Construct once after binding the opted-in peer listener. It borrows
// the Vault, receives no signer, and creates only bounded invocation memory.
// A challenge is not requester authentication, consent, or any V19 authority
// variable. Without NewAcceptanceHandler there is no acceptance endpoint.
// Neither handler performs outbound I/O or modeled writes.
func NewChallengeHandler(vault *storage.Vault, root, local key.Public,
	boundPeerIntroURL string, next http.Handler,
) http.Handler {
	return &challengeHandler{
		vault: vault, root: bytes.Clone(root), local: bytes.Clone(local),
		endpoint: boundPeerIntroURL, next: next,
		challenges: challengeLedger{
			entries: make(map[[32]byte]challengeEntry),
			now:     time.Now, random: rand.Reader,
		},
	}
}

func (h *challengeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/peer/pw/accept" && h.endpoint != "" && h.accept != nil {
		h.serveAcceptance(w, r)
		return
	}
	if r.URL.Path != "/peer/pw/challenge" || h.endpoint == "" {
		h.next.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	fail := func(status int) { http.Error(w, http.StatusText(status), status) }
	if r.URL.RawPath != "" || r.URL.Opaque != "" {
		fail(http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		fail(http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery ||
		r.URL.Fragment != "" || r.URL.RawFragment != "" {
		fail(http.StatusBadRequest)
		return
	}
	requester, ad, status := readChallengeRequest(w, r)
	if status != 0 {
		fail(status)
		return
	}
	if bytes.Equal(requester, h.local) || !validChallengeRequester(requester) ||
		!h.authenticChallengeAd(ad) {
		fail(http.StatusBadRequest)
		return
	}
	if status := h.challengePreflight(requester, ad); status != 0 {
		fail(status)
		return
	}
	nonce, expires, status := h.challenges.issue(requester, ad)
	if status != 0 {
		fail(status)
		return
	}
	document, err := json.Marshal(struct {
		Version         int    `json:"version"`
		Challenge       []byte `json:"challenge"`
		ExpiresUnixNano int64  `json:"expires_unix_nano"`
	}{1, nonce, expires.UnixNano()})
	if err != nil || len(document) > 1024 {
		fail(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// Lost responses leave only an expiring nonce, never recoverable authority.
	// No retry, diagnostic, signing or durable write follows a failed response.
	_, _ = w.Write(document)
}

// Shape admission is deliberately separate from authentication in ads. Check
// both here, before touching local state, without accepting a caller proof.
func (h *challengeHandler) authenticChallengeAd(ad []byte) bool {
	if ads.ValidateClaim(h.root, h.local, ad) != nil {
		return false
	}
	var current ads.Current
	if wire.DecMode.Unmarshal(ad, &current) != nil {
		return false
	}
	payload, err := wire.Marshal(current.Payload)
	if err != nil {
		return false
	}
	digest := key.HashTagged(ads.SignaturePurpose, payload)
	return current.Signature.Verify(h.local, digest[:])
}

func (h *challengeHandler) challengePreflight(
	requester key.Public,
	ad []byte,
) int {
	if status := h.currentChallengeAd(ad); status != 0 {
		return status
	}
	known, err := onboarding.ListKnownIntroductions(h.vault, h.root)
	if err != nil {
		return http.StatusInternalServerError
	}
	ownKnown, peerKnown := bytes.Equal(h.root, h.local), false
	for _, subject := range known {
		ownKnown = ownKnown || bytes.Equal(subject, h.local)
		peerKnown = peerKnown || bytes.Equal(subject, requester)
	}
	denied, err := policy.IsDenied(h.vault, h.root, h.local, requester)
	if err != nil {
		return http.StatusInternalServerError
	}
	if !ownKnown || !peerKnown || denied {
		return http.StatusConflict
	}
	// These momentary reads only reduce unnecessary issuance. A later exchange
	// must recheck Known, Deny, current ad and device usability before signing.
	return 0
}

func (h *challengeHandler) currentChallengeAd(ad []byte) int {
	current, found, err := ads.ReadCurrentLocal(
		h.vault, h.root, h.local, time.Now())
	if err != nil {
		return http.StatusInternalServerError
	}
	if !found || current.Payload.PeerIntroductionURL != h.endpoint {
		return http.StatusConflict
	}
	canonical, err := wire.Marshal(current)
	if err != nil {
		return http.StatusInternalServerError
	}
	if !bytes.Equal(canonical, ad) {
		return http.StatusConflict
	}
	return 0
}

// Match the existing canonical COSE ES256/P-256 profile, including shortened
// coordinates emitted by the installed signer. No decoder diagnostics escape.
func validChallengeRequester(public key.Public) bool {
	if len(public) == 0 || len(public) > 128 {
		return false
	}
	var decoded webauthncose.EC2PublicKeyData
	if wire.DecMode.Unmarshal(public, &decoded) != nil {
		return false
	}
	canonical, err := wire.EncMode.Marshal(decoded)
	if err != nil || !bytes.Equal(public, canonical) ||
		decoded.KeyType != int64(webauthncose.EllipticKey) ||
		decoded.Algorithm != int64(webauthncose.AlgES256) ||
		decoded.Curve != int64(webauthncose.P256) ||
		len(decoded.XCoord) == 0 || len(decoded.XCoord) > 32 ||
		len(decoded.YCoord) == 0 || len(decoded.YCoord) > 32 {
		return false
	}
	var point [65]byte
	point[0] = 4
	copy(point[33-len(decoded.XCoord):33], decoded.XCoord)
	copy(point[65-len(decoded.YCoord):], decoded.YCoord)
	_, err = ecdh.P256().NewPublicKey(point[:])
	return err == nil
}

func decodeRequesterHex(value string) (key.Public, bool) {
	if len(value) == 0 || len(value) > 2*128 {
		return nil, false
	}
	public, err := hex.DecodeString(value)
	return public, err == nil && hex.EncodeToString(public) == value
}
