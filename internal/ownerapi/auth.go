package ownerapi

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const ownerStatusTokenSize = 32

// NewAuthenticatedStatusHandler protects NewStatusHandler before route dispatch.
// The caller must supply exactly 32 freshly generated random bytes dedicated to
// this status credential, independent of signing keys, public identities, Vault
// secrets, and transport sessions or addresses. Only length can be validated.
// Requests must carry one Authorization: Bearer header with the case-sensitive,
// 64-character lowercase hex encoding of token. No other input grants access.
//
// The constructor owns an encoded copy of token; clearing or changing the input
// cannot change the credential. This promises no secure Go-heap erasure.
// NewStatusHandler copies the public identities and borrows the Vault without
// I/O or a signing handle. Neither handler opens/closes resources or writes state.
// Invalid token configuration returns a nil handler and a generic error.
//
// Possession permits only reading this configured status surface, not proof of
// human identity, signing-key control, enrollment, trust, or device authority.
// The owner-status-demo command mounts this protected handler on a dedicated
// loopback developer listener with a private credential file for that invocation.
// The bare constructor remains unprotected. Production owner access must protect
// provisioning/storage/transmission and establish credential lifetime. Bearer
// possession provides neither encryption nor server authentication; the demo
// does not authorize remote plaintext exposure.
func NewAuthenticatedStatusHandler(
	vault *storage.Vault,
	expectedRoot, expectedChild key.Public,
	token []byte,
) (handler http.Handler, err error) {
	if len(token) != ownerStatusTokenSize {
		return nil, errors.New("invalid owner status token configuration")
	}

	return &authenticatedStatusHandler{
		next:  NewStatusHandler(vault, expectedRoot, expectedChild),
		token: hex.EncodeToString(token),
	}, nil
}

type authenticatedStatusHandler struct {
	next  http.Handler
	token string
}

func (h *authenticatedStatusHandler) ServeHTTP(
	w http.ResponseWriter, r *http.Request,
) {
	values := r.Header.Values("Authorization")
	if len(values) == 1 {
		value := strings.Trim(values[0], " \t")
		scheme, token, separated := strings.Cut(value, " ")
		token = strings.TrimLeft(token, " ")
		// Equality with our lowercase hex encoding also rejects malformed tokens.
		if separated && strings.EqualFold(scheme, "Bearer") &&
			len(token) == hex.EncodedLen(ownerStatusTokenSize) &&
			subtle.ConstantTimeCompare([]byte(token), []byte(h.token)) == 1 {
			h.next.ServeHTTP(w, r)
			return
		}
	}

	w.Header().Set("WWW-Authenticate", `Bearer realm="owner-status"`)
	w.Header().Set("Cache-Control", "no-store")
	writeStatusError(w, http.StatusUnauthorized)
}
