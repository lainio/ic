package ownerapi

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"unicode/utf8"

	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/fxamacker/cbor/v2"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/onboarding"
)

const maxAdResponseBytes = onboarding.MaxIntroductionBytes + 4096

type adResponse struct {
	Introduction introductionResponse
	Ad           []byte
}

// A sequential ReceiveEdge projection followed by ReceiveAdClaim. The HTTP
// response cannot establish AuthenticAds/CurrentAd, and the two primitives do
// not share a transaction. This is neither atomic/full ReadAd nor VerifyAd.
func (h *publicationHandler) serveFetchAd(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawPath != "" || r.URL.Opaque != "" {
		writeStatusError(w, http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeStatusError(w, http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || r.URL.RawFragment != "" {
		writeStatusError(w, http.StatusBadRequest)
		return
	}
	endpoint, ok := readFetchRequest(w, r, "/peer/ad")
	if !ok {
		return
	}
	data, err := fetchPeerDocument(r.Context(), endpoint, maxAdResponseBytes)
	if err != nil {
		writeStatusError(w, http.StatusBadGateway)
		return
	}
	document, err := decodeAdResponse(data)
	if err != nil {
		writeStatusError(w, http.StatusBadGateway)
		return
	}
	if !quietIntroductionShape(document.Introduction.Proposal) {
		writeStatusError(w, http.StatusBadGateway)
		return
	}
	subject, err := onboarding.CheckIntroduction(
		document.Introduction.Proposal, document.Introduction.Acceptance, h.root,
	)
	if err != nil || ads.ValidateClaim(h.root, subject, document.Ad) != nil {
		writeStatusError(w, http.StatusBadGateway)
		return
	}
	if bytes.Equal(subject, h.child) {
		writeStatusError(w, http.StatusBadRequest)
		return
	}
	// All network reads, decoding, and admission checks precede the mutation
	// lock and either Vault transaction. Borrow the service's already open Vault.
	h.mutations.Lock()
	defer h.mutations.Unlock()
	if r.Context().Err() != nil {
		writeStatusError(w, http.StatusBadGateway)
		return
	}
	_, created, err := onboarding.SaveIntroduction(
		h.vault, h.root, document.Introduction.Proposal, document.Introduction.Acceptance,
	)
	if err != nil {
		writeAdReceiptError(w, err)
		return
	}
	changed, err := ads.ReceiveClaim(h.vault, h.root, subject, document.Ad)
	if err != nil {
		// Introduction evidence may already be committed. Preserve it and
		// allow an explicit retry; never roll back by deleting earlier receipts.
		writeAdReceiptError(w, err)
		return
	}
	encoded, err := json.Marshal(struct {
		SubjectPublicKeyHex string `json:"subject_public_key_hex"`
		IntroductionCreated bool   `json:"introduction_created"`
		AdChanged           bool   `json:"ad_changed"`
	}{hex.EncodeToString(subject), created, changed})
	if err != nil {
		writeStatusError(w, http.StatusInternalServerError)
		return
	}
	// Both commits can also precede a lost acknowledgement. No automatic retry.
	writeIntroductionResult(w, encoded)
}

// The existing proof helpers trace CBOR errors, which can contain offending
// map keys. Preflight decoding without tracing before calling those helpers.
// This authenticates nothing; CheckIntroduction remains the admission policy.
func quietIntroductionShape(proposal []byte) bool {
	var path intro.Path
	if wire.DecMode.Unmarshal(proposal, &path) != nil {
		return false
	}
	for _, edge := range path {
		var public webauthncose.EC2PublicKeyData
		if cbor.Unmarshal(edge.Public(), &public) != nil {
			return false
		}
	}
	return true
}

func writeAdReceiptError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, onboarding.ErrDifferentIntroduction),
		errors.Is(err, onboarding.ErrIntroductionsFull), errors.Is(err, ads.ErrReceivedClaimsFull):
		status = http.StatusConflict
	case errors.Is(err, onboarding.ErrInvalidIntroduction), errors.Is(err, ads.ErrInvalidClaim):
		status = http.StatusBadGateway
	}
	writeStatusError(w, status)
}

// Decode the exact peer envelope, retaining the inner bytes unchanged. Raw
// decoder errors and peer-controlled tokens never enter err2 diagnostics.
func decodeAdResponse(data []byte) (_ adResponse, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errPeerFetch })

	assert.That(len(data) <= maxAdResponseBytes && utf8.Valid(data), errPeerFetch)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	assert.That(try.To1(introductionToken(decoder)) == json.Delim('{'), errPeerFetch)
	var document adResponse
	seen := make(map[string]bool, 3)
	for decoder.More() {
		name, ok := try.To1(introductionToken(decoder)).(string)
		assert.That(ok && !seen[name], errPeerFetch)
		seen[name] = true
		switch name {
		case "version":
			assert.That(try.To1(introductionToken(decoder)) == json.Number("1"), errPeerFetch)
		case "introduction":
			var nested json.RawMessage
			assert.That(decoder.Decode(&nested) == nil && len(nested) <= maxIntroductionBytes, errPeerFetch)
			document.Introduction = try.To1(decodeIntroduction(nested))
		case "ad":
			encoded, ok := try.To1(introductionToken(decoder)).(string)
			assert.That(ok && encoded != "", errPeerFetch)
			decoded, decodeErr := base64.StdEncoding.DecodeString(encoded)
			assert.That(decodeErr == nil && base64.StdEncoding.EncodeToString(decoded) == encoded, errPeerFetch)
			document.Ad = decoded // ValidateClaim enforces the existing 1024-byte policy.
		default:
			return adResponse{}, errPeerFetch
		}
	}
	assert.That(try.To1(introductionToken(decoder)) == json.Delim('}') && len(seen) == 3, errPeerFetch)
	_, end := decoder.Token()
	assert.That(end == io.EOF, errPeerFetch)
	return document, nil
}
