package ownerapi

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"unicode/utf8"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/key"
)

const maxCheckResponseBytes = 4 * 1024

var errInvalidIntroduction = errors.New("invalid introduction")

type checkResponse struct {
	SubjectPublicKeyHex string `json:"subject_public_key_hex"`
	IsSelf              bool   `json:"is_self"`
}

func (h *statusHandler) serveCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeStatusError(w, http.StatusMethodNotAllowed)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" ||
		len(r.Header.Values("Content-Type")) != 1 {
		writeStatusError(w, http.StatusUnsupportedMediaType)
		return
	}

	// Authentication has already succeeded. Bound actual reads, including
	// chunked bodies and dishonest Content-Length, before decoding anything.
	data, err := io.ReadAll(
		http.MaxBytesReader(w, r.Body, maxIntroductionBytes),
	)
	if err != nil {
		status := http.StatusBadRequest
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeStatusError(w, status)
		return
	}
	document, err := decodeIntroduction(data)
	if err != nil {
		writeStatusError(w, http.StatusBadRequest)
		return
	}
	result, err := checkIntroduction(document, h.expectedRoot, h.expectedChild)
	if err != nil {
		writeStatusError(w, http.StatusBadRequest)
		return
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > maxCheckResponseBytes {
		writeStatusError(w, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	try.Out1(w.Write(encoded)).Logf("writing owner introduction check response")
}

// Decode just this concrete transfer envelope. Token decoding preserves
// duplicate field detection and distinguishes the integer 1 from 1.0 or 1e0.
func decodeIntroduction(data []byte) (_ introductionResponse, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.That(utf8.Valid(data), errInvalidIntroduction)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	assert.Equal(try.To1(decoder.Token()), json.Token(json.Delim('{')),
		errInvalidIntroduction)
	document := introductionResponse{}
	seen := make(map[string]bool, 3)
	for decoder.More() {
		name, ok := try.To1(decoder.Token()).(string)
		assert.That(ok && !seen[name], errInvalidIntroduction)
		seen[name] = true
		value := try.To1(decoder.Token())
		switch name {
		case "version":
			assert.Equal(
				value,
				json.Token(json.Number("1")),
				errInvalidIntroduction,
			)
			document.Version = 1
		case "proposal", "acceptance":
			encoded, ok := value.(string)
			assert.That(ok && encoded != "", errInvalidIntroduction)
			decoded := try.To1(base64.StdEncoding.DecodeString(encoded))
			assert.Equal(base64.StdEncoding.EncodeToString(decoded), encoded,
				errInvalidIntroduction)
			if name == "proposal" {
				document.Proposal = decoded
			} else {
				document.Acceptance = decoded
			}
		default:
			return introductionResponse{}, errInvalidIntroduction
		}
	}
	assert.Equal(try.To1(decoder.Token()), json.Token(json.Delim('}')),
		errInvalidIntroduction)
	assert.Equal(len(seen), 3, errInvalidIntroduction)
	_, end := decoder.Token()
	assert.Equal(end, io.EOF, errInvalidIntroduction)
	return document, nil
}

// Stateless inspection only: no Vault, signer, Known promotion or peer I/O.
// The Root and local identity come exclusively from copied service config.
func checkIntroduction(document introductionResponse, root, child key.Public) (
	_ checkResponse, err error,
) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	proposal := try.To1(intro.ParsePath(document.Proposal))
	assert.SLonger(proposal, 1, errInvalidIntroduction)
	assert.That(publicIntroduction(proposal), errInvalidIntroduction)
	for _, edge := range proposal {
		assert.That(edge.Body.Options.BackupKeyIndex == 0 &&
			!edge.Body.Options.Rotation, errInvalidIntroduction)
	}
	try.To(proposal.ProveFromRoot(root))
	try.To(proposal.VerifyAcceptance(document.Acceptance))

	subject := proposal.LeafPubKey()
	return checkResponse{
		SubjectPublicKeyHex: hex.EncodeToString(subject),
		IsSelf:              bytes.Equal(subject, child),
	}, nil
}
