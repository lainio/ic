package nodevault

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/ownerapi"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
)

type replyProbe struct {
	key.Handle
	acceptanceDigest []byte
	probes           int
	fail             bool
}

func (s *replyProbe) Sign(data []byte) ([]byte, error) {
	if bytes.Equal(data, s.acceptanceDigest) {
		return nil, errors.New("must not sign the saved acceptance again")
	}
	s.probes++
	if s.fail {
		return nil, errors.New("private diagnostic probe failure")
	}
	return s.Handle.Sign(data)
}

func bobHTTPReply(t *testing.T, store *Store, f fixture, listener net.Listener,
	raw []byte,
) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	records := readBobEstablishment(t, store.Vault())
	var history struct {
		_                 struct{} `cbor:",toarray"`
		Version           uint8
		Request, Response []byte
	}
	try.To(wire.UnmarshalCanonical(&history, records[1]))
	var saved pw.SignedAccepted
	try.To(wire.UnmarshalCanonical(&saved, history.Response))
	digest := key.HashTagged(pw.AcceptedPurpose,
		try.To1(wire.Marshal(saved.Payload)))
	signer := &replyProbe{Handle: f.alice, acceptanceDigest: digest[:]}
	_, _, bind := try.To3(ownerapi.NewEstablishmentCredentials(t.Context(),
		store.Vault(), f.binding.Root, f.binding.Child, signer, t.TempDir()))
	_, _, establish := bind(listener)
	handler := peerapi.NewEstablishmentHandler(
		establish,
		http.NotFoundHandler(),
	)
	body := try.To1(json.Marshal(struct {
		Version int    `json:"version"`
		Request []byte `json:"request"`
	}{1, raw}))
	before := try.To1(stateFiles(f))
	remaining := store.provider.remaining
	request := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/peer/pw/establish",
			bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	w := request()
	assert.Equal(w.Code, 200)
	var response struct {
		Version    int
		Acceptance []byte
	}
	try.To(json.Unmarshal(w.Body.Bytes(), &response))
	assert.Equal(response.Version, 1)
	assert.DeepEqual(response.Acceptance, history.Response)
	assert.Equal(signer.probes, 1)
	signer.fail = true
	failed := request()
	assert.Equal(failed.Code, 409)
	assert.Equal(failed.Body.String(), "Conflict\n")
	assert.Equal(signer.probes, 2)
	assert.Equal(store.provider.remaining, remaining)
	assert.DeepEqual(try.To1(stateFiles(f)), before)
	assert.DeepEqual(readBobEstablishment(t, store.Vault()), records)
	return bytes.Clone(w.Body.Bytes())
}
