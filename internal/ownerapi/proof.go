package ownerapi

import (
	"reflect"
	"time"

	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/key"
)

// CurrentAdProver is only the publisher half of a future online VerifyAd flow.
// The caller supplies the exact ad and its own fresh 32-byte random challenge.
// The capability creates no stored state and grants no general signing access.
type CurrentAdProver func(adCBOR, challenge []byte) (key.Signature, error)

func (h *publicationHandler) proveCurrentAd(adCBOR, challenge []byte) (key.Signature, error) {
	// Same lock as publication, bootstrap and all evidence/Known writes. It
	// spans preflight, both signatures and the final comparison, but no HTTP I/O.
	h.mutations.Lock()
	defer h.mutations.Unlock()
	if h.endpoint == "" {
		return nil, ads.ErrNotCurrent
	}
	return ads.ProveCurrentLocal(h.vault, h.root, h.child,
		proofSigner{h.signer}, h.endpoint, adCBOR, challenge, time.Now())
}

// Discard provider diagnostics before the domain layer's err2 tracing. This
// adapter changes no signing input or algorithm and remains private to the
// owner service. The peer receives only CurrentAdProver.
type proofSigner struct{ key.Handle }

func (s proofSigner) CBORPublicKey() ([]byte, error) {
	if s.Handle == nil {
		return nil, ads.ErrUnusable
	}
	value := reflect.ValueOf(s.Handle)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return nil, ads.ErrUnusable
		}
	}
	public, err := s.Handle.CBORPublicKey()
	if err != nil {
		return nil, ads.ErrUnusable
	}
	return public, nil
}

func (s proofSigner) Sign(data []byte) ([]byte, error) {
	signature, err := s.Handle.Sign(data)
	if err != nil {
		return nil, ads.ErrUnusable
	}
	return signature, nil
}
