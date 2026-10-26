package ads

import (
	"bytes"
	"crypto/ecdh"
	"math"
	"strings"
	"time"

	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/localhttp"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const (
	maxEndpointBytes = 256
	maxRecordBytes   = 1024
	maxPublicBytes   = 128
)

func normalizeEndpoint(value string) (_ string, err error) {
	defer err2.Handle(&err, func(error) error { return ErrInvalidInput })

	const prefix, path = "http://", "/peer/introduction"
	if len(value) > maxEndpointBytes ||
		!strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, path) ||
		strings.ContainsAny(value, "%?#@\\") {
		return "", ErrInvalidInput
	}
	address := strings.TrimSuffix(strings.TrimPrefix(value, prefix), path)
	return prefix + try.To1(localhttp.Address(address, false)) + path, nil
}

func validateInputs(vault *storage.Vault, root, local key.Public,
	now time.Time,
) (err error) {
	defer err2.Handle(&err, nil)

	if vault == nil {
		return ErrInvalidInput
	}
	try.To(validatePublic(root))
	try.To(validatePublic(local))
	return validateTime(now)
}

func validateTime(value time.Time) error {
	// Unix nanoseconds must round-trip: 1970 through int64's 2262 limit.
	if value.IsZero() || value.Before(time.Unix(0, 0)) ||
		value.After(time.Unix(0, math.MaxInt64)) {
		return ErrInvalidInput
	}
	return nil
}

func validatePublic(public key.Public) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return ErrInvalidInput })

	assert.That(
		len(public) > 0 && len(public) <= maxPublicBytes,
		ErrInvalidInput,
	)
	var decoded webauthncose.EC2PublicKeyData
	try.To(wire.UnmarshalCanonical(&decoded, public))
	assert.That(decoded.KeyType == int64(webauthncose.EllipticKey) &&
		decoded.Algorithm == int64(webauthncose.AlgES256) &&
		decoded.Curve == int64(webauthncose.P256), ErrInvalidInput)
	// The existing software signer encodes coordinates with big.Int.Bytes,
	// so leading zero octets may be omitted. Preserve its exact public bytes.
	assert.That(len(decoded.XCoord) > 0 && len(decoded.XCoord) <= 32 &&
		len(decoded.YCoord) > 0 && len(decoded.YCoord) <= 32, ErrInvalidInput)
	var point [65]byte
	point[0] = 4 // Uncompressed P-256 point; NewPublicKey checks curve membership.
	copy(point[33-len(decoded.XCoord):33], decoded.XCoord)
	copy(point[65-len(decoded.YCoord):], decoded.YCoord)
	try.To1(ecdh.P256().NewPublicKey(point[:]))
	return nil
}

func decodeCurrent(
	record []byte,
	root, local key.Public,
) (_ Current, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return ErrInvalidRecord })

	assert.That(
		len(record) > 0 && len(record) <= maxRecordBytes,
		ErrInvalidRecord,
	)
	var current Current
	try.To(wire.UnmarshalCanonical(&current, record))
	ad := current.Payload
	assert.That(ad.Version == 1 && ad.Slot == 1 && ad.Epoch == 0 &&
		bytes.Equal(ad.Root, root) && bytes.Equal(ad.Node, local) &&
		bytes.Equal(ad.Device, local) && len(ad.Token) == 32 &&
		ad.ExpiresUnixNano >= int64(TTL), ErrInvalidRecord)
	endpoint := try.To1(normalizeEndpoint(ad.PeerIntroductionURL))
	assert.Equal(endpoint, ad.PeerIntroductionURL, ErrInvalidRecord)
	// P-256 ASN.1 signatures fit in 72 bytes. Verify with the pinned key,
	// never signer.Verify or a key selected from the stored record.
	assert.That(len(current.Signature) > 0 && len(current.Signature) <= 72,
		ErrInvalidRecord)
	digest := key.HashTagged(SignaturePurpose, try.To1(wire.Marshal(ad)))
	assert.That(current.Signature.Verify(local, digest[:]), ErrInvalidRecord)
	return current, nil
}
