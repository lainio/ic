package ads

import (
	"bytes"
	"crypto/ecdh"
	"math"
	"net/netip"
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

	current := try.To1(decodeAdShape(record, root, local))
	// Local publications still require both the publisher's time range and
	// independent signature authentication. Shape admission alone is not this.
	assert.That(current.Payload.ExpiresUnixNano >= int64(TTL), ErrInvalidRecord)
	digest := key.HashTagged(SignaturePurpose, try.To1(wire.Marshal(current.Payload)))
	assert.That(current.Signature.Verify(local, digest[:]), ErrInvalidRecord)
	return current, nil
}

// decodeAdShape admits only the development v1 layout under independent public
// identities. It checks neither signature authenticity nor freshness/currentness.
// A successful result must never be treated as VerifiedAd or reachability.
func decodeAdShape(record []byte, root, subject key.Public) (_ Current, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return ErrInvalidRecord })

	assert.That(
		len(record) > 0 && len(record) <= maxRecordBytes,
		ErrInvalidRecord,
	)
	var current Current
	assert.That(wire.UnmarshalCanonical(&current, record) == nil, ErrInvalidRecord)
	ad := current.Payload
	assert.That(ad.Version == 1 && ad.Slot == 1 && ad.Epoch == 0 &&
		bytes.Equal(ad.Root, root) && bytes.Equal(ad.Node, subject) &&
		bytes.Equal(ad.Device, subject) && len(ad.Token) == 32 &&
		ad.ExpiresUnixNano >= 0, ErrInvalidRecord)
	try.To(validatePublic(root))
	try.To(validatePublic(subject))
	assert.That(normalizedClaimEndpoint(ad.PeerIntroductionURL), ErrInvalidRecord)
	// P-256 ASN.1 signatures fit in 72 bytes; contents remain untrusted here.
	assert.That(len(current.Signature) > 0 && len(current.Signature) <= 72,
		ErrInvalidRecord)
	return current, nil
}

// Receipt accepts only the normalizer's canonical literal loopback output.
// Parse failures stay local: localhttp.Address traces its underlying errors,
// which can include an untrusted address or port.
func normalizedClaimEndpoint(value string) bool {
	const prefix, path = "http://", "/peer/introduction"
	if len(value) > maxEndpointBytes || !strings.HasPrefix(value, prefix) ||
		!strings.HasSuffix(value, path) || strings.Contains(value, "%") {
		return false
	}
	address := strings.TrimSuffix(strings.TrimPrefix(value, prefix), path)
	parsed, err := netip.ParseAddrPort(address)
	return err == nil && parsed.Port() != 0 && parsed.Addr().IsLoopback() &&
		value == prefix+netip.AddrPortFrom(parsed.Addr().Unmap(), parsed.Port()).String()+path
}
