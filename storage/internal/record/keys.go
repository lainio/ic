package record

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
)

// derive returns independently owned encryption and index keys for a vault/key
// generation. Namespaces do not participate. The caller provisions the secret;
// this helper neither assesses entropy nor converts passwords.
func derive(secret []byte, vault, id [16]byte) (ke, ki []byte, err error) {
	defer err2.Handle(&err, nil)
	if len(secret) != 32 {
		return nil, nil, errFormat
	}
	var keys [2][]byte
	for i, label := range [...]string{"ms/v1/enc", "ms/v1/idx"} {
		// All three field lengths are fixed and bounded before allocation.
		info := make([]byte, 0, 4+len(label)+4+len(vault)+4+len(id))
		for _, field := range [][]byte{[]byte(label), vault[:], id[:]} {
			info = binary.BigEndian.AppendUint32(info, uint32(len(field)))
			info = append(info, field...)
		}
		keys[i] = try.To1(hkdf.Key(sha256.New, secret, []byte("ms/v1/hkdf"), string(info), 32))
	}
	return keys[0], keys[1], nil
}

// lookupToken returns all 32 raw HMAC bytes. It validates inputs before hashing
// and neither retains key material nor verifies a stored record's identity.
func lookupToken(ki, context []byte, id [16]byte, key []byte) (token [32]byte, err error) {
	defer err2.Handle(&err, nil)
	if len(ki) != 32 || len(key) == 0 || len(key) > maxKeySize {
		return token, errFormat
	}
	try.To(checkContext(context))
	const label = "ms/v1/lookup"
	message := make([]byte, 0, 4+len(label)+4+len(context)+4+len(id)+4+len(key))
	for _, field := range [][]byte{[]byte(label), context, id[:], key} {
		message = binary.BigEndian.AppendUint32(message, uint32(len(field)))
		message = append(message, field...)
	}
	mac := hmac.New(sha256.New, ki)
	try.To1(mac.Write(message))
	return [32]byte(mac.Sum(nil)), nil
}
