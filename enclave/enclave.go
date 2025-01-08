/*
Package enclave is a server-side Secure Enclave. It offers a secure and sealed
storage to store ... TODO
*/
package enclave

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"slices"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/findy-network/findy-common-go/crypto"
	"github.com/findy-network/findy-common-go/crypto/db"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/chain"
	"github.com/lainio/ic/identity"
	"github.com/lainio/ic/key"
)

type bucket = byte

const (
	userBucket bucket = iota
	userIDCountBucket
)

var (
	buckets = [][]byte{
		{userBucket},
		{userIDCountBucket},
	}
	sealedBoxFilename string

	// Key must be set from production environment, SHA-256, 32 bytes
	hexKey    = "15308490f1e4026284594dd08d31291bc8ef2aeac730d0daf6ff87bb92d4336c"
	theCipher *crypto.Cipher
)

func Close() (err error) {
	return db.Close()
}

// InitSealedBox initialize enclave's sealed box. This must be called once
// during the app life cycle.
func InitSealedBox(filename, backupName, key string) (err error) {
	defer err2.Handle(&err)

	gob.Register(User{})
	if key == "" {
		key = hexKey
	}
	k, _ := hex.DecodeString(key)
	theCipher = crypto.NewCipher(k)
	glog.V(1).Infoln("init enclave", filename)
	sealedBoxFilename = filename
	if backupName == "" {
		backupName = "backup-" + sealedBoxFilename
	}
	try.To(db.Init(db.Cfg{
		Filename:   sealedBoxFilename,
		BackupName: backupName,
		Buckets:    buckets,
	}))
	userIDCount = try.To1(GetUserIDCount())
	return nil
}

// WipeSealedBox closes and destroys the enclave permanently. This version only
// removes the sealed box file. In the future we might add sector wiping
// functionality.
func WipeSealedBox() {
	err := db.Wipe()
	if err != nil {
		glog.Error(err.Error())
	}
}

func BackupTicker(interval time.Duration) (done chan<- struct{}) {
	return db.BackupTicker(interval)
}

// PutUser saves the user to database.
func PutUser(u User) (err error) {
	defer err2.Handle(&err)

	try.To(db.AddKeyValueToBucket(buckets[userBucket],
		&db.Data{
			Data: u.Data(),
			Read: encrypt,
		},
		&db.Data{
			Data: u.Key(),
			Read: hash,
		},
	))

	return nil
}

// GetUser returns user by name if exists in enclave
func GetUser(id uint32) (u User, exist bool, err error) {
	defer err2.Handle(&err)

	value := &db.Data{
		Write: decrypt,
	}
	already := try.To1(db.GetKeyValueFromBucket(buckets[userBucket],
		&db.Data{
			Data: uint32ToBytes(id),
			Read: hash,
		},
		value,
	))
	if !already {
		return u, already, err
	}

	return NewUserFromData(value.Data), already, err
}

// GetExistingUser returns user by name if exists in enclave
func GetExistingUser(id uint32) (u User, err error) {
	defer err2.Handle(&err)

	u, already := try.To2(GetUser(id))

	if !already {
		return u, fmt.Errorf("user (%v) not exist", id)
	}

	return u, err
}

func RemoveUser(id uint32) (err error) {
	defer err2.Handle(&err)

	_ = try.To1(GetExistingUser(id))
	return db.RmKeyValueFromBucket(
		buckets[userBucket], &db.Data{
			Data: uint32ToBytes(id),
			Read: hash,
		})
}

func GetAllUsers() (users []User, err error) {
	defer err2.Handle(&err)

	us := try.To1(db.GetAllValuesFromBucket(buckets[userBucket],
		decrypt,
	))
	if len(us) == 0 {
		return
	}

	users = make([]User, len(us))
	for i, v := range us {
		users[i] = NewUserFromData(v)
	}
	slices.SortFunc(users, UserSort)

	return
}

func UserSort(a, b User) int {
	if a.ID < b.ID {
		return -1
	} else if a.ID > b.ID {
		return 1
	}
	return 0
}

func PutUserIDCount() (err error) {
	defer err2.Handle(&err)

	userID := []byte{01}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, userIDCount)

	try.To(db.AddKeyValueToBucket(
		buckets[userIDCountBucket],
		&db.Data{
			Data: b,
			Read: encrypt,
		},
		&db.Data{
			Data: userID,
			Read: hash,
		},
	))

	return nil
}

func GetUserIDCount() (count uint32, err error) {
	defer err2.Handle(&err)

	userID := []byte{01}
	value := &db.Data{
		Write: decrypt,
	}
	already := try.To1(db.GetKeyValueFromBucket(
		buckets[userIDCountBucket],
		&db.Data{
			Data: userID,
			Read: hash,
		},
		value,
	))
	if !already {
		return 0, nil
	}

	return binary.LittleEndian.Uint32(value.Data), nil
}

// all of the following has same signature. They also panic on error

// hash makes the cryptographic hash of the map key value. This prevents us to
// store key value index (email, DID) to the DB aka sealed box as plain text.
// Please use salt when implementing this.
func hash(key []byte) (k []byte) {
	h := sha256.Sum256(key)
	return h[:]
}

// encrypt encrypts the actual wallet key value. This is used when data is
// stored do the DB aka sealed box.
func encrypt(value []byte) (k []byte) {
	return theCipher.TryEncrypt(value)
}

// decrypt decrypts the actual wallet key value. This is used when data is
// retrieved from the DB aka sealed box.
func decrypt(value []byte) (k []byte) {
	return theCipher.TryDecrypt(value)
}

// noop function if need e.g. tests
func _(value []byte) (k []byte) {
	println("noop called!")
	return value
}

var (
	userIDCount uint32
)

type RoleInfo struct {
	ID      uint32
	KeyInfo key.Info
}

// User is data type for our Identities. It works as a wrapper for [identity]
// and helps us store them to DB. Public members are for GOB serialization.
// TODO: We could have UserRaw the help us keep User clean.
type User struct {
	RoleInfo

	IdentityCBOR []byte

	identity *identity.Identity
}

func (u User) Data() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	try.To(enc.Encode(u))
	return buf.Bytes()
}

func (u User) Key() []byte {
	return uint32ToBytes(u.ID)
}

func (u User) IdentityStr() string {
	return base58.Encode(u.identity.Bytes())
}

func (u *User) SetIdentityFromStr(idStr string) {
	d := base58.Decode(idStr)
	id := identity.NewFromData(d, key.NewFromInfo(u.KeyInfo))
	u.identity = &id
}

func (u User) Identity() *identity.Identity {
	return u.identity
}

func (u *User) SetIdentity(id *identity.Identity) {
	u.identity = id
}

func uint32ToBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func NewUser(flags ...chain.Opts) User {
	kh := key.New()
	var id identity.Identity

	if len(flags) > 0 {
		id = identity.NewRoot(kh, flags...)
	} else {
		id = identity.New(kh)
	}

	atomic.AddUint32(&userIDCount, 1)
	try.To(PutUserIDCount())

	return User{
		RoleInfo: RoleInfo{
			ID:      userIDCount,
			KeyInfo: key.InfoFromHandle(kh),
		},
		identity:     &id,
		IdentityCBOR: id.Bytes(),
	}
}

func NewUserFromData(b []byte) (u User) {
	buf := bytes.NewReader(b)
	dec := gob.NewDecoder(buf)
	try.To(dec.Decode(&u))

	iden := identity.NewFromData(
		u.IdentityCBOR,
		key.NewFromInfo(u.KeyInfo),
	)
	u.identity = &iden

	return
}
