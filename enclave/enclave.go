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
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/findy-network/findy-common-go/crypto"
	"github.com/findy-network/findy-common-go/crypto/db"
	"github.com/findy-network/findy-common-go/x"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/chain"
	"github.com/lainio/ic/digest"
	"github.com/lainio/ic/identity"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/pw"
)

type bucket = byte

const (
	userBucket bucket = iota
	userIDCountBucket
	pwBucketSender
	pwBucketReceiver
)

const hexLen = 64

var (
	buckets = [][]byte{
		{userBucket},
		{userIDCountBucket},
		{pwBucketSender},
		{pwBucketReceiver},
	}
	sealedBoxFilename string

	// Key must be set from production environment, SHA-256, 32 bytes
	hexKey    = "15308490f1e4026284594dd08d31291bc8ef2aeac730d0daf6ff87bb92d4336c"
	theCipher *crypto.Cipher
)

func TryClose() {
	try.To(Close())
}

func Close() (err error) {
	return db.Close()
}

func TryInitSealedBox(filename, backupName, key string) {
	try.To(InitSealedBox(filename, backupName, key))
}

// InitSealedBox initialize enclave's sealed box. This must be called once
// during the app life cycle.
func InitSealedBox(filename, backupName, key string) (err error) {
	defer err2.Handle(&err)

	keyLen := len(key)
	var k []byte
	if keyLen < hexLen && keyLen > 0 {
		k = base58.Decode(key)
	} else {
		key = x.Whom(keyLen == 0, hexKey, key)
		k, _ = hex.DecodeString(key)
	}

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

func PutPW(isAddresser bool, pw *pw.Connection) (err error) {
	defer err2.Handle(&err)

	try.To(db.AddKeyValueToBucket(
		buckets[x.Whom(isAddresser, pwBucketSender, pwBucketReceiver)],
		&db.Data{
			Data: pw.Data(),
			Read: encrypt,
		},
		&db.Data{
			Data: pw.Key(),
			Read: hash,
		},
	))

	return nil
}

func GetPW(
	isAddresser bool,
	idk key.Public,
) (
	conn *pw.Connection,
	exist bool,
	err error,
) {
	defer err2.Handle(&err)

	value := &db.Data{
		Write: decrypt,
	}
	exist = try.To1(db.GetKeyValueFromBucket(
		buckets[x.Whom(isAddresser, pwBucketSender, pwBucketReceiver)],
		&db.Data{
			Data: idk,
			Read: hash,
		},
		value,
	))
	conn = pw.NewFromData(value.Data)
	return
}

func PutReceiversPW(pw *pw.Connection) (err error) {
	defer err2.Handle(&err)

	try.To(db.AddKeyValueToBucket(buckets[pwBucketReceiver],
		&db.Data{
			Data: pw.Data(),
			Read: encrypt,
		},
		&db.Data{
			Data: pw.Key(),
			Read: hash,
		},
	))

	return nil
}

func PutSendersPW(pw *pw.Connection) (err error) {
	defer err2.Handle(&err)

	try.To(db.AddKeyValueToBucket(buckets[pwBucketSender],
		&db.Data{
			Data: pw.Data(),
			Read: encrypt,
		},
		&db.Data{
			Data: pw.Key(),
			Read: hash,
		},
	))

	return nil
}

func GetReceiversPW(idk key.Public) (conn *pw.Connection, exist bool, err error) {
	defer err2.Handle(&err)

	value := &db.Data{
		Write: decrypt,
	}
	exist = try.To1(db.GetKeyValueFromBucket(buckets[pwBucketReceiver],
		&db.Data{
			Data: idk,
			Read: hash,
		},
		value,
	))
	conn = pw.NewFromData(value.Data)
	return
}

func GetSendersPW(idk key.Public) (conn *pw.Connection, exist bool, err error) {
	defer err2.Handle(&err)

	value := &db.Data{
		Write: decrypt,
	}
	exist = try.To1(db.GetKeyValueFromBucket(buckets[pwBucketSender],
		&db.Data{
			Data: idk,
			Read: hash,
		},
		value,
	))
	conn = pw.NewFromData(value.Data)
	return
}

func GetAllPW(isAddresser bool) (pconns []*pw.Connection, err error) {
	defer err2.Handle(&err)

	conns := try.To1(db.GetAllValuesFromBucket(
		buckets[x.Whom(isAddresser, pwBucketSender, pwBucketReceiver)],
		decrypt,
	))
	if len(conns) == 0 {
		return
	}

	pconns = make([]*pw.Connection, len(conns))
	for i, v := range conns {
		pconns[i] = pw.NewFromData(v)
	}

	return
}

func TryPutUser(u User) {
	try.To(PutUser(u))
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

func TryGetUser(id uint32) (u User, exist bool) {
	return try.To2(GetUser(id))
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

func TryGetAllUsersByIDKPrefix(idkPrefix string) (u []User) {
	return try.To1(GetAllUsersByIDKPrefix(idkPrefix))
}

func GetAllUsersByIDKPrefix(
	idkPrefix string,
) (
	retval []User,
	err error,
) {
	defer err2.Handle(&err)

	users := TryGetAllUsers()
	retval = make([]User, 0, len(users))
	for _, u := range users {
		if strings.HasPrefix(u.KeyInfo.Public.PKString(), idkPrefix) {
			user := try.To1(GetExistingUser(u.ID))
			retval = append(retval, user)
		}
	}
	return
}

func TryGetUserByIDK(idk key.Public) (u User, exist bool) {
	return try.To2(GetUserByIDK(idk))
}

func GetUserByIDK(idk key.Public) (u User, exist bool, err error) {
	defer err2.Handle(&err)

	users := TryGetAllUsers()
	for _, u := range users {
		if u.KeyInfo.Public.Equal(idk) {
			return GetUser(u.ID)
		}
	}

	return
}

func TryGetExistingUserByIDK(idk key.Public) (u User) {
	return try.To1(GetExistingUserByIDK(idk))
}

func GetExistingUserByIDK(idk key.Public) (u User, err error) {
	defer err2.Handle(&err)

	u, already := try.To2(GetUserByIDK(idk))

	if !already {
		return u, fmt.Errorf("user (%v) not exist", idk)
	}

	return
}

func TryGetExistingUserByType(t, d string) (u User) {
	return try.To1(GetExistingUserByType(t, d))
}

func GetExistingUserByType(t, d string) (u User, err error) {
	defer err2.Handle(&err)

	u, already := try.To2(GetUserByType(t, d))

	if !already {
		return u, fmt.Errorf("user (%v) not exist", d)
	}

	return
}

func TryGetUserByType(t, d string) (u User, exist bool) {
	return try.To2(GetUserByType(t, d))
}

func GetUserByType(t, d string) (u User, exist bool, err error) {
	defer err2.Handle(&err)

	users := TryGetAllUsers()
	for _, u := range users {
		if found, u := Equal(t, d, u); found {
			return u, true, nil
		}
	}

	return
}

func Equal(t, d string, rhs User) (ok bool, u User) {
	// TODO: how to use these types "db", "idk", etc. as same const ArgType?
	// mv ArgType to its own pkg
	glog.V(3).Infoln("t:", t, "d:", d, "rhs-user ID:", rhs.ID)
	switch t {
	case "db":
		ok = try.To1(strconv.Atoi(d)) == int(rhs.ID)
		if ok {
			u = TryGetExistingUser(rhs.ID)
		}
	case "idk":
		ok = rhs.KeyInfo.Public.PKString() == d
		if ok {
			u = TryGetExistingUserByIDK(rhs.KeyInfo.Public)
		}
	case "digestv2":
		if rhs.Identity().Initialized() {
			rhDigest := rhs.Identity().Digest().Digest().Build()
			lhDigest := digest.DigestV2(d)
			isWot := lhDigest.Build().WoT(rhDigest)
			if isWot {
				u = TryGetExistingUserByDigestV2(d)
			}
		}
	case "digest":
		ok = rhs.Identity().Digest().Base58() == d
		if ok {
			u = TryGetExistingUserByDigest(d)
		}
	case "alias":
		ok = rhs.Alias == d
		if ok {
			u = TryGetExistingUserByAlias(d)
		}
	}
	if ok {
		return
	}
	ok = false
	return
}

func TryGetExistingUserByAlias(d string) (u User) {
	return try.To1(GetExistingUserByAlias(d))
}

func GetExistingUserByAlias(d string) (u User, err error) {
	defer err2.Handle(&err)

	u, already := try.To2(GetUserByAlias(d))

	if !already {
		return u, fmt.Errorf("user (%v) not exist", d)
	}

	return
}

func TryGetUserByAlias(d string) (u User, exist bool) {
	return try.To2(GetUserByAlias(d))
}

func GetUserByAlias(d string) (u User, exist bool, err error) {
	defer err2.Handle(&err)

	users := TryGetAllUsers()
	for _, u := range users {
		if u.Alias == d {
			return GetUser(u.ID)
		}
	}

	return
}

func TryGetExistingUserByDigestV2(d string) (u User) {
	return try.To1(GetExistingUserByDigestV2(d))
}

func GetExistingUserByDigestV2(d string) (u User, err error) {
	defer err2.Handle(&err)

	u, already := try.To2(GetUserByDigestV2(d))

	if !already {
		return u, fmt.Errorf("user (%v) not exist", d)
	}

	return
}

func TryGetUserByDigestV2(d string) (u User, exist bool) {
	return try.To2(GetUserByDigestV2(d))
}

func GetUserByDigestV2(d string) (u User, exist bool, err error) {
	defer err2.Handle(&err)

	users := TryGetAllUsers()
	for _, u := range users {
		if u.Identity().Initialized() {
			userDigest := u.Identity().Digest().Digest().Build()
			dataDigest := digest.DigestV2(d).Build()
			if userDigest.WoT(dataDigest) {
				return GetUser(u.ID)
			}
		}
	}

	return
}

func TryGetExistingUserByDigest(d string) (u User) {
	return try.To1(GetExistingUserByDigest(d))
}

func GetExistingUserByDigest(d string) (u User, err error) {
	defer err2.Handle(&err)

	u, already := try.To2(GetUserByDigest(d))

	if !already {
		return u, fmt.Errorf("user (%v) not exist", d)
	}

	return
}

func TryGetUserByDigest(d string) (u User, exist bool) {
	return try.To2(GetUserByDigest(d))
}

func GetUserByDigest(d string) (u User, exist bool, err error) {
	defer err2.Handle(&err)

	users := TryGetAllUsers()
	for _, u := range users {
		if u.Identity().Initialized() && u.Identity().Digest().Base58() == d {
			return GetUser(u.ID)
		}
	}

	return
}

func TryGetExistingUser(id uint32) (u User) {
	return try.To1(GetExistingUser(id))
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

func TryRemoveUser(id uint32) {
	try.To(RemoveUser(id))
}

func RemoveUser(id uint32) (err error) {
	defer err2.Handle(&err)

	//_ = try.To1(GetExistingUser(id))
	return db.RmKeyValueFromBucket(
		buckets[userBucket], &db.Data{
			Data: uint32ToBytes(id),
			Read: hash,
		})
}

func TryGetAllUsers() (users []User) {
	return try.To1(GetAllUsers())
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
	Alias   string
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
	assert.That(bytes.Equal(u.identity.Bytes(), u.IdentityCBOR))
	return base58.Encode(u.IdentityCBOR)
}

func (u *User) MakeIdentityFromStr(idStr string) *identity.Identity {
	d := base58.Decode(idStr)
	id := identity.NewFromData(d, key.NewFromInfo(u.KeyInfo))
	return &id
}

func (u *User) SetIdentityFromStr(idStr string) {
	id := u.MakeIdentityFromStr(idStr)
	u.SetIdentity(id)
}

func (u User) Identity() *identity.Identity {
	assert.NotNil(u.identity)
	assert.That(bytes.Equal(u.identity.Bytes(), u.IdentityCBOR))
	return u.identity
}

func (u *User) SetIdentity(id *identity.Identity) {
	u.IdentityCBOR = id.Bytes()
	u.identity = id
}

func (u *User) EqualPK(pk string) bool {
	assert.Len(pk, key.PKLen)
	return u.RoleInfo.KeyInfo.PKString() == pk
}

func uint32ToBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func NewUserWithAlias(alias string, flags ...chain.Opts) User {
	u := NewUser(flags...)
	u.Alias = alias
	return u
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
