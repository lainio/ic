package enclave

import (
	"flag"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/chain"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/pw"
)

const dbFilename = "MEMORY_fido-enclave.bolt"

const emailAddress = 1
const emailNotCreated = 0

func TestMain(m *testing.M) {
	try.To(flag.Set("logtostderr", "true"))
	try.To(flag.Set("v", "3"))

	setUp()
	code := m.Run()
	tearDown()
	os.Exit(code)
}

func setUp() {
	_ = os.RemoveAll(dbFilename)
}

func tearDown() {
	WipeSealedBox()
}

func TestInitSealedBox(t *testing.T) {
	defer assert.PushTester(t)()

	// default for testing
	TryInitSealedBox(dbFilename, "", "")
	TryClose()
	// hex key
	TryInitSealedBox(dbFilename, "",
		"1669cffcb6aecd479d7fd6fcee7fe97eb176ebc26e116ff1f42f4e066ab2df0e")
	TryClose()
	// base58 key
	TryInitSealedBox(dbFilename, "",
		"HUbkSypCy4CVxNdsqM1TwyVyYA2LVz8PWX3YTCsQSmXq")
	// leave it open for the rest of the tests
	// TryClose()
}

func TestPutGetPW(t *testing.T) {
	defer assert.PushTester(t)()

	h1 := key.NewHand()
	h2 := key.NewHand()
	h1Endp := pw.ConnEndpoint{Info: *h1.Info, Endpoint: "h1_endp"}
	h2Endp := pw.ConnEndpoint{Info: *h2.Info, Endpoint: "h2_endp"}

	// First we are addresser (initiator)
	isAddresser := true // Important!! We are testing addresser end here
	conn1 := pw.New(isAddresser, h1Endp, h2Endp)
	try.To(PutPW(isAddresser, conn1))
	dbConn1, found := try.To2(GetPW(isAddresser, conn1.Key()))
	assert.That(found)
	assert.That(dbConn1.TheirIDK().Equal(conn1.TheirIDK()))
	assert.DeepEqual(dbConn1, conn1)

	// Second we are addressee (joiner)
	isAddresser = false // Important!! We are testing addressee end here
	conn1 = pw.New(isAddresser, h1Endp, h2Endp)
	try.To(PutPW(isAddresser, conn1))
	dbConn1, found = try.To2(GetPW(isAddresser, conn1.Key()))
	assert.That(found)
	assert.That(dbConn1.TheirIDK().Equal(conn1.TheirIDK()))
	assert.DeepEqual(dbConn1, conn1)

	pconnsWeAreAddresser := try.To1(GetAllPW(true))
	assert.SNotEmpty(pconnsWeAreAddresser)
	assert.SShorter(pconnsWeAreAddresser, 2)

	pconnsWeAreNOTAddresser := try.To1(GetAllPW(false))
	assert.SNotEmpty(pconnsWeAreNOTAddresser)
	assert.SShorter(pconnsWeAreNOTAddresser, 2)
}

func TestPutSendersPW(t *testing.T) {
	defer assert.PushTester(t)()

	h1 := key.NewHand()
	h2 := key.NewHand()
	weAreAddresser := true // Important!! We are testing Senders
	h1Endp := pw.ConnEndpoint{Info: *h1.Info, Endpoint: "h1_endp"}
	h2Endp := pw.ConnEndpoint{Info: *h2.Info, Endpoint: "h2_endp"}

	conn1 := pw.New(weAreAddresser, h1Endp, h2Endp)
	try.To(PutSendersPW(conn1))
	dbConn1, found := try.To2(GetSendersPW(conn1.Key()))
	assert.That(found)
	assert.That(dbConn1.TheirIDK().Equal(conn1.TheirIDK()))
	assert.DeepEqual(dbConn1, conn1)
}

func TestPutReceiversPW(t *testing.T) {
	defer assert.PushTester(t)()

	h1 := key.NewHand()
	h2 := key.NewHand()
	weAreAddresser := false // Important!! We are testing Receivers
	h1Endp := pw.ConnEndpoint{Info: *h1.Info, Endpoint: "h1_endp"}
	h2Endp := pw.ConnEndpoint{Info: *h2.Info, Endpoint: "h2_endp"}

	conn1 := pw.New(weAreAddresser, h1Endp, h2Endp)
	try.To(PutReceiversPW(conn1))
	dbConn1, found := try.To2(GetReceiversPW(conn1.Key()))
	assert.That(found)
	assert.That(dbConn1.TheirIDK().Equal(conn1.TheirIDK()))
	assert.DeepEqual(dbConn1, conn1)

	dbConn1, found = try.To2(GetReceiversPW(conn1.OurIDK()))
	assert.ThatNot(found)
}

func TestPutUserIDCount(t *testing.T) {
	defer assert.PushTester(t)()

	oldCount := userIDCount
	try.To(PutUserIDCount())
	count := try.To1(GetUserIDCount())
	assert.Equal(count, oldCount)
}

func TestGetUserIDCount(t *testing.T) {
	defer assert.PushTester(t)()

	_ = try.To1(GetUserIDCount())
}

func TestNewUser(t *testing.T) {
	defer assert.PushTester(t)()

	var root, u User
	for i := range 2 { // roots
		alias := fmt.Sprintf("root_alias_%d", i+1)
		newU := NewUserWithAlias(alias, chain.WithAllowRouting(true))
		assert.NotNil(newU.identity)
		assert.That(newU.identity.IsRoot())
		try.To(PutUser(newU))
		u = newU
		root = newU
	}
	var lastAlias string
	for i := range 10 {
		alias := fmt.Sprintf("alias_%v", i)
		lastAlias = alias
		newU := NewUserWithAlias(alias)
		assert.NotNil(newU.identity)
		assert.Equal(newU.Alias, alias)
		try.To(PutUser(newU))
		u = newU
	}

	invit := root.Identity().Invite(
		*u.Identity(),
		chain.WithPosition(100),
	)
	assert.Equal(invit.ICCount(), 1)
	u.SetIdentity(&invit)
	try.To(PutUser(u))
	assert.Equal(u.Identity().ICCount(), 1)
	assert.Equal(u.Alias, lastAlias)

	u2, found := try.To2(GetUser(u.ID))
	assert.Equal(u.ID, u2.ID)
	assert.That(found)
	assert.NotNil(u2.identity)
	assert.Equal(u2.Identity().ICCount(), 1)
	assert.Equal(u2.Alias, lastAlias)

	users1 := try.To1(GetAllUsers())
	assert.SNotEmpty(users1)
	sorted := slices.IsSortedFunc(users1, UserSort)
	assert.That(sorted)

	assert.NoError(PutUser(u), "just update, not add")

	users2 := try.To1(GetAllUsers())
	sorted = slices.IsSortedFunc(users2, UserSort)
	assert.That(sorted, "keep it sorted")
	assert.SLen(users1, len(users2), "update (u), not add")

	try.To(PutUser(u))
}

func TestGetUser(t *testing.T) {
	defer assert.PushTester(t)()

	u2, found := try.To2(GetUser(emailAddress))
	assert.That(found)
	assert.NotNil(u2.identity)

	u3, found3 := try.To2(GetUserByIDK(u2.KeyInfo.Public))
	assert.That(found3)
	assert.NotNil(u3.identity)
	assert.Equal(u3.ID, u2.ID)
	assert.DeepEqual(u3.KeyInfo, u2.KeyInfo)

	u3, found3 = TryGetUserByIDK(u2.KeyInfo.Public)
	assert.That(found3)
	assert.NotNil(u3.identity)
	assert.Equal(u3.ID, u2.ID)
	assert.DeepEqual(u3.KeyInfo, u2.KeyInfo)

	digest := u2.Identity().Digest().Base58()
	u4, found4 := try.To2(GetUserByDigest(digest))
	assert.That(found4)
	assert.NotNil(u4.identity)
	assert.Equal(u4.ID, u2.ID)
	assert.DeepEqual(u4.KeyInfo, u2.KeyInfo)

	alias := u2.Alias
	assert.NotEmpty(alias)
	assert.Equal(alias, "root_alias_1") // see the alias name in TestNewUser
	u5, found5 := try.To2(GetUserByAlias(alias))
	assert.That(found5)
	assert.NotNil(u5.identity)
	assert.Equal(u5.ID, u2.ID)
	assert.DeepEqual(u5.KeyInfo, u2.KeyInfo)

	users := try.To1(GetAllUsers())
	assert.SNotEmpty(users)

	prefix := u2.KeyInfo.Public.PKString()[:4]
	allUsers := TryGetAllUsersByIDKPrefix(prefix)
	assert.SNotEmpty(allUsers)
	assert.SLen(allUsers, 1)
	assert.That(allUsers[0].EqualPK(u2.KeyInfo.PKString()))
	assert.DeepEqual(allUsers[0].KeyInfo, u2.KeyInfo)

	_, found = try.To2(GetUser(emailNotCreated))
	assert.ThatNot(found)
	assert.NotNil(u2.identity)
}

func TestGetExistingUser(t *testing.T) {
	defer assert.PushTester(t)()

	u := try.To1(GetExistingUser(emailAddress))
	assert.NotZero(u.ID)

	u2 := TryGetExistingUserByIDK(u.KeyInfo.Public)
	assert.Equal(u2.ID, u.ID)
	assert.That(u2.KeyInfo.Public.Equal(u.KeyInfo.Public))

	digest := u2.Identity().Digest().Base58()
	u4 := TryGetExistingUserByType("digest", digest)
	assert.NotNil(u4.identity)
	assert.Equal(u4.ID, u2.ID)
	assert.DeepEqual(u4.KeyInfo, u2.KeyInfo)

	_, err := GetExistingUser(emailNotCreated)
	assert.Error(err)
}

func TestRemoveUser(t *testing.T) {
	defer assert.PushTester(t)()

	u := NewUser()
	try.To(PutUser(u))
	assert.NotZero(u.ID)

	users1 := try.To1(GetAllUsers())
	assert.SNotEmpty(users1)

	try.To(RemoveUser(u.ID))

	users2 := try.To1(GetAllUsers())
	assert.SLonger(users1, len(users2))

	_, err := GetExistingUser(u.ID)
	assert.Error(err)

	_ = RemoveUser(emailNotCreated)
	//assert.Error(err)
}

func TestClose(t *testing.T) {
	defer assert.PushTester(t)()

	try.To(Close())
}
