package enclave

import (
	"flag"
	"os"
	"slices"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/chain"
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
	for range 2 { // roots
		newU := NewUser(chain.WithAllowRouting(true))
		assert.NotNil(newU.identity)
		assert.That(newU.identity.IsRoot())
		try.To(PutUser(newU))
		u = newU
		root = newU
	}
	for range 10 {
		newU := NewUser()
		assert.NotNil(newU.identity)
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

	u2, found := try.To2(GetUser(u.ID))
	assert.Equal(u.ID, u2.ID)
	assert.That(found)
	assert.NotNil(u2.identity)
	assert.Equal(u2.Identity().ICCount(), 1)

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
	assert.NotNil(u2.identity)
	assert.That(found)

	users := try.To1(GetAllUsers())
	assert.SNotEmpty(users)

	_, found = try.To2(GetUser(emailNotCreated))
	assert.ThatNot(found)
	assert.NotNil(u2.identity)
}

func TestGetExistingUser(t *testing.T) {
	defer assert.PushTester(t)()

	u := try.To1(GetExistingUser(emailAddress))
	assert.NotZero(u.ID)

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
