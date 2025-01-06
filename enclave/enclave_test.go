package enclave

import (
	"flag"
	"os"
	"slices"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
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

	try.To(InitSealedBox(dbFilename, "", ""))
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

	var u User
	for range 10 {
		newU := NewUser()
		assert.NotNil(newU.identity)
		try.To(PutUser(newU))
		u = newU
	}

	u2, found := try.To2(GetUser(u.ID))
	assert.Equal(u.ID, u2.ID)
	assert.That(found)
	assert.NotNil(u2.identity)

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

	err = RemoveUser(emailNotCreated)
	assert.Error(err)
}

func TestClose(t *testing.T) {
	defer assert.PushTester(t)()

	try.To(Close())
}
