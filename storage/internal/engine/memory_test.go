package engine

import (
	"fmt"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func openTestMemory(t *testing.T) Engine {
	t.Helper()
	db := NewMemory()
	t.Cleanup(func() {
		if err := awaitMemory(t, memoryWorker(db.Close)); err != nil {
			t.Errorf("close engine: %v", err)
		}
	})
	return db
}

func TestMemoryContract(t *testing.T) {
	runContract(t, openTestMemory)
}

func TestMemoryIndependentInstances(t *testing.T) {
	defer assert.PushTester(t)()
	first, second := openTestMemory(t), openTestMemory(t)
	try.To(first.Update(func(tx WriteTx) error {
		try.To(tx.Put([]byte("one"), []byte("first")))
		return tx.Put([]byte("two"), []byte("second"))
	}))
	try.To(second.View(func(tx ReadTx) error {
		checkRecord(t, tx, "one", "", false)
		checkRecord(t, tx, "two", "", false)
		return nil
	}))
	try.To(second.Update(func(tx WriteTx) error {
		try.To(tx.Put([]byte("one"), []byte("independent")))
		return tx.Delete([]byte("two"))
	}))
	checkPair(t, first, "first", "second")
	try.To(first.Update(func(tx WriteTx) error { return tx.Delete([]byte("one")) }))
	try.To(first.Close())
	try.To(second.View(func(tx ReadTx) error {
		checkRecord(t, tx, "one", "independent", true)
		return nil
	}))
}

func TestMemoryViewSnapshot(t *testing.T) {
	defer assert.PushTester(t)()
	db := openTestMemory(t)
	try.To(db.Update(func(tx WriteTx) error {
		try.To(tx.Put([]byte("one"), []byte("first")))
		return tx.Put([]byte("two"), []byte("second"))
	}))

	stop := make(chan struct{})
	defer close(stop) // Unblock callbacks on every failure path, before cleanup.
	readAgain := make(chan struct{})
	observed := make(chan [2]string, 2)
	reader := memoryWorker(func() error {
		return db.View(func(tx ReadTx) (err error) {
			defer err2.Handle(&err, nil)

			before := try.To1(readMemoryPair(tx))
			observed <- before
			select {
			case <-readAgain:
			case <-stop:
				return nil
			}
			after, err := readMemoryPair(tx)
			observed <- after
			return err
		})
	})
	assert.Equal(awaitMemory(t, observed), [2]string{"first", "second"})

	pending := make(chan struct{})
	commit := make(chan struct{})
	writer := memoryWorker(func() error {
		return db.Update(func(tx WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			defer assert.PushAsserter(assert.Plain)()

			try.To(tx.Put([]byte("one"), []byte("later")))
			// The unchanged value is shared across map versions internally.
			// Mutating a Get result must not alter either version's bytes.
			value, found := try.To2(tx.Get([]byte("two")))
			assert.That(found, "missing nonempty record two")
			assert.SNotEmpty(value, "missing nonempty record two")
			value[0] = 'X'
			close(pending)
			select {
			case <-commit:
				return nil
			case <-stop:
				return fmt.Errorf("test stopped before commit")
			}
		})
	})
	awaitMemory(t, pending)
	// A newly admitted View also cannot see the writer's pending changes.
	current := memoryWorker(func() error {
		return db.View(func(tx ReadTx) error {
			values, err := readMemoryPair(tx)
			observed <- values
			return err
		})
	})
	assert.NoError(awaitMemory(t, current))
	assert.Equal(awaitMemory(t, observed), [2]string{"first", "second"})
	close(commit)
	assert.NoError(awaitMemory(t, writer)) // Must progress while the old View lives.
	close(readAgain)
	assert.Equal(awaitMemory(t, observed), [2]string{"first", "second"})
	assert.NoError(awaitMemory(t, reader))
	checkPair(t, db, "later", "second")
}

func TestMemoryConcurrentUpdates(t *testing.T) {
	defer assert.PushTester(t)()
	db := openTestMemory(t)
	try.To(db.Update(func(tx WriteTx) error { return tx.Put([]byte("count"), []byte("0")) }))
	const workers, increments = 8, 50
	start := make(chan struct{})
	stop := make(chan struct{})
	defer close(stop)
	results := make([]<-chan error, workers)
	for i := range results {
		results[i] = memoryWorker(func() (err error) {
			defer err2.Handle(&err, nil)

			select {
			case <-start:
			case <-stop:
				return nil
			}
			for range increments {
				select {
				case <-stop:
					return nil
				default:
				}
				try.To(db.Update(func(tx WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					defer assert.PushAsserter(assert.Plain)()

					value, found := try.To2(tx.Get([]byte("count")))
					assert.That(found, "missing counter")
					count := try.To1(strconv.Atoi(string(value)))
					// Encourage competing writers to attempt admission between
					// this read and write; correctness cannot depend on scheduling.
					runtime.Gosched()
					return tx.Put([]byte("count"), []byte(strconv.Itoa(count+1)))
				}))
			}
			return nil
		})
	}
	close(start)
	for _, result := range results {
		assert.NoError(awaitMemory(t, result))
	}
	try.To(db.View(func(tx ReadTx) error {
		checkRecord(t, tx, "count", strconv.Itoa(workers*increments), true)
		return nil
	}))
}

func TestMemoryCloseDrains(t *testing.T) {
	for _, mode := range []string{"view", "update"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			db := openTestMemory(t)
			stop := make(chan struct{})
			defer close(stop)
			entered := make(chan struct{})
			release := make(chan struct{})
			finished := make(chan struct{})
			hold := func() {
				close(entered)
				select {
				case <-release:
				case <-stop:
				}
			}
			transaction := memoryWorker(func() error {
				if mode == "view" {
					return db.View(func(ReadTx) error {
						defer close(finished)
						hold()
						return nil
					})
				}
				return db.Update(func(tx WriteTx) error {
					defer close(finished)
					hold()
					return tx.Put([]byte("one"), []byte("admitted"))
				})
			})
			awaitMemory(t, entered)
			closed := memoryWorker(func() (err error) {
				defer err2.Handle(&err, nil)

				try.To(db.Close())
				select {
				case <-finished:
					return nil
				default:
					return fmt.Errorf("Close returned before the callback finished")
				}
			})
			// Observe admission stopping before releasing the held callback.
			// This also ensures Close has started, without sleep-based ordering.
			rejected := memoryWorker(func() error {
				for {
					err := db.View(func(ReadTx) error { return nil })
					if err != nil {
						return err
					}
					select {
					case <-stop:
						return nil
					default:
						runtime.Gosched()
					}
				}
			})
			assert.Equal(awaitMemory(t, rejected), ErrClosed)
			select {
			case err := <-closed:
				t.Fatalf("Close completed with an admitted callback still held: %v", err)
			default:
			}
			close(release)
			assert.NoError(awaitMemory(t, transaction))
			assert.NoError(awaitMemory(t, closed))
			called := false
			assert.Equal(db.View(func(ReadTx) error { called = true; return nil }), ErrClosed)
			assert.Equal(db.Update(func(WriteTx) error { called = true; return nil }), ErrClosed)
			assert.ThatNot(called)
			assert.NoError(db.Close())
		})
	}
}

// Worker observations and errors are checked only by the test goroutine.
func readMemoryPair(tx ReadTx) (values [2]string, err error) {
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()

	for i, key := range []string{"one", "two"} {
		value, found := try.To2(tx.Get([]byte(key)))
		assert.That(found, "missing record %s", key)
		values[i] = string(value)
	}
	return values, nil
}

func memoryWorker(fn func() error) <-chan error {
	result := make(chan error, 1)
	go func() { result <- fn() }()
	return result
}

func awaitMemory[T any](t *testing.T, result <-chan T) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for memory worker")
		var zero T
		return zero
	}
}

func TestMemoryNestedSnapshot(t *testing.T) {
	defer assert.PushTester(t)()
	db := openTestMemory(t)
	seedNamespaces(t, db)
	stop := make(chan struct{})
	defer close(stop) // Release held callbacks before engine cleanup on failure.
	readAgain := make(chan struct{})
	observed := make(chan string, 1)
	reader := memoryWorker(func() error {
		return db.View(func(tx ReadTx) (err error) {
			defer err2.Handle(&err, nil)
			defer assert.PushAsserter(assert.Plain)()

			left := try.To1(tx.Child([]byte("left")))
			for stage := range 4 {
				if stage > 0 {
					select {
					case <-readAgain:
					case <-stop:
						return nil
					}
				}
				// Reopening the child also checks the held tree's membership.
				deep := try.To1(left.Child([]byte("deep")))
				value, found := try.To2(deep.Get([]byte("key")))
				assert.That(found, "missing descendant record")
				observed <- string(value)
			}
			// A child created by the committed writer is still absent here.
			_, err = left.Child([]byte("new"))
			assert.Equal(err, ErrNamespaceNotFound)
			return err
		})
	})
	assert.Equal(awaitMemory(t, observed), "descendant")

	pending := make(chan struct{})
	abort := make(chan struct{})
	aborted := fmt.Errorf("abort nested update")
	writer := memoryWorker(func() error {
		return db.Update(func(tx WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			left := try.To1(tx.ChildForUpdate([]byte("left")))
			deep := try.To1(left.ChildForUpdate([]byte("deep")))
			try.To(deep.Put([]byte("key"), []byte("uncommitted")))
			try.To1(left.EnsureChild([]byte("aborted")))
			close(pending)
			select {
			case <-abort:
			case <-stop:
			}
			return aborted
		})
	})
	awaitMemory(t, pending)
	select {
	case readAgain <- struct{}{}:
	case <-time.After(5 * time.Second):
		t.Fatal("held nested reader did not request pending-state check")
	}
	assert.Equal(awaitMemory(t, observed), "descendant")
	// A new reader must also see the committed tree while the writer is pending.
	current := memoryWorker(func() error {
		return db.View(func(tx ReadTx) (err error) {
			defer err2.Handle(&err, nil)
			defer assert.PushAsserter(assert.Plain)()
			left := try.To1(tx.Child([]byte("left")))
			deep := try.To1(left.Child([]byte("deep")))
			value, found := try.To2(deep.Get([]byte("key")))
			assert.That(found, "missing committed descendant")
			assert.Equal(string(value), "descendant")
			_, err = left.Child([]byte("aborted"))
			return err
		})
	})
	assert.Equal(awaitMemory(t, current), ErrNamespaceNotFound)
	close(abort)
	assert.Equal(awaitMemory(t, writer), aborted)
	select {
	case readAgain <- struct{}{}:
	case <-time.After(5 * time.Second):
		t.Fatal("held nested reader did not request aborted-state check")
	}
	assert.Equal(awaitMemory(t, observed), "descendant")
	checkNamespaceSeed(t, db)

	committed := memoryWorker(func() error {
		return db.Update(func(tx WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			defer assert.PushAsserter(assert.Plain)()
			left := try.To1(tx.ChildForUpdate([]byte("left")))
			deep := try.To1(left.ChildForUpdate([]byte("deep")))
			try.To(deep.Put([]byte("key"), []byte("committed")))
			created := try.To1(left.EnsureChild([]byte("new")))
			try.To(created.Put([]byte("key"), []byte("created")))
			// Unchanged record bytes may be shared internally, but Get owns its copy.
			value, found := try.To2(left.Get([]byte("key")))
			assert.That(found)
			assert.SNotEmpty(value)
			value[0] = 'X'
			return nil
		})
	})
	assert.NoError(awaitMemory(t, committed)) // Commit while the old View is held.
	select {
	case readAgain <- struct{}{}:
	case <-time.After(5 * time.Second):
		t.Fatal("held nested reader did not request committed-state check")
	}
	assert.Equal(awaitMemory(t, observed), "descendant")
	assert.Equal(awaitMemory(t, reader), ErrNamespaceNotFound)
	try.To(db.View(func(tx ReadTx) error {
		left := try.To1(tx.Child([]byte("left")))
		deep := try.To1(left.Child([]byte("deep")))
		checkRecord(t, deep, "key", "committed", true)
		checkRecord(t, left, "key", "left", true)
		created := try.To1(left.Child([]byte("new")))
		checkRecord(t, created, "key", "created", true)
		return nil
	}))
	assert.Equal(db.View(func(tx ReadTx) error {
		left := try.To1(tx.Child([]byte("left")))
		_, err := left.Child([]byte("aborted"))
		return err
	}), ErrNamespaceNotFound)
}
