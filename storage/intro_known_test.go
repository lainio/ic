package storage_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"slices"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const knownNamespace = "known-introductions-v1"

func TestKnownExplicitPromotionReopenAndNoWriteRetry(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, parent, bob, carol := key.New(), key.New(), key.New(), key.New(), key.New()
	r, a := key.InfoFromHandle(root).Public, key.InfoFromHandle(alice).Public
	f := newIntroductionFixture(t, r, a)
	base := intro.New(key.Info{Public: r})
	own := base.Introduce(root, key.Info{Public: a})
	try.To1(onboarding.SignAfterStoredChoice(f.vault, alice, r, r, own))
	choiceBefore := try.To1(introductionRecords(f.vault, "introduction-choice-demo"))
	shared := base.Introduce(root, key.Info{Public: key.InfoFromHandle(parent).Public})
	want := make([]key.Public, 0, 2)
	for _, child := range []key.Handle{bob, carol} {
		path := shared.Introduce(parent, key.Info{Public: key.InfoFromHandle(child).Public})
		proposal, acceptance := path.Bytes(), try.To1(path.SignAcceptance(child))
		subject, created := try.To2(onboarding.SaveIntroduction(f.vault, r, proposal, acceptance))
		assert.That(created)
		want = append(want, bytes.Clone(subject))
		clear(proposal)
		clear(acceptance)
		clear(subject)
	}
	slices.SortFunc(want, func(a, b key.Public) int { return bytes.Compare(a, b) })
	assert.DeepEqual(try.To1(onboarding.ListIntroductions(f.vault, r)), want)
	assert.SLen(try.To1(onboarding.ListKnownIntroductions(f.vault, r)), 0)
	receivedBefore := try.To1(introductionRecords(f.vault, "received-introductions-v1"))
	f.provider.mu.Lock()
	remaining := f.provider.remainingEncryptions
	f.provider.mu.Unlock()
	rootCopy := bytes.Clone(r)
	assert.Equal(try.To1(onboarding.VerifyReceived(f.vault, rootCopy)), 2)
	clear(rootCopy)
	f.provider.mu.Lock()
	after := f.provider.remainingEncryptions
	f.provider.mu.Unlock()
	assert.Equal(after, remaining-2) // Exactly one seal per new subject.
	assert.DeepEqual(try.To1(onboarding.ListKnownIntroductions(f.vault, r)), want)
	assert.DeepEqual(try.To1(introductionRecords(f.vault, "received-introductions-v1")), receivedBefore)
	assert.DeepEqual(try.To1(introductionRecords(f.vault, "introduction-choice-demo")), choiceBefore)
	markers := try.To1(introductionRecords(f.vault, knownNamespace))
	assert.Equal(len(markers), 2) // Neither Alice nor the shared ancestor was received as a subject.
	for _, marker := range markers {
		assert.Equal(len(marker), 1+key.HashSize)
	}

	try.To(f.vault.Close())
	try.To(f.db.Close())
	reopened := try.To1(storage.OpenBolt(f.path))
	defer func() { try.Out(reopened.Close()).Logf() }()
	p := f.provider
	f.vault = try.To1(reopened.OpenVault(t.Context(), p.vault, p.id, p))
	defer func() { try.Out(f.vault.Close()).Logf() }()
	f.assertReadOnly(t) // No remaining encryptions; compare the entire file at cleanup.
	assert.Equal(try.To1(onboarding.VerifyReceived(f.vault, r)), 0)
	got := try.To1(onboarding.ListKnownIntroductions(f.vault, r))
	assert.DeepEqual(got, want)
	clear(got[0])
	got[1] = nil
	assert.DeepEqual(try.To1(onboarding.ListKnownIntroductions(f.vault, r)), want)
	assert.DeepEqual(try.To1(introductionRecords(f.vault, knownNamespace)), markers)
	assert.DeepEqual(try.To1(introductionRecords(f.vault, "received-introductions-v1")), receivedBefore)
	assert.DeepEqual(try.To1(introductionRecords(f.vault, "introduction-choice-demo")), choiceBefore)
}

func TestKnownEmptyNoOp(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "empty namespaces"}[existing], func(t *testing.T) {
			defer assert.PushTester(t)()

			r := key.InfoFromHandle(key.New()).Public
			f := newIntroductionFixture(t, r, r)
			if existing {
				try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)

					try.To1(tx.EnsureChild([]byte("received-introductions-v1")))
					try.To1(tx.EnsureChild([]byte(knownNamespace)))
					return nil
				}))
			}
			f.assertReadOnly(t)
			assert.Equal(try.To1(onboarding.VerifyReceived(f.vault, r)), 0)
			assert.SLen(try.To1(onboarding.ListKnownIntroductions(f.vault, r)), 0)
		})
	}
}

func TestKnownNamespaceBoundaries(t *testing.T) {
	for _, scenario := range []string{
		"received only", "orphan known", "known namespace is a record", "received namespace is a record",
	} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()

			r := key.InfoFromHandle(key.New()).Public
			f := newIntroductionFixture(t, r, r)
			try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)

				switch scenario {
				case "received only":
					ns := try.To1(tx.EnsureChild([]byte("received-introductions-v1")))
					return ns.Put(r, []byte("invalid unpromoted evidence"))
				case "orphan known":
					ns := try.To1(tx.EnsureChild([]byte(knownNamespace)))
					return ns.Put(r, append([]byte{1}, make([]byte, key.HashSize)...))
				case "known namespace is a record":
					return tx.Put([]byte(knownNamespace), []byte("wrong kind"))
				default:
					try.To1(tx.EnsureChild([]byte(knownNamespace)))
					return tx.Put([]byte("received-introductions-v1"), []byte("wrong kind"))
				}
			}))
			f.assertReadOnly(t)
			count, err := onboarding.VerifyReceived(f.vault, r)
			assert.Error(err)
			assert.ErrorIsNot(err, storage.ErrKeyUsageExhausted)
			assert.Equal(count, 0)
			listed, err := onboarding.ListKnownIntroductions(f.vault, r)
			if scenario == "received only" {
				assert.NoError(err) // A missing Known namespace is empty, even with Received records.
				assert.SLen(listed, 0)
			} else {
				assert.Error(err)
				assert.SNil(listed)
			}
		})
	}
}

func TestKnownRejectsInvalidStorage(t *testing.T) {
	for _, scenario := range []string{
		"wrong root", "received version", "received acceptance", "received key",
		"known evidence acceptance", "known evidence missing", "valid replacement",
		"marker empty", "marker version", "marker digest", "marker trailing bytes", "orphan marker",
	} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()

			root, alice, bob := key.New(), key.New(), key.New()
			r, a, b := key.InfoFromHandle(root).Public, key.InfoFromHandle(alice).Public,
				key.InfoFromHandle(bob).Public
			f := newIntroductionFixture(t, r, a)
			base := intro.New(key.Info{Public: r})
			alicePath := base.Introduce(root, key.Info{Public: a})
			try.To2(onboarding.SaveIntroduction(f.vault, r, alicePath.Bytes(), try.To1(alicePath.SignAcceptance(alice))))
			assert.Equal(try.To1(onboarding.VerifyReceived(f.vault, r)), 1)
			bobPath := base.Introduce(root, key.Info{Public: b})
			try.To2(onboarding.SaveIntroduction(f.vault, r, bobPath.Bytes(), try.To1(bobPath.SignAcceptance(bob))))
			knownBroken := true
			queryRoot := r
			if scenario == "wrong root" {
				queryRoot = a
			} else {
				try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)

					received := try.To1(tx.ChildForUpdate([]byte("received-introductions-v1")))
					known := try.To1(tx.ChildForUpdate([]byte(knownNamespace)))
					marker, _ := try.To2(known.Get(a))
					switch scenario {
					case "received version", "received acceptance", "received key":
						knownBroken = false // Invalid unpromoted evidence cannot hide valid Known subjects.
						record, _ := try.To2(received.Get(b))
						subject := b
						switch scenario {
						case "received version":
							record[0]++
						case "received acceptance":
							record[len(record)-1] ^= 1
						case "received key":
							subject = r
						}
						return received.Put(subject, record)
					case "known evidence acceptance":
						record, _ := try.To2(received.Get(a))
						record[len(record)-1] ^= 1
						return received.Put(a, record)
					case "known evidence missing":
						return received.Delete(a)
					case "valid replacement":
						// Independently valid evidence for the same subject must still
						// match the exact record that was explicitly promoted.
						other := base.Introduce(root, key.Info{Public: a}, intro.WithEndpoint("changed", false))
						proposal, acceptance := other.Bytes(), try.To1(other.SignAcceptance(alice))
						assert.DeepEqual(try.To1(onboarding.CheckIntroduction(proposal, acceptance, r)), a)
						record := binary.BigEndian.AppendUint32([]byte{1}, uint32(len(proposal)))
						record = append(record, proposal...)
						return received.Put(a, append(record, acceptance...))
					case "marker empty":
						marker = nil
					case "marker version":
						marker[0]++
					case "marker digest":
						marker[1] ^= 1
					case "marker trailing bytes":
						marker = append(marker, 0)
					case "orphan marker":
						return known.Put(r, marker)
					}
					return known.Put(a, marker)
				}))
			}
			before := try.To1(introductionRecords(f.vault, knownNamespace))
			f.assertReadOnly(t)
			count, err := onboarding.VerifyReceived(f.vault, queryRoot)
			assert.Error(err)
			assert.ErrorIsNot(err, storage.ErrKeyUsageExhausted) // Validation precedes every insertion.
			assert.Equal(count, 0)
			assert.DeepEqual(try.To1(introductionRecords(f.vault, knownNamespace)), before)
			listed, err := onboarding.ListKnownIntroductions(f.vault, queryRoot)
			if knownBroken {
				assert.Error(err)
				assert.SNil(listed) // No truncated results after a valid marker.
			} else {
				assert.NoError(err)
				assert.DeepEqual(listed, []key.Public{a})
			}
		})
	}
}

func TestKnownConflictingSharedAncestor(t *testing.T) {
	for _, priorKnown := range []bool{false, true} {
		t.Run(map[bool]string{false: "both received", true: "one already known"}[priorKnown], func(t *testing.T) {
			defer assert.PushTester(t)()

			root, parent, ancestor, alice, bob := key.New(), key.New(), key.New(), key.New(), key.New()
			r, a, b := key.InfoFromHandle(root).Public, key.InfoFromHandle(alice).Public,
				key.InfoFromHandle(bob).Public
			f := newIntroductionFixture(t, r, a)
			base := intro.New(key.Info{Public: r})
			ancestorInfo := key.Info{Public: key.InfoFromHandle(ancestor).Public}
			direct := base.Introduce(root, ancestorInfo)
			indirect := base.Introduce(root, key.Info{Public: key.InfoFromHandle(parent).Public})
			indirect = indirect.Introduce(parent, ancestorInfo)
			first := direct.Introduce(ancestor, key.Info{Public: a})
			second := indirect.Introduce(ancestor, key.Info{Public: b})
			firstAcceptance, secondAcceptance := try.To1(first.SignAcceptance(alice)), try.To1(second.SignAcceptance(bob))
			assert.DeepEqual(try.To1(onboarding.CheckIntroduction(first.Bytes(), firstAcceptance, r)), a)
			assert.DeepEqual(try.To1(onboarding.CheckIntroduction(second.Bytes(), secondAcceptance, r)), b)
			try.To2(onboarding.SaveIntroduction(f.vault, r, first.Bytes(), firstAcceptance))
			want := []key.Public{}
			if priorKnown {
				assert.Equal(try.To1(onboarding.VerifyReceived(f.vault, r)), 1)
				want = append(want, a)
			}
			try.To2(onboarding.SaveIntroduction(f.vault, r, second.Bytes(), secondAcceptance))
			before := try.To1(introductionRecords(f.vault, knownNamespace))
			f.assertReadOnly(t)
			count, err := onboarding.VerifyReceived(f.vault, r)
			assert.Error(err)
			assert.ErrorIsNot(err, storage.ErrKeyUsageExhausted)
			assert.Equal(count, 0)
			assert.DeepEqual(try.To1(introductionRecords(f.vault, knownNamespace)), before)
			assert.DeepEqual(try.To1(onboarding.ListKnownIntroductions(f.vault, r)), want)
		})
	}
}

func TestKnownInsertionFailureRollsBack(t *testing.T) {
	for _, priorKnown := range []bool{false, true} {
		t.Run(map[bool]string{false: "new namespace", true: "existing namespace"}[priorKnown], func(t *testing.T) {
			defer assert.PushTester(t)()

			root := key.New()
			r := key.InfoFromHandle(root).Public
			f := newIntroductionFixture(t, r, r)
			base := intro.New(key.Info{Public: r})
			want := []key.Public{}
			for i := range 3 {
				if i == 0 && !priorKnown {
					continue
				}
				child := key.New()
				subject := key.InfoFromHandle(child).Public
				path := base.Introduce(root, key.Info{Public: subject})
				try.To2(onboarding.SaveIntroduction(f.vault, r, path.Bytes(), try.To1(path.SignAcceptance(child))))
				if i == 0 {
					assert.Equal(try.To1(onboarding.VerifyReceived(f.vault, r)), 1)
					want = append(want, subject)
				}
			}
			before := try.To1(os.ReadFile(f.path))
			receivedBefore := try.To1(introductionRecords(f.vault, "received-introductions-v1"))
			knownBefore := try.To1(introductionRecords(f.vault, knownNamespace))
			f.provider.mu.Lock()
			f.provider.remainingEncryptions = 1 // First Put succeeds; second seal is refused.
			f.provider.mu.Unlock()
			count, err := onboarding.VerifyReceived(f.vault, r)
			assert.ErrorIs(err, storage.ErrKeyUsageExhausted)
			assert.Equal(count, 0)
			f.provider.mu.Lock()
			remaining := f.provider.remainingEncryptions
			f.provider.mu.Unlock()
			assert.Equal(remaining, uint32(0)) // The attempted seal was charged despite rollback.
			assert.DeepEqual(try.To1(os.ReadFile(f.path)), before)
			assert.DeepEqual(try.To1(onboarding.ListKnownIntroductions(f.vault, r)), want)
			assert.DeepEqual(try.To1(introductionRecords(f.vault, knownNamespace)), knownBefore)
			assert.DeepEqual(try.To1(introductionRecords(f.vault, "received-introductions-v1")), receivedBefore)
			try.To(f.vault.View(func(tx storage.ReadTx) (err error) {
				defer err2.Handle(&err, nil)

				assert.Equal(try.To1(tx.HasChild([]byte(knownNamespace))), priorKnown)
				return nil
			}))
			// An explicit retry can promote exactly the two missing subjects.
			f.provider.mu.Lock()
			f.provider.remainingEncryptions = 2
			f.provider.mu.Unlock()
			assert.Equal(try.To1(onboarding.VerifyReceived(f.vault, r)), 2)
			assert.SLen(try.To1(onboarding.ListKnownIntroductions(f.vault, r)), len(want)+2)
			f.assertReadOnly(t)
			assert.Equal(try.To1(onboarding.VerifyReceived(f.vault, r)), 0)
		})
	}
}

func introductionRecords(vault *storage.Vault, namespace string) (_ map[string][]byte, err error) {
	defer err2.Handle(&err, nil)

	records := make(map[string][]byte)
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)

		if !try.To1(tx.HasChild([]byte(namespace))) {
			return nil
		}
		ns := try.To1(tx.Child([]byte(namespace)))
		return ns.Each(func(subject, record []byte) error {
			records[string(subject)] = record
			return nil
		})
	}))
	return records, nil
}
