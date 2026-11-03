package pw

import (
	"os"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestFirstUseBackendCommitFailure(t *testing.T) {
	for _, phase := range []string{"Await", "useSeen", "Ready"} {
		t.Run(phase, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newFirstUse(t)
			var saved SavedFirstUse
			var response []byte
			fixture := &f.alice
			if phase != "Await" {
				saved = try.To1(f.startUse())
			}
			if phase == "Ready" {
				response = try.To1(f.bobUse(saved.request, f.local.handle))
			}
			if phase == "useSeen" {
				fixture = &f.f
			}
			before := useRecords(t, fixture.vault)
			disk := try.To1(os.ReadFile(fixture.path))
			restore := readOnlyVaultDescriptor(t, fixture.path)
			var err error
			switch phase {
			case "Await":
				var result SavedFirstUse
				result, err = f.startUse()
				assert.SNil(result.request)
			case "useSeen":
				var result []byte
				result, err = f.bobUse(saved.request, f.local.handle)
				assert.SNil(result)
			case "Ready":
				var ready bool
				ready, err = f.receiveUse(response)
				assert.ThatNot(ready)
			}
			restore()
			assert.Equal(err, ErrFirstUse)
			assert.DeepEqual(try.To1(os.ReadFile(fixture.path)), disk)
			assert.DeepEqual(useRecords(t, fixture.vault), before)
			fixture.reopen(t)
			assert.DeepEqual(useRecords(t, fixture.vault), before)
		})
	}
}
