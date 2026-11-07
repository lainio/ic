package pw

import (
	"os"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestFirstUseBackendCommitFailureV2(t *testing.T) {
	for _, phase := range []string{"Await", "useSeen", "Ready", "Expired"} {
		t.Run(phase, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newFirstUseV2(t)
			var saved SavedFirstUseV2
			var response []byte
			fixture := &f.alice
			if phase != "Await" {
				saved = try.To1(f.startUseV2())
			}
			if phase == "Ready" || phase == "Expired" {
				response = try.To1(f.bobUseV2(saved.request, f.local.handle))
			}
			if phase == "Expired" {
				assert.That(try.To1(f.receiveUseV2(response)))
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
				var result SavedFirstUseV2
				result, err = f.startUseV2()
				assert.SNil(result.request)
			case "useSeen":
				var result []byte
				result, err = f.bobUseV2(saved.request, f.local.handle)
				assert.SNil(result)
			case "Ready":
				var ready bool
				ready, err = f.receiveUseV2(response)
				assert.ThatNot(ready)
			case "Expired":
				var expired bool
				expired, err = f.expireUseV2(true)
				assert.ThatNot(expired)
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
