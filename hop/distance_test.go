package hop

import (
	"testing"

	"github.com/lainio/err2/assert"
)

func TestDistance_TakeShorter(t *testing.T) {
	type args struct {
		rhs Distance
	}
	tests := []struct {
		name     string
		d        Distance
		args     args
		wantSwap bool
	}{
		{"rhs smaller", 1, args{0}, true},
		{"d is NotConnected", NewNotConnected(), args{1}, true},

		{"rhs equal", 1, args{1}, false},
		{"rhs greater", 1, args{2}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			swaped := tt.d.PickShorter(tt.args.rhs)
			assert.Equal(swaped, tt.wantSwap)
		})
	}
}
