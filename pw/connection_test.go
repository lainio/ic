package pw

import (
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/key"
)

func TestNew(t *testing.T) {
	defer assert.PushTester(t)()

	{
		h1 := key.NewHand()
		h2 := key.NewHand()
		weAreAddresser := true
		h1Endp := ConnEndpoint{*h1.Info, "h1_endp"}
		h2Endp := ConnEndpoint{*h2.Info, "h2_endp"}

		a1 := New(weAreAddresser, h1Endp, h2Endp)
		assert.NotNil(a1)
		assert.That(a1.IsAddressers)
		assert.Equal(a1.Addresser.String(), h1.String())
		assert.Equal(a1.Addressee.String(), h2.String())

		a2 := New(!weAreAddresser, h1Endp, h2Endp)
		assert.NotNil(a2)
		assert.ThatNot(a2.IsAddressers)
		assert.Equal(a2.Addresser.String(), h1.String())
		assert.Equal(a2.Addressee.String(), h2.String())
	}
}

func TestNewFromData(t *testing.T) {
	defer assert.PushTester(t)()

	{
		h1 := key.NewHand()
		h2 := key.NewHand()
		weAreAddresser := true
		h1Endp := ConnEndpoint{*h1.Info, "h1_endp"}
		h2Endp := ConnEndpoint{*h2.Info, "h2_endp"}
		a1 := New(weAreAddresser, h1Endp, h2Endp)
		assert.NotNil(a1)

		d := a1.Data()
		clone := NewFromData(d)
		assert.NotNil(clone)
		assert.DeepEqual(clone, a1)
	}
}
