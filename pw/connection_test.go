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
		assert.That(a1.IsAddresser)
		assert.Equal(a1.Addresser.String(), h1.String())
		assert.Equal(a1.Addressee.String(), h2.String())

		assert.That(a1.TheirIDK().Equal(a1.Addressee.Public))
		assert.That(a1.OurIDK().Equal(a1.Addresser.Public))

		// As can be seen we are NOT addresser
		a2 := New(!weAreAddresser, h1Endp, h2Endp)
		assert.NotNil(a2)
		assert.ThatNot(a2.IsAddresser)

		assert.Equal(a2.Addresser.String(), h1.String(),
			"same direction as if would constructed as addresser")
		assert.Equal(a2.Addressee.String(), h2.String(),
			"same direction as if would constructed as addresser")

		assert.That(a2.TheirIDK().Equal(a2.Addresser.Public))
		assert.That(a2.OurIDK().Equal(a2.Addressee.Public))
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
