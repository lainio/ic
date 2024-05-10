package chain

import (
	"bytes"
	"encoding/gob"

	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
)

// Block is the block in our invitation Chain (IC). Note that Invitee
// is an important field, because its data must be same at the node
// level. They verify that otherwise separated ICs belong to the same node!
type Block struct {
	HashToPrev key.Hash // TODO: check the size later => 32, TODO: make own type
	Invitee    key.Info
	Options

	InvitersSignature key.Signature

	// TODO: where we should put our specific chain types? To keep it simple
	// this is a good place. However, we have a Chain type as well. They belong
	// to Identity, and Node will be changed to concept of invitation chains,
	// maybe named like that as well.

	// TODO: about endopints:
	// We don't want any static rounting, i.e., we try to avoid the need of
	// envelope until have to. That means that if we have Active Nodes that
	// serve their ancestors, those ansestor client apps connect nodes directly
	// anw we use only one lvl envelope for those cases. This might lead to
	// rule that only those Identies who have their own Active Nodes can
	// stream.
}

// NewVerifyBlock returns two randomized Blocks that can be used for
// verification or challenges, etc. First block is for challenge, i.e. pinCode
// is unknown aka 0, and second block is for actual signing where pincode is set
// to Position field. By this we can send pincode by other, safe channel.
func NewVerifyBlock(pinCode int) (Block, Block) {
	challengeBlock := Block{
		HashToPrev: key.RandSlice(32),
		Invitee:    key.RandInfo(32),
	}
	return challengeBlock, Block{
		HashToPrev: challengeBlock.HashToPrev,
		Invitee:    challengeBlock.Invitee,
		Options: Options{
			Position: pinCode,
		},
	}
}

// NewBlockFromData constructor from raw gob data block.
// TODO: start to use CBOR? for everything, all add as format?
func NewBlockFromData(d []byte) (b Block) {
	r := bytes.NewReader(d)
	dec := gob.NewDecoder(r)
	try.To(dec.Decode(&b))
	return b
}

func (b Block) Bytes() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	try.To(enc.Encode(b))
	return buf.Bytes()
}

func (b Block) ExcludeBytes() []byte {
	return b.excludeSign().Bytes()
}

func (b Block) excludeSign() Block {
	newBlock := Block{
		HashToPrev: b.HashToPrev,
		Invitee:    b.Invitee,
		Options: Options{
			Position: b.Position,
			Rotation: b.Rotation,
		},
	}
	return newBlock
}

func EqualBlocks(b1, b2 Block) bool {
	return key.EqualBytes(b1.HashToPrev, b2.HashToPrev) &&
		key.EqualBytes(b1.Invitee.ID, b2.Invitee.ID) &&
		key.EqualBytes(b1.Invitee.Public, b2.Invitee.Public) &&
		key.EqualBytes(b1.InvitersSignature, b2.InvitersSignature) &&
		b1.Position == b2.Position &&
		b1.Rotation == b2.Rotation
}

func (b Block) VerifySign(invitersPubKey key.Public) bool {
	return key.VerifySign(
		invitersPubKey,
		b.ExcludeBytes(),
		b.InvitersSignature,
	)
}

// TODO: move all options to own file?

type Opts func(*Options)

type Options struct {
	Position     int
	Rotation     bool
	AllowRouting bool
	Endpoint     string

	// TODO: future ones, endpoint or does this belong to key.Info? It might be
	// good if we could share same key with the Tor service and our ID?
	// However, the key rotation is as important as
}

func NewOptions(options ...Opts) *Options {
	opts := new(Options)
	for _, o := range options {
		o(opts)
	}
	return opts
}

func WithPosition(p int) Opts {
	return func(o *Options) {
		o.Position = p
	}
}

func WithRotation(r bool) Opts {
	return func(o *Options) {
		o.Rotation = r
	}
}

func WithAllowRouting(allow bool) Opts {
	return func(o *Options) {
		o.AllowRouting = allow
	}
}

func WithEndpoint(endpoint string) Opts {
	return func(o *Options) {
		o.Endpoint = endpoint
	}
}
