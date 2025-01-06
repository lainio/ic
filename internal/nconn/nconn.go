package nconn

import (
	"github.com/golang/glog"
	_ "github.com/lainio/err2/assert" // make sure we got flags
	"github.com/lainio/err2/try"
	nats "github.com/nats-io/nats.go"
)

type NConn struct {
	*nats.EncodedConn
}

func New(codec string) *NConn {
	glog.V(4).Infoln("new NATS conn, type:", codec)
	nc := try.To1(nats.Connect(nats.DefaultURL))
	if codec == CBOR_DECODER {
		ec := &nats.EncodedConn{Conn: nc, Enc: ourCodec} //nolint:staticcheck
		return &NConn{ec}
	}
	return &NConn{try.To1(nats.NewEncodedConn(nc, codec))} //nolint:staticcheck
}

func (nc NConn) Pub(_ string) {

}
