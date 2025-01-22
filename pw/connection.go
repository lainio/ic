package pw

import "github.com/lainio/ic/key"

type Connection struct {
	IDK      key.Public
	Endpoint string // TODO: we start with simple, but propably later we...
}

func New(idk key.Public, ep string) Connection {
	return Connection{
		IDK:      idk,
		Endpoint: ep,
	}
}
