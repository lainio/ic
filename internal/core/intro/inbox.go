package intro

import (
	"bytes"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
)

// Inbox retains unverified path evidence for one receiver.
// Its zero value is ready for use. Use it through a pointer; do not copy it
// after use. Concurrent access requires synchronization by the owner.
type Inbox struct {
	paths []Path
}

// ReceivePath decodes and retains claims without verifying or promoting them.
// Parse errors leave the inbox unchanged. Empty paths and exact duplicate
// representations are successful no-ops; distinct paths keep receipt order.
func (in *Inbox) ReceivePath(data []byte) (err error) {
	defer err2.Handle(&err)

	path := try.To1(ParsePath(data))
	if len(path) == 0 {
		return nil
	}

	encoded := path.Bytes()
	for _, received := range in.paths {
		if bytes.Equal(received.Bytes(), encoded) {
			return nil
		}
	}

	in.paths = append(in.paths, path)
	return nil
}

// Paths returns independent deep copies in first-receipt order.
// The returned evidence is still unverified.
func (in *Inbox) Paths() []Path {
	paths := make([]Path, len(in.paths))
	for i, path := range in.paths {
		paths[i] = path.Clone()
	}
	return paths
}
