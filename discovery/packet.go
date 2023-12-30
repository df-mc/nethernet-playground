package discovery

import "bytes"

const (
	IDRequest uint16 = iota
	IDResponse
	IDMessage
)

type Packet interface {
	ID() uint16
	Read(buf *bytes.Buffer) error
	Write(buf *bytes.Buffer)
}
