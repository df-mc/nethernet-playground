package discovery

import (
	"bytes"
)

type RequestPacket struct{}

func (*RequestPacket) ID() uint16 {
	return IDRequest
}

func (*RequestPacket) Read(*bytes.Buffer) error {
	return nil
}

func (*RequestPacket) Write(*bytes.Buffer) {}
