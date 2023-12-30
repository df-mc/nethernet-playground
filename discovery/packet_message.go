package discovery

import (
	"bytes"
	"encoding/binary"
)

type MessagePacket struct {
	RecipientID uint64
	Message     []byte
}

func (*MessagePacket) ID() uint16 {
	return IDMessage
}

func (pk *MessagePacket) Read(buf *bytes.Buffer) error {
	var length uint32
	_ = binary.Read(buf, binary.LittleEndian, &pk.RecipientID)
	_ = binary.Read(buf, binary.LittleEndian, &length)
	pk.Message = make([]byte, length)
	_, err := buf.Read(pk.Message)
	return err
}

func (pk *MessagePacket) Write(buf *bytes.Buffer) {
	_ = binary.Write(buf, binary.LittleEndian, pk.RecipientID)
	_ = binary.Write(buf, binary.LittleEndian, uint32(len(pk.Message)))
	_ = binary.Write(buf, binary.LittleEndian, pk.Message)
}
