package discovery

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
)

type ResponsePacket struct {
	NetherNetVersion uint8
	ServerName       []byte
	LevelName        []byte
	GameType         int32
	PlayerCount      int32
	MaxPlayers       int32
	EditorWorld      bool
	TransportLayer   int32
}

func (*ResponsePacket) ID() uint16 {
	return IDResponse
}

func (pk *ResponsePacket) Read(buf *bytes.Buffer) error {
	var length uint32
	_ = binary.Read(buf, binary.LittleEndian, &length)
	encoded := make([]byte, length)
	var decoded []byte
	_, _ = buf.Read(encoded)
	_, _ = hex.Decode(decoded, encoded)
	buf = bytes.NewBuffer(decoded)

	var serverNameLength, levelNameLength byte // TODO: Should be uint32
	_ = binary.Read(buf, binary.LittleEndian, &pk.NetherNetVersion)
	_ = binary.Read(buf, binary.LittleEndian, &serverNameLength) // TODO: Should be Varuint32
	pk.ServerName = make([]byte, serverNameLength)
	_, _ = buf.Read(pk.ServerName)
	_ = binary.Read(buf, binary.LittleEndian, &levelNameLength) // TODO: Should be Varuint32
	pk.LevelName = make([]byte, levelNameLength)
	_, _ = buf.Read(pk.LevelName)
	_ = binary.Read(buf, binary.LittleEndian, &pk.GameType)
	_ = binary.Read(buf, binary.LittleEndian, &pk.PlayerCount)
	_ = binary.Read(buf, binary.LittleEndian, &pk.MaxPlayers)
	_ = binary.Read(buf, binary.LittleEndian, &pk.EditorWorld)
	return binary.Read(buf, binary.LittleEndian, &pk.TransportLayer)
}

func (pk *ResponsePacket) Write(buf *bytes.Buffer) {
	_ = binary.Write(buf, binary.LittleEndian, pk.NetherNetVersion)
	_ = binary.Write(buf, binary.LittleEndian, byte(len(pk.ServerName))) // TODO: Should be Varuint32
	_ = binary.Write(buf, binary.LittleEndian, pk.ServerName)
	_ = binary.Write(buf, binary.LittleEndian, byte(len(pk.LevelName))) // TODO: Should be Varuint32
	_ = binary.Write(buf, binary.LittleEndian, pk.LevelName)
	_ = binary.Write(buf, binary.LittleEndian, pk.GameType)
	_ = binary.Write(buf, binary.LittleEndian, pk.PlayerCount)
	_ = binary.Write(buf, binary.LittleEndian, pk.MaxPlayers)
	_ = binary.Write(buf, binary.LittleEndian, pk.EditorWorld)
	_ = binary.Write(buf, binary.LittleEndian, pk.TransportLayer)

	var encoded []byte
	hex.Encode(encoded, buf.Bytes())
	buf.Reset()
	_ = binary.Write(buf, binary.LittleEndian, uint32(len(encoded)))
	_ = binary.Write(buf, binary.LittleEndian, encoded)
}
