package main

import (
	"bytes"
	"encoding/hex"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	IDDiscoveryPacketTypeRequest = iota
	IDDiscoveryPacketTypeResponse
	IDDiscoveryPacketTypeMessage
)

type DiscoveryPacket interface {
	protocol.Marshaler

	ID() uint16
}

type DiscoveryRequestPacket struct{}

func (p *DiscoveryRequestPacket) ID() uint16 {
	return IDDiscoveryPacketTypeRequest
}

func (p *DiscoveryRequestPacket) Marshal(io protocol.IO) {
	// No fields to marshal.
}

type DiscoveryResponsePacket struct {
	ServerData
}

func (p *DiscoveryResponsePacket) ID() uint16 {
	return IDDiscoveryPacketTypeResponse
}

func (p *DiscoveryResponsePacket) Marshal(io protocol.IO) {
	if _, ok := io.(*protocol.Writer); ok {
		subBuf := &bytes.Buffer{}
		subWriter := protocol.NewWriter(subBuf, 0)
		p.ServerData.Marshal(subWriter)

		encodedServerData := []byte(hex.EncodeToString(subBuf.Bytes()))
		protocol.FuncSliceUint32Length(io, &encodedServerData, io.Uint8)
	} else {
		var hexEncodedServerData []byte
		protocol.FuncSliceUint32Length(io, &hexEncodedServerData, io.Uint8)

		encodedServerData, err := hex.DecodeString(string(hexEncodedServerData))
		if err != nil {
			panic(err)
		}

		subBuf := bytes.NewBuffer(encodedServerData)
		subReader := protocol.NewReader(subBuf, 0, true)
		p.ServerData.Marshal(subReader)
	}
}

type DiscoveryMessagePacket struct {
	RecipientID uint64
	Data        string
}

func (p *DiscoveryMessagePacket) ID() uint16 {
	return IDDiscoveryPacketTypeMessage
}

func (p *DiscoveryMessagePacket) Marshal(io protocol.IO) {
	io.Uint64(&p.RecipientID)
	if _, ok := io.(*protocol.Writer); ok {
		s := []byte(p.Data)
		protocol.FuncSliceUint32Length(io, &s, io.Uint8)
	} else {
		var s []byte
		protocol.FuncSliceUint32Length(io, &s, io.Uint8)
		p.Data = string(s)
	}
}

type ServerData struct {
	Version        byte
	ServerName     string
	LevelName      string
	GameType       int32
	Players        int32
	MaxPlayers     int32
	EditorWorld    bool
	TransportLayer int32
}

func (x *ServerData) Marshal(io protocol.IO) {
	io.Uint8(&x.Version)
	io.String(&x.ServerName)
	io.String(&x.LevelName)
	io.Int32(&x.GameType)
	io.Int32(&x.Players)
	io.Int32(&x.MaxPlayers)
	io.Bool(&x.EditorWorld)
	io.Int32(&x.TransportLayer)
}
