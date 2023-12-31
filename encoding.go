package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"nethernettest/discovery"
)

func decodeDiscoveryPacket(rawData []byte) (discovery.Packet, uint64, error) {
	data, err := decryptECB(rawData[32:])
	if err != nil {
		return nil, 0, fmt.Errorf("error decrypting: %w", err)
	}

	hm := hmac.New(sha256.New, key[:])
	hm.Write(data)
	if checksum := hm.Sum(nil); !bytes.Equal(rawData[:32], checksum) {
		return nil, 0, fmt.Errorf("checksum mismatch: %v != %v", rawData[:32], checksum)
	}

	var length, pkID uint16
	var senderID uint64
	buf := bytes.NewBuffer(data)
	_ = binary.Read(buf, binary.LittleEndian, &length)
	_ = binary.Read(buf, binary.LittleEndian, &pkID)
	_ = binary.Read(buf, binary.LittleEndian, &senderID)
	buf.Next(8)

	var pk discovery.Packet
	switch pkID {
	case discovery.IDRequest:
		pk = &discovery.RequestPacket{}
	case discovery.IDResponse:
		pk = &discovery.ResponsePacket{}
	case discovery.IDMessage:
		pk = &discovery.MessagePacket{}
	default:
		return nil, 0, fmt.Errorf("unknown packet ID %v", pkID)
	}
	if err := pk.Read(buf); err != nil {
		return nil, 0, fmt.Errorf("error reading packet %d: %w", pkID, err)
	}
	return pk, senderID, nil
}

func encodeDiscoveryPacket(senderID uint64, pk discovery.Packet) ([]byte, error) {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, pk.ID())
	_ = binary.Write(buf, binary.LittleEndian, senderID)
	_ = binary.Write(buf, binary.LittleEndian, make([]byte, 8))
	pk.Write(buf)

	length := len(buf.Bytes())
	payload := append([]byte{byte(length), byte(length >> 8)}, buf.Bytes()...)
	data, err := encryptECB(payload)
	if err != nil {
		return nil, fmt.Errorf("error encrypting: %w", err)
	}

	hm := hmac.New(sha256.New, key[:])
	hm.Write(payload)
	data = append(hm.Sum(nil), data...)
	return data, nil
}
