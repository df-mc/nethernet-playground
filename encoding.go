package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

var packetPool = newPacketPool()

func decodeDiscoveryPacket(packetBytes []byte) (DiscoveryPacket, uint64, error) {
	checksum := packetBytes[:32]
	packetBytes = packetBytes[32:]

	decrypted, err := decryptECB(packetBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("error decrypting: %w", err)
	}

	hm := hmac.New(sha256.New, key[:])
	hm.Write(decrypted)

	ourChecksum := hm.Sum(nil)
	if !bytes.Equal(checksum, ourChecksum) {
		return nil, 0, fmt.Errorf("checksum mismatch: %v != %v", checksum, ourChecksum)
	}

	buf := bytes.NewBuffer(decrypted)
	reader := protocol.NewReader(buf, 0, true)

	length := buf.Len()

	var givenPacketLength uint16
	reader.Uint16(&givenPacketLength)

	if int(givenPacketLength) != length {
		return nil, 0, fmt.Errorf("packet length mismatch: %v != %v", givenPacketLength, buf.Len())
	}

	var packetType uint16
	reader.Uint16(&packetType)

	var senderID uint64
	reader.Uint64(&senderID)

	var currByte uint8
	for i := 0; i < 8; i++ {
		reader.Uint8(&currByte)
	}

	pk := packetPool[packetType]()
	pk.Marshal(reader)
	return pk, senderID, nil
}

func encodeDiscoveryPacket(senderId uint64, pk DiscoveryPacket) ([]byte, error) {
	buf := new(bytes.Buffer)
	writer := protocol.NewWriter(buf, 0)

	subBuf := new(bytes.Buffer)
	subWriter := protocol.NewWriter(subBuf, 0)

	respType := pk.ID()
	subWriter.Uint16(&respType)
	subWriter.Uint64(&senderId)

	pad := make([]byte, 8)
	subWriter.Bytes(&pad)

	pk.Marshal(subWriter)

	subBufLen := uint16(subBuf.Len()) + 2
	writer.Uint16(&subBufLen)

	subBufBytes := subBuf.Bytes()
	writer.Bytes(&subBufBytes)

	payload := buf.Bytes()
	encrypted, err := encryptECB(payload)
	if err != nil {
		return nil, fmt.Errorf("error encrypting: %w", err)
	}

	hm := hmac.New(sha256.New, key[:])
	hm.Write(payload)
	checksum := hm.Sum(nil)

	encrypted = append(checksum, encrypted...)
	return encrypted, nil
}
