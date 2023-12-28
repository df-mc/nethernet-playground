package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"github.com/kr/pretty"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"math/rand"
	"net"
	"testing"
	"time"
)

var packetPool = newPacketPool()

func decodePacket(packetBytes []byte) (Packet, uint64, error) {
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

func encodePacket(senderId uint64, pk Packet) ([]byte, error) {
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

func broadcastAddress() (net.IP, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, i := range interfaces {
		addresses, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addresses {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil {
				continue
			}
			if ipNet.IP.IsPrivate() || ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() {
				continue
			}

			broadcast := make(net.IP, 4)
			for j := 0; j < 4; j++ {
				broadcast[j] = ip[j] | ^ipNet.Mask[j]
			}
			return broadcast, nil
		}
	}
	return nil, fmt.Errorf("no suitable broadcast address found")
}

func TestBroadcasting(t *testing.T) {
	broadcastingAddress, err := broadcastAddress()
	if err != nil {
		panic(err)
	}

	fmt.Println("Broadcasting address:", broadcastingAddress.String())

	discoveryResponsePacket, err := encodePacket(rand.Uint64(), &DiscoveryResponsePacket{
		ServerData{
			Version:        0x2,
			ServerName:     "NetherNet Testing!",
			LevelName:      "Tal",
			GameType:       0,
			Players:        1,
			MaxPlayers:     420,
			EditorWorld:    false,
			TransportLayer: 2,
		},
	})
	if err != nil {
		panic(err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:7551", broadcastingAddress.String()))
	if err != nil {
		panic(err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Println("Broadcasting!")
	fmt.Println(conn.LocalAddr())

	for {
		_, err = conn.Write(discoveryResponsePacket)
		if err != nil {
			panic(err)
		}
		time.Sleep(2 * time.Second)
	}
}

func TestLookForBroadcasts(t *testing.T) {
	broadcastingAddress, err := broadcastAddress()
	if err != nil {
		panic(err)
	}

	fmt.Println("Broadcasting address:", broadcastingAddress.String())

	listenConn, err := net.ListenPacket("udp", "0.0.0.0:7551")
	if err != nil {
		panic(err)
	}
	defer listenConn.Close()

	fmt.Println("Listening for broadcasts!")

	type message struct {
		data []byte
		addr net.Addr
	}
	messages := make(chan message)
	go func() {
		for {
			buf := make([]byte, 1024)
			n, addr, err := listenConn.ReadFrom(buf)
			if err != nil {
				return
			}
			messages <- message{
				data: buf[:n],
				addr: addr,
			}
		}
	}()

	ticker := time.NewTicker(2 * time.Second)
	for {
		select {
		case <-ticker.C:
			discoveryRequestPacket, err := encodePacket(rand.Uint64(), &DiscoveryRequestPacket{})
			if err != nil {
				panic(err)
			}
			if _, err := listenConn.WriteTo(discoveryRequestPacket, &net.UDPAddr{
				IP:   broadcastingAddress,
				Port: 7551,
			}); err != nil {
				panic(err)
			}
		case msg := <-messages:
			packet, senderId, err := decodePacket(msg.data)
			if err != nil {
				panic(err)
			}
			if _, ok := packet.(*DiscoveryResponsePacket); !ok {
				continue
			}
			pretty.Println(packet, senderId)
		}
	}
}
