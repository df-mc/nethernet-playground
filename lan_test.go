package main

import (
	"fmt"
	"github.com/kr/pretty"
	"math/rand"
	"net"
	"testing"
	"time"
)

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
			if ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() {
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

var conns = make(map[uint64]*lanConn)

type lanConn struct {
	id     uint64
	hostId uint64

	addr *net.UDPAddr

	closeChan               chan struct{}
	discoveryMessagePackets chan *DiscoveryMessagePacket
}

func newLanConn(addr *net.UDPAddr, id, hostId uint64) *lanConn {
	fmt.Println("New LAN connection:", addr.String())
	l := &lanConn{
		id:     id,
		hostId: hostId,

		addr: addr,

		closeChan:               make(chan struct{}),
		discoveryMessagePackets: make(chan *DiscoveryMessagePacket),
	}
	go l.readLoop()
	return l
}

func (c *lanConn) processDiscoveryMessagePacket(p *DiscoveryMessagePacket) {
	c.discoveryMessagePackets <- p
}

func (c *lanConn) readLoop() {
	for {
		select {
		case <-c.closeChan:
			return
		case msg := <-c.discoveryMessagePackets:
			pretty.Println("Received discovery message packet:", msg)
		case <-time.After(5 * time.Second):
			fmt.Println("Connection timed out:", c.addr.String())
			c.close()
			return
		}
	}
}

func (c *lanConn) close() {
	delete(conns, c.id)
	close(c.discoveryMessagePackets)
	close(c.closeChan)
}

func TestBroadcasting(t *testing.T) {
	sessionId := rand.Uint64()

	broadcastingAddress, err := broadcastAddress()
	if err != nil {
		panic(err)
	}

	fmt.Println("Broadcasting address:", broadcastingAddress.String())

	discoveryResponsePacket, err := encodeDiscoveryPacket(sessionId, &DiscoveryResponsePacket{
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

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	go func() {
		for {
			buf := make([]byte, 1024)
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				panic(err)
			}

			pk, senderID, err := decodeDiscoveryPacket(buf[:n])
			if err != nil {
				// Ignore invalid packets.
				continue
			}
			discoveryMessage, ok := pk.(*DiscoveryMessagePacket)
			if !ok {
				// Ignore non-message packets.
				continue
			}
			if discoveryMessage.Data == "Ping" {
				// For some reason, the retarded client sends a message with the text "Ping" when it first starts.
				// We don't want to construct a new LAN connection for this, so we just ignore it.
				continue
			}

			lanConn, ok := conns[senderID]
			if !ok {
				lanConn = newLanConn(addr, sessionId, senderID)
				conns[senderID] = lanConn
			}
			lanConn.processDiscoveryMessagePacket(discoveryMessage)
		}
	}()

	fmt.Println("Broadcasting!")
	fmt.Println(conn.LocalAddr())

	for {
		_, err = conn.WriteToUDP(discoveryResponsePacket, udpAddr)
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
			discoveryRequestPacket, err := encodeDiscoveryPacket(rand.Uint64(), &DiscoveryRequestPacket{})
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
			packet, senderId, err := decodeDiscoveryPacket(msg.data)
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
