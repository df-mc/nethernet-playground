package main

var packets = map[uint16]func() Packet{
	IDDiscoveryPacketTypeRequest: func() Packet {
		return &DiscoveryRequestPacket{}
	},
	IDDiscoveryPacketTypeResponse: func() Packet {
		return &DiscoveryResponsePacket{}
	},
	IDDiscoveryPacketTypeMessage: func() Packet {
		return &DiscoveryMessagePacket{}
	},
}

type pool map[uint16]func() Packet

func newPacketPool() pool {
	p := pool{}
	for id, pk := range packets {
		p[id] = pk
	}
	return p
}
