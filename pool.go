package main

var packets = map[uint16]func() DiscoveryPacket{
	IDDiscoveryPacketTypeRequest: func() DiscoveryPacket {
		return &DiscoveryRequestPacket{}
	},
	IDDiscoveryPacketTypeResponse: func() DiscoveryPacket {
		return &DiscoveryResponsePacket{}
	},
	IDDiscoveryPacketTypeMessage: func() DiscoveryPacket {
		return &DiscoveryMessagePacket{}
	},
}

type pool map[uint16]func() DiscoveryPacket

func newPacketPool() pool {
	p := pool{}
	for id, pk := range packets {
		p[id] = pk
	}
	return p
}
