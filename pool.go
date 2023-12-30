package main

import "nethernettest/discovery"

var packets = map[uint16]func() discovery.Packet{
	discovery.IDRequest: func() discovery.Packet {
		return &discovery.RequestPacket{}
	},
	discovery.IDResponse: func() discovery.Packet {
		return &discovery.ResponsePacket{}
	},
	discovery.IDMessage: func() discovery.Packet {
		return &discovery.MessagePacket{}
	},
}

type pool map[uint16]func() discovery.Packet

func newPacketPool() pool {
	p := pool{}
	for id, pk := range packets {
		p[id] = pk
	}
	return p
}
