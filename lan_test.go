package main

import (
	"bytes"
	"fmt"
	"github.com/kr/pretty"
	"github.com/pion/logging"
	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"math/rand"
	"net"
	"strconv"
	"strings"
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

var conns = make(map[uint64]*lanConn)

type lanConn struct {
	id     uint64
	hostId uint64

	sessionId uint64

	addr *net.UDPAddr
	conn *net.UDPConn

	api      *webrtc.API
	gatherer *webrtc.ICEGatherer

	ice *webrtc.ICETransport
	dtl *webrtc.DTLSTransport
	sct *webrtc.SCTPTransport

	candidates int

	peerIceParams  webrtc.ICEParameters
	peerDTLSParams webrtc.DTLSParameters
	peerSCTPParams webrtc.SCTPCapabilities

	closeChan               chan struct{}
	discoveryMessagePackets chan *DiscoveryMessagePacket
}

func newLanConn(conn *net.UDPConn, addr *net.UDPAddr, hostId, id uint64) (*lanConn, error) {
	fmt.Println("New LAN connection:", addr.String())
	fmt.Printf("Client ID: %d, Host ID: %d\n", id, hostId)

	factory := logging.NewDefaultLoggerFactory()
	factory.DefaultLogLevel = logging.LogLevelDebug

	var s webrtc.SettingEngine
	s.LoggerFactory = factory

	api := webrtc.NewAPI(webrtc.WithSettingEngine(s))

	gatherer, err := api.NewICEGatherer(webrtc.ICEGatherOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create ice gatherer: %w", err)
	}

	ice := api.NewICETransport(gatherer)
	dtl, err := api.NewDTLSTransport(ice, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create dtls transport: %w", err)
	}
	sct := api.NewSCTPTransport(dtl)

	l := &lanConn{
		id:     id,
		hostId: hostId,

		api:      api,
		gatherer: gatherer,

		ice: ice,
		dtl: dtl,
		sct: sct,

		addr: addr,
		conn: conn,

		closeChan:               make(chan struct{}),
		discoveryMessagePackets: make(chan *DiscoveryMessagePacket),
	}
	go l.readLoop()
	return l, nil
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
			messageParts := strings.Split(msg.Data, " ")
			messageId, providedSessionId, actualMessage := messageParts[0], messageParts[1], strings.Join(messageParts[2:], " ")
			parsedProvidedSessionId, err := strconv.ParseUint(providedSessionId, 10, 64)
			if err != nil {
				panic(err)
			}
			if c.sessionId == 0 {
				c.sessionId = parsedProvidedSessionId
			}
			if c.sessionId != parsedProvidedSessionId {
				panic(fmt.Errorf("unexpected session id: expected '%d', got '%d'", c.sessionId, parsedProvidedSessionId))
			}

			switch messageId {
			case "CONNECTREQUEST":
				var peerSD sdp.SessionDescription
				if err = peerSD.Unmarshal([]byte(actualMessage)); err != nil {
					panic(err)
				}

				if len(peerSD.MediaDescriptions) != 1 {
					panic(fmt.Errorf("expected 1 media description, got %d", len(peerSD.MediaDescriptions)))
				}

				mediaDescription := peerSD.MediaDescriptions[0]

				iceUFrag, ok := mediaDescription.Attribute("ice-ufrag")
				if !ok {
					panic(fmt.Errorf("missing ice-ufrag attribute"))
				}

				icePwd, ok := mediaDescription.Attribute("ice-pwd")
				if !ok {
					panic(fmt.Errorf("missing ice-pwd attribute"))
				}

				peerFp, ok := mediaDescription.Attribute("fingerprint")
				if !ok {
					panic(fmt.Errorf("missing fingerprint attribute"))
				}

				maxMessageSize, ok := mediaDescription.Attribute("max-message-size")
				if !ok {
					panic(fmt.Errorf("missing max-message-size attribute"))
				}

				c.peerIceParams.UsernameFragment = iceUFrag
				c.peerIceParams.Password = icePwd

				fingerprintParts := strings.Split(peerFp, " ")
				c.peerDTLSParams.Fingerprints = append(c.peerDTLSParams.Fingerprints, webrtc.DTLSFingerprint{
					Algorithm: fingerprintParts[0],
					Value:     fingerprintParts[1],
				})
				c.peerDTLSParams.Role = webrtc.DTLSRoleServer

				maxMessageSizeInt, err := strconv.Atoi(maxMessageSize)
				if err != nil {
					panic(err)
				}

				c.peerSCTPParams.MaxMessageSize = uint32(maxMessageSizeInt)
			case "CANDIDATEADD":
				matches := candidateRegexp.FindStringSubmatch(actualMessage)[1:]

				foundation := matches[0]
				priorityUnparsed := matches[1]
				address := matches[2]
				portUnparsed := matches[3]
				unparsedTyp := matches[4]
				relatedAddress := matches[5]
				relatedPortUnparsed := matches[6]

				priority, err := strconv.ParseUint(priorityUnparsed, 10, 32)
				if err != nil {
					panic(err)
				}
				port, err := strconv.ParseUint(portUnparsed, 10, 16)
				if err != nil {
					panic(err)
				}

				var relatedPort uint64
				if len(relatedAddress) > 0 && len(relatedPortUnparsed) > 0 {
					relatedPort, err = strconv.ParseUint(relatedPortUnparsed, 10, 16)
					if err != nil {
						panic(err)
					}
				}

				typ, err := webrtc.NewICECandidateType(unparsedTyp)
				if err != nil {
					panic(err)
				}

				err = c.ice.AddRemoteCandidate(&webrtc.ICECandidate{
					Foundation:     foundation,
					Priority:       uint32(priority),
					Address:        address,
					Protocol:       webrtc.ICEProtocolUDP,
					Port:           uint16(port),
					Typ:            typ,
					RelatedAddress: relatedAddress,
					RelatedPort:    uint16(relatedPort),
				})
				if err != nil {
					panic(err)
				}

				c.candidates++
				if c.candidates == 4 {
					c.sendConnectionInfo()
				}
			}

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

func (c *lanConn) sendConnectionInfo() {
	iceParams, err := c.gatherer.GetLocalParameters()
	if err != nil {
		panic(err)
	}

	dtlsParams, err := c.dtl.GetLocalParameters()
	if err != nil {
		panic(err)
	}
	if len(dtlsParams.Fingerprints) != 1 {
		panic(fmt.Errorf("expected 1 fingerprint, got %d", len(dtlsParams.Fingerprints)))
	}

	fingerprint := dtlsParams.Fingerprints[0]

	sctpCapabilities := c.sct.GetCapabilities()

	gatherFinished := make(chan struct{})
	c.gatherer.OnLocalCandidate(func(i *webrtc.ICECandidate) {
		if i == nil {
			close(gatherFinished)
		}
	})

	if err = c.gatherer.Gather(); err != nil {
		panic(err)
	}

	<-gatherFinished

	iceCandidates, err := c.gatherer.GetLocalCandidates()
	if err != nil {
		panic(err)
	}

	sdpDesc := sdp.SessionDescription{
		Origin:      sdp.Origin{Username: "-", SessionID: rand.Uint64(), SessionVersion: 0x2, NetworkType: "IN", AddressType: "IP4", UnicastAddress: "127.0.0.1"},
		SessionName: "-",
		TimeDescriptions: []sdp.TimeDescription{
			{},
		},
		Attributes: []sdp.Attribute{
			{Key: "group", Value: "BUNDLE 0"},
			{Key: "extmap-allow-mixed", Value: ""},
			{Key: "msid-semantic", Value: " WMS"},
		},
		MediaDescriptions: []*sdp.MediaDescription{
			{
				MediaName: sdp.MediaName{
					Media: "application",
					Port: sdp.RangedPort{
						Value: 9,
					},
					Protos:  []string{"UDP", "DTLS", "SCTP"},
					Formats: []string{"webrtc-datachannel"},
				},
				ConnectionInformation: &sdp.ConnectionInformation{
					NetworkType: "IN",
					AddressType: "IP4",
					Address: &sdp.Address{
						Address: "0.0.0.0",
					},
				},
				Attributes: []sdp.Attribute{
					{Key: "ice-ufrag", Value: iceParams.UsernameFragment},
					{Key: "ice-pwd", Value: iceParams.Password},
					{Key: "ice-options", Value: "trickle"},
					{Key: "fingerprint", Value: fmt.Sprintf("%s %s", fingerprint.Algorithm, fingerprint.Value)},
					{Key: "setup", Value: "active"},
					{Key: "mid", Value: "0"},
					{Key: "sctp-port", Value: "5000"},
					{Key: "max-message-size", Value: strconv.Itoa(int(sctpCapabilities.MaxMessageSize))},
				},
			},
		},
	}

	encodedSdpDesc, err := sdpDesc.Marshal()
	if err != nil {
		panic(err)
	}

	c.writeDiscoveryPacket(&DiscoveryMessagePacket{
		RecipientID: c.id,
		Data:        fmt.Sprintf("CONNECTRESPONSE %d %s", c.sessionId, encodedSdpDesc),
	})
	for id, candidate := range iceCandidates {
		c.writeDiscoveryPacket(&DiscoveryMessagePacket{
			RecipientID: c.id,
			Data: fmt.Sprintf(
				"CANDIDATEADD %d %s",
				c.sessionId,
				c.formatIceCandidate(id+1, candidate, iceParams),
			),
		})
	}

	fmt.Println("Waiting for ICE connection...")

	if err = c.ice.Start(nil, c.peerIceParams, nil); err != nil {
		panic(err)
	}

	fmt.Println("ICE connection established!")

	if err = c.dtl.Start(c.peerDTLSParams); err != nil {
		panic(err)
	}

	fmt.Println("DTLS connection established!")

	type message struct {
		reliable bool
		data     []byte
	}

	var (
		reliableChannel   *webrtc.DataChannel
		unreliableChannel *webrtc.DataChannel
		channelsReady     = make(chan struct{})

		messages = make(chan message)
	)
	c.sct.OnDataChannelOpened(func(channel *webrtc.DataChannel) {
		fmt.Printf("SCTP channel opened: %s\n", channel.Label())

		var reliable bool
		switch channel.Label() {
		case "ReliableDataChannel":
			reliableChannel = channel
			reliable = true
		case "UnreliableDataChannel":
			unreliableChannel = channel
		}
		if reliableChannel != nil && unreliableChannel != nil {
			close(channelsReady)
		}

		channel.OnMessage(func(msg webrtc.DataChannelMessage) {
			messages <- message{reliable: reliable, data: msg.Data}
		})
	})
	if err = c.sct.Start(c.peerSCTPParams); err != nil {
		panic(err)
	}

	<-channelsReady

	clientPool := packet.NewClientPool()
	var (
		compress bool

		currentPacket    []byte
		promisedSegments uint8
	)
	for {
		select {
		case msg := <-messages:
			messagePromisedSegments := msg.data[0]
			msg.data = msg.data[1:]

			if promisedSegments > 0 && promisedSegments-1 != messagePromisedSegments {
				panic(fmt.Errorf("invalid promised segments: %d != %d", promisedSegments-1, messagePromisedSegments))
			}
			promisedSegments = messagePromisedSegments

			currentPacket = append(currentPacket, msg.data...)

			if promisedSegments > 0 {
				continue
			}

			fmt.Println("Decoding packet...")

			decodedPacket, err := decodePacket(clientPool, currentPacket, compress)
			if err != nil {
				panic(err)
			}

			if promisedSegments == 0 {
				currentPacket = nil
			}

			pretty.Printf("Received packet (reliable: %v): %v\n", msg.reliable, pretty.Sprint(decodedPacket))

			switch decodedPacket.(type) {
			case *packet.RequestNetworkSettings:
				pk := &packet.NetworkSettings{
					CompressionThreshold: 256,
					CompressionAlgorithm: packet.CompressionAlgorithmFlate,
				}
				encodedPacket, err := encodePacket(pk, compress)
				if err != nil {
					panic(err)
				}
				compress = true
				pretty.Printf("Sending packet (reliable: true): %v\n", pretty.Sprint(pk))
				if err = reliableChannel.Send(append([]byte{0}, encodedPacket...)); err != nil { // todo: split into segments
					panic(err)
				}
			}
		}
	}

	fmt.Println("SCTP connection established!")
}

func decodePacket(pool packet.Pool, data []byte, compress bool) (packet.Packet, error) {
	if compress {
		var err error
		if data, err = packet.FlateCompression.Decompress(data); err != nil {
			return nil, fmt.Errorf("failed to decompress packet: %w", err)
		}
	}
	buf := bytes.NewBuffer(data)

	var length uint32
	if err := protocol.Varuint32(buf, &length); err != nil {
		return nil, fmt.Errorf("failed to read packet length: %w", err)
	}

	pkBytes := buf.Next(int(length))
	pkBuf := bytes.NewBuffer(pkBytes)

	header := &packet.Header{}
	if err := header.Read(pkBuf); err != nil {
		return nil, fmt.Errorf("failed to read packet header: %w", err)
	}

	pkFunc, ok := pool[header.PacketID]

	var pk packet.Packet
	if ok {
		pk = pkFunc()
	} else {
		fmt.Println("Unknown packet ID:", header.PacketID)
		pk = &packet.Unknown{PacketID: header.PacketID}
	}

	pk.Marshal(protocol.NewReader(pkBuf, 0, true))
	return pk, nil
}

func encodePacket(pk packet.Packet, compress bool) ([]byte, error) {
	pkBuf := bytes.NewBuffer(nil)
	pkWriter := protocol.NewWriter(pkBuf, 0)

	header := &packet.Header{PacketID: pk.ID()}
	if err := header.Write(pkBuf); err != nil {
		return nil, fmt.Errorf("failed to write packet header: %w", err)
	}

	pk.Marshal(pkWriter)

	buf := bytes.NewBuffer(nil)
	if err := protocol.WriteVaruint32(buf, uint32(pkBuf.Len())); err != nil {
		return nil, fmt.Errorf("failed to write packet length: %w", err)
	}
	buf.Write(pkBuf.Bytes())

	out := buf.Bytes()
	if compress {
		var err error
		if out, err = packet.FlateCompression.Compress(out); err != nil {
			return nil, fmt.Errorf("failed to compress packet: %w", err)
		}
	}
	return out, nil
}

func (c *lanConn) writeDiscoveryPacket(packet DiscoveryPacket) {
	packetBytes, err := encodeDiscoveryPacket(c.hostId, packet)
	if err != nil {
		panic(err)
	}
	if _, err = c.conn.WriteToUDP(packetBytes, c.addr); err != nil {
		panic(err)
	}
	pretty.Println("Wrote discovery packet:", packet)
}

func (c *lanConn) formatIceCandidate(networkId int, candidate webrtc.ICECandidate, iceParams webrtc.ICEParameters) string {
	sb := strings.Builder{}
	sb.WriteString("candidate:")
	sb.WriteString(candidate.Foundation)
	sb.WriteRune(' ')
	sb.WriteRune('1')
	sb.WriteRune(' ')
	sb.WriteString("udp")
	sb.WriteRune(' ')
	sb.WriteString(strconv.Itoa(int(candidate.Priority)))
	sb.WriteRune(' ')
	sb.WriteString(candidate.Address)
	sb.WriteRune(' ')
	sb.WriteString(strconv.Itoa(int(candidate.Port)))
	sb.WriteRune(' ')
	sb.WriteString("typ")
	sb.WriteRune(' ')
	sb.WriteString(candidate.Typ.String())
	sb.WriteRune(' ')
	if candidate.Typ == webrtc.ICECandidateTypeRelay || candidate.Typ == webrtc.ICECandidateTypeSrflx {
		sb.WriteString("raddr")
		sb.WriteRune(' ')
		sb.WriteString(candidate.RelatedAddress)
		sb.WriteRune(' ')
		sb.WriteString("rport")
		sb.WriteRune(' ')
		sb.WriteString(strconv.Itoa(int(candidate.RelatedPort)))
		sb.WriteRune(' ')
	}
	sb.WriteString("generation")
	sb.WriteRune(' ')
	sb.WriteRune('0')
	sb.WriteRune(' ')
	sb.WriteString("ufrag")
	sb.WriteRune(' ')
	sb.WriteString(iceParams.UsernameFragment)
	sb.WriteRune(' ')
	sb.WriteString("network-id")
	sb.WriteRune(' ')
	sb.WriteString(strconv.Itoa(networkId))
	sb.WriteRune(' ')
	sb.WriteString("network-cost")
	sb.WriteRune(' ')
	sb.WriteRune('0') // TODO: Actually calculate this?
	return sb.String()
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
				lanConn, err = newLanConn(conn, addr, sessionId, senderID)
				if err != nil {
					panic(err)
				}
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
