package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/pion/logging"
	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"golang.org/x/oauth2"
	"log"
	"math/rand"
	"net/http"
	"nethernettest/playfab"
	"nethernettest/xbxlive"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func main() {
	src := tokenSource()

	pf, err := playfab.New(http.DefaultClient, src)
	if err != nil {
		panic(err)
	}

	fmt.Println("Authenticated with PlayFab.")
	mcToken := pf.MCToken()

	xb, err := xbxlive.New(http.DefaultClient, src)
	if err != nil {
		panic(err)
	}

	fmt.Println("Authenticated with Xbox Live.")
	friends, err := xb.Friends()
	if err != nil {
		panic(err)
	}

	friend := friends[0]
	webrtcNetworkId := friend.WebRTCNetworkID
	fmt.Printf("Found friend: %s (%s)\n", friend.HostName, webrtcNetworkId)

	header := http.Header{}
	header.Add("Authorization", mcToken)

	c, _, err := websocket.DefaultDialer.Dial(
		fmt.Sprintf("wss://signal.franchise.minecraft-services.net/ws/v1.0/signaling/%d", rand.Uint64()),
		header,
	)
	if err != nil {
		panic(err)
	}
	defer c.Close()

	sessionId := rand.Uint64()

	_, message, err := c.ReadMessage()
	if err != nil {
		panic(err)
	}

	log.Printf("recv: %s", string(message))

	var fullConfigMessage messageFrom
	if err = json.Unmarshal(message, &fullConfigMessage); err != nil {
		panic(err)
	}
	if fullConfigMessage.Type != 2 {
		panic(fmt.Errorf("unexpected full config message type: expected 2, got %d", fullConfigMessage.Type))
	}
	if fullConfigMessage.From != "Server" {
		panic(fmt.Errorf("unexpected full config message from: expected Server, got %s", fullConfigMessage.From))
	}

	var webrtcConfig webRtcConfig
	if err = json.Unmarshal([]byte(fullConfigMessage.Message), &webrtcConfig); err != nil {
		panic(err)
	}

	iceServers := make([]webrtc.ICEServer, 0, len(webrtcConfig.TurnAuthServers))
	for _, turnAuthServer := range webrtcConfig.TurnAuthServers {
		iceServers = append(iceServers, webrtc.ICEServer{
			URLs:           turnAuthServer.Urls,
			Username:       turnAuthServer.Username,
			Credential:     turnAuthServer.Password,
			CredentialType: webrtc.ICECredentialTypePassword,
		})
	}

	factory := logging.NewDefaultLoggerFactory()
	factory.DefaultLogLevel = logging.LogLevelDebug

	var s webrtc.SettingEngine
	s.LoggerFactory = factory

	api := webrtc.NewAPI(webrtc.WithSettingEngine(s))
	gatherer, err := api.NewICEGatherer(webrtc.ICEGatherOptions{
		ICEServers: iceServers,
	})
	if err != nil {
		panic(err)
	}

	iceParams, err := gatherer.GetLocalParameters()
	if err != nil {
		panic(err)
	}

	ice := api.NewICETransport(gatherer)

	dtls, err := api.NewDTLSTransport(ice, nil)
	if err != nil {
		panic(err)
	}

	sctp := api.NewSCTPTransport(dtls)

	dtlsParams, err := dtls.GetLocalParameters()
	if err != nil {
		panic(err)
	}
	if len(dtlsParams.Fingerprints) != 1 {
		panic(fmt.Errorf("expected 1 fingerprint, got %d", len(dtlsParams.Fingerprints)))
	}

	fingerprint := dtlsParams.Fingerprints[0]

	gatherFinished := make(chan struct{})
	gatherer.OnLocalCandidate(func(i *webrtc.ICECandidate) {
		if i == nil {
			close(gatherFinished)
		}
	})

	if err = gatherer.Gather(); err != nil {
		panic(err)
	}

	<-gatherFinished

	iceCandidates, err := gatherer.GetLocalCandidates()
	if err != nil {
		panic(err)
	}

	sctpCapabilities := sctp.GetCapabilities()

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
					{Key: "setup", Value: "actpass"},
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

	encodedMessage, err := json.Marshal(messageTo{
		Message: fmt.Sprintf("CONNECTREQUEST %d %s", sessionId, encodedSdpDesc),
		To:      json.Number(webrtcNetworkId),
		Type:    1,
	})
	if err != nil {
		panic(err)
	}

	err = c.WriteMessage(websocket.TextMessage, encodedMessage)
	if err != nil {
		panic(err)
	}

	log.Printf("wrote: %s", string(encodedMessage))

	for i, iceCandidate := range iceCandidates {
		sb := strings.Builder{}
		sb.WriteString("candidate:")
		sb.WriteString(iceCandidate.Foundation)
		sb.WriteRune(' ')
		sb.WriteRune('1')
		sb.WriteRune(' ')
		sb.WriteString("udp")
		sb.WriteRune(' ')
		sb.WriteString(strconv.Itoa(int(iceCandidate.Priority)))
		sb.WriteRune(' ')
		sb.WriteString(iceCandidate.Address)
		sb.WriteRune(' ')
		sb.WriteString(strconv.Itoa(int(iceCandidate.Port)))
		sb.WriteRune(' ')
		sb.WriteString("typ")
		sb.WriteRune(' ')
		sb.WriteString(iceCandidate.Typ.String())
		sb.WriteRune(' ')
		if iceCandidate.Typ == webrtc.ICECandidateTypeRelay || iceCandidate.Typ == webrtc.ICECandidateTypeSrflx {
			sb.WriteString("raddr")
			sb.WriteRune(' ')
			sb.WriteString(iceCandidate.RelatedAddress)
			sb.WriteRune(' ')
			sb.WriteString("rport")
			sb.WriteRune(' ')
			sb.WriteString(strconv.Itoa(int(iceCandidate.RelatedPort)))
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
		sb.WriteString(strconv.Itoa(i + 1))
		sb.WriteRune(' ')
		sb.WriteString("network-cost")
		sb.WriteRune(' ')
		sb.WriteRune('0') // fuck that shit

		encodedMessage, err = json.Marshal(messageTo{
			Message: fmt.Sprintf("CANDIDATEADD %d %s", sessionId, sb.String()),
			To:      json.Number(webrtcNetworkId),
			Type:    1,
		})
		if err != nil {
			panic(err)
		}

		err = c.WriteMessage(websocket.TextMessage, encodedMessage)
		if err != nil {
			panic(err)
		}

		log.Printf("wrote: %s", string(encodedMessage))
	}

	messages := make(chan []byte)
	go func() {
		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				close(messages)
				return
			}
			messages <- message
		}
	}()

	var (
		peerIceParams  webrtc.ICEParameters
		peerDTLSParams webrtc.DTLSParameters
		peerSCTPParams webrtc.SCTPCapabilities

		closedReady bool
		ready       = make(chan struct{})
	)
	go func() {
		for {
			select {
			case message, ok := <-messages:
				if !ok {
					// Channel is closed, which means an error occurred
					return
				}

				var fullMessage messageFrom
				if err = json.Unmarshal(message, &fullMessage); err != nil {
					panic(err)
				}

				messageParts := strings.Split(fullMessage.Message, " ")
				messageId, providedSessionId, actualMessage := messageParts[0], messageParts[1], strings.Join(messageParts[2:], " ")
				if fmt.Sprintf("%d", sessionId) != providedSessionId {
					panic(fmt.Errorf("unexpected session id: expected '%d', got '%s'", sessionId, providedSessionId))
				}

				switch messageId {
				case "CONNECTRESPONSE":
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

					peerIceParams.UsernameFragment = iceUFrag
					peerIceParams.Password = icePwd

					fingerprintParts := strings.Split(peerFp, " ")
					peerDTLSParams.Fingerprints = append(peerDTLSParams.Fingerprints, webrtc.DTLSFingerprint{
						Algorithm: fingerprintParts[0],
						Value:     fingerprintParts[1],
					})
					peerDTLSParams.Role = webrtc.DTLSRoleClient

					maxMessageSizeInt, err := strconv.Atoi(maxMessageSize)
					if err != nil {
						panic(err)
					}

					peerSCTPParams.MaxMessageSize = uint32(maxMessageSizeInt)
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

					err = ice.AddRemoteCandidate(&webrtc.ICECandidate{
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

					if !closedReady {
						close(ready)
						closedReady = true
					}
				}
			}
		}
	}()

	fmt.Println("waiting for at least one candidate")

	<-ready

	fmt.Println("starting ice connection")
	fmt.Println(peerIceParams)

	role := webrtc.ICERoleControlled
	if err = ice.Start(nil, peerIceParams, &role); err != nil {
		panic(err)
	}

	fmt.Println("started, starting dtls connection")
	fmt.Println(peerDTLSParams)

	if err = dtls.Start(peerDTLSParams); err != nil {
		panic(err)
	}

	fmt.Println("starting sctp connection")

	if err = sctp.Start(peerSCTPParams); err != nil {
		panic(err)
	}

	fmt.Println("started!")

	reliableDataChannel, err := api.NewDataChannel(sctp, &webrtc.DataChannelParameters{Label: "ReliableDataChannel"})
	if err != nil {
		panic(err)
	}

	unreliableDataChannel, err := api.NewDataChannel(sctp, &webrtc.DataChannelParameters{Label: "UnreliableDataChannel", Ordered: false})
	if err != nil {
		panic(err)
	}

	fmt.Println("created channels!")

	unreliableDataChannel.OnMessage(func(msg webrtc.DataChannelMessage) {
		fmt.Printf("Unreliable Message: '%x'\n", msg.Data)
	})
	reliableDataChannel.OnMessage(func(msg webrtc.DataChannelMessage) {
		fmt.Printf("Reliable Message: '%x'\n", msg.Data)
	})
	reliableDataChannel.OnError(func(err error) {
		panic(err)
	})

	payload, _ := hex.DecodeString(`0006c10100000276`)
	err = reliableDataChannel.Send(payload)
	if err != nil {
		panic(err)
	}

	select {}
}

var candidateRegexp = regexp.MustCompile(`candidate:(\d+) 1 udp (\d+) (.*?) (\d+) typ (host|srflx|relay) (?:raddr (.*?) rport (\d+) )?generation 0 ufrag (.*?) network-id (\d+)(?: network-cost (\d+))?`)

type messageTo struct {
	Message string      `json:"Message"`
	To      json.Number `json:"To"`
	Type    int         `json:"Type"`
}

type messageFrom struct {
	Type    int    `json:"Type"`
	From    string `json:"From"`
	Message string `json:"Message"`
}

func tokenSource() oauth2.TokenSource {
	token := new(oauth2.Token)
	data, err := os.ReadFile("token.tok")
	if err == nil {
		_ = json.Unmarshal(data, token)
	} else {
		token, err = auth.RequestLiveToken()
		if err != nil {
			panic(err)
		}
	}
	src := auth.RefreshTokenSource(token)
	_, err = src.Token()
	if err != nil {
		token, err = auth.RequestLiveToken()
		if err != nil {
			panic(err)
		}
		src = auth.RefreshTokenSource(token)
	}
	tok, _ := src.Token()
	b, _ := json.Marshal(tok)
	_ = os.WriteFile("token.tok", b, 0644)
	return src
}
