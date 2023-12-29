package main

import (
	"fmt"
	"github.com/pion/logging"
	"github.com/pion/webrtc/v4"
	"strconv"
	"strings"
)

type conn struct {
	api      *webrtc.API
	gatherer *webrtc.ICEGatherer

	ice *webrtc.ICETransport
	dtl *webrtc.DTLSTransport
	sct *webrtc.SCTPTransport
}

type webRtcConfig struct {
	Username            string `json:"Username"`
	Password            string `json:"Password"`
	ExpirationInSeconds int    `json:"ExpirationInSeconds"`
	TurnAuthServers     []struct {
		Username string   `json:"Username"`
		Password string   `json:"Password"`
		Urls     []string `json:"Urls"`
	} `json:"TurnAuthServers"`
}

func newConn(conf webRtcConfig) (*conn, error) {
	factory := logging.NewDefaultLoggerFactory()
	factory.DefaultLogLevel = logging.LogLevelDebug

	var s webrtc.SettingEngine
	s.LoggerFactory = factory

	api := webrtc.NewAPI(webrtc.WithSettingEngine(s))

	c := &conn{api: api}

	iceServers := make([]webrtc.ICEServer, 0, len(conf.TurnAuthServers))
	for _, turnAuthServer := range conf.TurnAuthServers {
		iceServers = append(iceServers, webrtc.ICEServer{
			URLs:           turnAuthServer.Urls,
			Username:       turnAuthServer.Username,
			Credential:     turnAuthServer.Password,
			CredentialType: webrtc.ICECredentialTypePassword,
		})
	}

	var err error
	c.gatherer, err = api.NewICEGatherer(webrtc.ICEGatherOptions{
		ICEServers: iceServers,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create ice gatherer: %w", err)
	}

	c.ice = api.NewICETransport(c.gatherer)
	if c.dtl, err = api.NewDTLSTransport(c.ice, nil); err != nil {
		return nil, fmt.Errorf("failed to create dtls transport: %w", err)
	}
	c.sct = api.NewSCTPTransport(c.dtl)
	return c, nil
}

func (c *conn) localCandidates() ([]webrtc.ICECandidate, error) {
	gatherFinished := make(chan struct{})
	c.gatherer.OnLocalCandidate(func(i *webrtc.ICECandidate) {
		if i == nil {
			close(gatherFinished)
		}
	})

	if err := c.gatherer.Gather(); err != nil {
		return nil, fmt.Errorf("failed to gather ice candidates: %w", err)
	}

	<-gatherFinished

	return c.gatherer.GetLocalCandidates()
}

func (c *conn) formatIceCandidate(networkId int, candidate webrtc.ICECandidate, iceParams webrtc.ICEParameters) string {
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
