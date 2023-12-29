package xbxlive

import (
	"encoding/json"
	"time"
)

const serviceConfigID = `4fc10100-5f7a-4470-899b-280835760c07`

type friendsRequestPeople struct {
	Moniker     string `json:"moniker"`
	MonikerXUID string `json:"monikerXuid"`
}

type friendsRequestOwners struct {
	People friendsRequestPeople `json:"people"`
}

type friendsRequest struct {
	Type   string               `json:"type"`
	SCID   string               `json:"scid"`
	Owners friendsRequestOwners `json:"owners"`
}

type friendsResponse struct {
	Results []struct {
		Type       string `json:"type"`
		SessionRef struct {
			Scid         string `json:"scid"`
			TemplateName string `json:"templateName"`
			Name         string `json:"name"`
		} `json:"sessionRef"`
		Version        int    `json:"version"`
		TitleID        string `json:"titleId"`
		OwnerXuid      string `json:"ownerXuid"`
		ID             string `json:"id"`
		InviteProtocol string `json:"inviteProtocol"`
		GameTypes      struct {
			UwpDesktop struct {
				TitleID   string   `json:"titleId"`
				Pfn       string   `json:"pfn"`
				BoundPfns []string `json:"boundPfns"`
			} `json:"uwp-desktop"`
			Android struct {
			} `json:"android"`
			Win32 struct {
				TitleID string `json:"titleId"`
			} `json:"win32"`
			Ios struct {
			} `json:"ios"`
			Scarlett struct {
				TitleID string `json:"titleId"`
			} `json:"scarlett"`
			Tvos struct {
			} `json:"tvos"`
			Era struct {
				TitleID string `json:"titleId"`
			} `json:"era"`
			UwpXboxone struct {
				TitleID string `json:"titleId"`
				Pfn     string `json:"pfn"`
			} `json:"uwp-xboxone"`
		} `json:"gameTypes"`
		CreateTime  time.Time `json:"createTime"`
		RelatedInfo struct {
			JoinRestriction string    `json:"joinRestriction"`
			Closed          bool      `json:"closed"`
			MaxMembersCount int       `json:"maxMembersCount"`
			MembersCount    int       `json:"membersCount"`
			Visibility      string    `json:"visibility"`
			InviteProtocol  string    `json:"inviteProtocol"`
			PostedTime      time.Time `json:"postedTime"`
		} `json:"relatedInfo"`
		CustomProperties struct {
			Joinability             string      `json:"Joinability"`
			HostName                string      `json:"hostName"`
			OwnerID                 string      `json:"ownerId"`
			RakNetGUID              string      `json:"rakNetGUID"`
			Version                 string      `json:"version"`
			LevelID                 string      `json:"levelId"`
			WorldName               string      `json:"worldName"`
			WorldType               string      `json:"worldType"`
			Protocol                int         `json:"protocol"`
			MemberCount             int         `json:"MemberCount"`
			MaxMemberCount          int         `json:"MaxMemberCount"`
			BroadcastSetting        int         `json:"BroadcastSetting"`
			LanGame                 bool        `json:"LanGame"`
			IsEditorWorld           bool        `json:"isEditorWorld"`
			TransportLayer          int         `json:"TransportLayer"`
			WebRTCNetworkID         json.Number `json:"WebRTCNetworkId"`
			OnlineCrossPlatformGame bool        `json:"OnlineCrossPlatformGame"`
			CrossPlayDisabled       bool        `json:"CrossPlayDisabled"`
			TitleID                 int         `json:"TitleId"`
			SupportedConnections    []struct {
				ConnectionType  int         `json:"ConnectionType"`
				HostIPAddress   string      `json:"HostIpAddress"`
				HostPort        int         `json:"HostPort"`
				WebRTCNetworkID json.Number `json:"WebRTCNetworkId"`
			} `json:"SupportedConnections"`
		} `json:"customProperties"`
	} `json:"results"`
}

type FriendConnection struct {
	ConnectionType  int
	HostIPAddress   string
	HostPort        int
	WebRTCNetworkID string
}

type Friend struct {
	Joinability             string
	HostName                string
	OwnerID                 string
	RakNetGUID              string
	Version                 string
	LevelID                 string
	WorldName               string
	WorldType               string
	Protocol                int
	MemberCount             int
	MaxMemberCount          int
	BroadcastSetting        int
	LanGame                 bool
	IsEditorWorld           bool
	TransportLayer          int
	WebRTCNetworkID         string
	OnlineCrossPlatformGame bool
	CrossPlayDisabled       bool
	TitleID                 int
	SupportedConnections    []FriendConnection `json:"SupportedConnections"`
}

func (x *XBXLive) Friends() ([]Friend, error) {
	var resp friendsResponse
	if err := x.request(
		"https://sessiondirectory.xboxlive.com/handles/query?include=relatedInfo,customProperties",
		friendsRequest{
			Type: "activity",
			SCID: serviceConfigID,
			Owners: friendsRequestOwners{
				People: friendsRequestPeople{
					Moniker:     "people",
					MonikerXUID: x.xuid,
				},
			},
		},
		&resp,
	); err != nil {
		return nil, err
	}

	friends := make([]Friend, 0, len(resp.Results))
	for _, result := range resp.Results {
		supportedConnections := make([]FriendConnection, 0, len(result.CustomProperties.SupportedConnections))
		for _, connection := range result.CustomProperties.SupportedConnections {
			supportedConnections = append(supportedConnections, FriendConnection{
				ConnectionType:  connection.ConnectionType,
				HostIPAddress:   connection.HostIPAddress,
				HostPort:        connection.HostPort,
				WebRTCNetworkID: string(connection.WebRTCNetworkID),
			})
		}
		friends = append(friends, Friend{
			Joinability:             result.CustomProperties.Joinability,
			HostName:                result.CustomProperties.HostName,
			OwnerID:                 result.CustomProperties.OwnerID,
			RakNetGUID:              result.CustomProperties.RakNetGUID,
			Version:                 result.CustomProperties.Version,
			LevelID:                 result.CustomProperties.LevelID,
			WorldName:               result.CustomProperties.WorldName,
			WorldType:               result.CustomProperties.WorldType,
			Protocol:                result.CustomProperties.Protocol,
			MemberCount:             result.CustomProperties.MemberCount,
			MaxMemberCount:          result.CustomProperties.MaxMemberCount,
			BroadcastSetting:        result.CustomProperties.BroadcastSetting,
			LanGame:                 result.CustomProperties.LanGame,
			IsEditorWorld:           result.CustomProperties.IsEditorWorld,
			TransportLayer:          result.CustomProperties.TransportLayer,
			WebRTCNetworkID:         string(result.CustomProperties.WebRTCNetworkID),
			OnlineCrossPlatformGame: result.CustomProperties.OnlineCrossPlatformGame,
			CrossPlayDisabled:       result.CustomProperties.CrossPlayDisabled,
			TitleID:                 result.CustomProperties.TitleID,
			SupportedConnections:    supportedConnections,
		})
	}
	return friends, nil
}
