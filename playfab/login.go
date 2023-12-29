package playfab

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"strings"
	"time"
)

const (
	// minecraftTitleID represents the PlayFab title ID for Minecraft: Bedrock Edition.
	minecraftTitleID = "20ca2"
	// minecraftDefaultSDK represents the usual SDK sent by the Minecraft client.
	minecraftDefaultSDK = "XPlatCppSdk-3.6.190304"
	// minecraftUserAgent represents the usual user agent sent by the Minecraft client.
	minecraftUserAgent = "libhttpclient/1.0.0.0"
)

// infoRequestParameters represent parameters that can be modified to request more information from the PlayFab API.
// By default, these are hardcoded to whatever the Minecraft client usually requests.
type infoRequestParameters struct {
	CharacterInventories bool `json:"GetCharacterInventories"`
	CharacterList        bool `json:"GetCharacterList"`
	PlayerProfile        bool `json:"GetPlayerProfile"`
	PlayerStatistics     bool `json:"GetPlayerStatistics"`
	TitleData            bool `json:"GetTitleData"`
	UserAccountInfo      bool `json:"GetUserAccountInfo"`
	UserData             bool `json:"GetUserData"`
	UserInventory        bool `json:"GetUserInventory"`
	UserReadOnlyData     bool `json:"GetUserReadOnlyData"`
	UserVirtualCurrency  bool `json:"GetUserVirtualCurrency"`
	PlayerStatisticNames any  `json:"PlayerStatisticNames"`
	ProfileConstraints   any  `json:"ProfileConstraints"`
	TitleDataKeys        any  `json:"TitleDataKeys"`
	UserDataKeys         any  `json:"UserDataKeys"`
	UserReadOnlyDataKeys any  `json:"UserReadOnlyDataKeys"`
}

// loginRequest is a request sent by the client to the PlayFab API to obtain a temporary login entityToken.
type loginRequest struct {
	CreateAccount         bool                  `json:"CreateAccount"`
	EncryptedRequest      any                   `json:"EncryptedRequest"`
	InfoRequestParameters infoRequestParameters `json:"InfoRequestParameters"`
	PlayerSecret          any                   `json:"PlayerSecret"`
	TitleID               string                `json:"TitleId"`
	XboxToken             string                `json:"XboxToken"`
}

// loginResponse is a response sent by the PlayFab API to a login request.
type loginResponse struct {
	Code   int    `json:"code"`
	Status string `json:"status"`
	Data   struct {
		SessionTicket   string `json:"SessionTicket"`
		PlayFabID       string `json:"PlayFabId"`
		NewlyCreated    bool   `json:"NewlyCreated"`
		SettingsForUser struct {
			NeedsAttribution bool `json:"NeedsAttribution"`
			GatherDeviceInfo bool `json:"GatherDeviceInfo"`
			GatherFocusInfo  bool `json:"GatherFocusInfo"`
		} `json:"SettingsForUser"`
		LastLoginTime     time.Time `json:"LastLoginTime"`
		InfoResultPayload struct {
			AccountInfo struct {
				PlayFabID string    `json:"PlayFabId"`
				Created   time.Time `json:"Created"`
				TitleInfo struct {
					DisplayName        string    `json:"DisplayName"`
					Origination        string    `json:"Origination"`
					Created            time.Time `json:"Created"`
					LastLogin          time.Time `json:"LastLogin"`
					FirstLogin         time.Time `json:"FirstLogin"`
					IsBanned           bool      `json:"isBanned"`
					TitlePlayerAccount struct {
						ID         string `json:"Id"`
						Type       string `json:"Type"`
						TypeString string `json:"TypeString"`
					} `json:"TitlePlayerAccount"`
				} `json:"TitleInfo"`
				PrivateInfo struct {
				} `json:"PrivateInfo"`
				XboxInfo struct {
					XboxUserID      string `json:"XboxUserId"`
					XboxUserSandbox string `json:"XboxUserSandbox"`
				} `json:"XboxInfo"`
			} `json:"AccountInfo"`
			UserInventory           []any `json:"UserInventory"`
			UserDataVersion         int   `json:"UserDataVersion"`
			UserReadOnlyDataVersion int   `json:"UserReadOnlyDataVersion"`
			CharacterInventories    []any `json:"CharacterInventories"`
			PlayerProfile           struct {
				PublisherID string `json:"PublisherId"`
				TitleID     string `json:"TitleId"`
				PlayerID    string `json:"PlayerId"`
				DisplayName string `json:"DisplayName"`
			} `json:"PlayerProfile"`
		} `json:"InfoResultPayload"`
		EntityToken struct {
			EntityToken     string    `json:"EntityToken"`
			TokenExpiration time.Time `json:"TokenExpiration"`
			Entity          struct {
				ID         string `json:"Id"`
				Type       string `json:"Type"`
				TypeString string `json:"TypeString"`
			} `json:"Entity"`
		} `json:"EntityToken"`
		TreatmentAssignment struct {
			Variants  []any `json:"Variants"`
			Variables []any `json:"Variables"`
		} `json:"TreatmentAssignment"`
	} `json:"data"`
}

// entityData contains data about the entity, such as the entity ID or entity type.
type entityData struct {
	ID         string `json:"Id"`
	Type       string `json:"Type"`
	TypeString string `json:"TypeString,omitempty"`
}

// entityTokenRequest is sent by the client to the PlayFab API to request an entity entityToken for the session.
type entityTokenRequest struct {
	Entity entityData `json:"Entity"`
}

// entityTokenResponse is a response sent by the PlayFab API to an entityTokenRequest.
type entityTokenResponse struct {
	Code   int    `json:"code"`
	Status string `json:"status"`
	Data   struct {
		EntityToken     string     `json:"EntityToken"`
		TokenExpiration time.Time  `json:"TokenExpiration"`
		Entity          entityData `json:"Entity"`
	} `json:"data"`
}

// mcTokenDevice contains data about the device, such as the device ID or device model.
type mcTokenDevice struct {
	ApplicationType    string   `json:"applicationType"`
	Capabilities       []string `json:"capabilities"`
	GameVersion        string   `json:"gameVersion"`
	ID                 string   `json:"id"`
	Memory             string   `json:"memory"`
	Platform           string   `json:"platform"`
	PlayFabTitleID     string   `json:"playFabTitleId"`
	StorePlatform      string   `json:"storePlatform"`
	TreatmentOverrides any      `json:"treatmentOverrides"`
	Type               string   `json:"type"`
}

// mcTokenUser contains data about the user, such as the user ID or user locale.
type mcTokenUser struct {
	Language     string `json:"language"`
	LanguageCode string `json:"languageCode"`
	RegionCode   string `json:"regionCode"`
	Token        string `json:"token"`
	TokenType    string `json:"tokenType"`
}

// mcTokenRequest is sent by the client to the PlayFab API to request a Minecraft entityToken for the session.
type mcTokenRequest struct {
	Device mcTokenDevice `json:"device"`
	User   mcTokenUser   `json:"user"`
}

// mcTokenResponse is a response sent by the PlayFab API to an mcTokenRequest.
type mcTokenResponse struct {
	Result struct {
		AuthorizationHeader string    `json:"authorizationHeader"`
		ValidUntil          time.Time `json:"validUntil"`
		Treatments          []string  `json:"treatments"`
		Configurations      struct {
			Minecraft struct {
				ID         string         `json:"id"`
				Parameters map[string]any `json:"parameters"`
			} `json:"minecraft"`
		} `json:"configurations"`
	} `json:"result"`
}

// acquireLoginToken acquires the temporary login entityToken that will be used to acquire the entity entityToken, using the Xbox
// Live entityToken.
func (p *PlayFab) acquireLoginToken() error {
	token, err := p.src.Token()
	if err != nil {
		return err
	}
	t, err := auth.RequestXBLToken(context.Background(), token, "rp://playfabapi.com/")
	if err != nil {
		return err
	}

	var resp loginResponse
	if err = p.request(fmt.Sprintf("Client/LoginWithXbox?sdk=%s", minecraftDefaultSDK), loginRequest{
		CreateAccount: true,
		InfoRequestParameters: infoRequestParameters{
			PlayerProfile:   true,
			UserAccountInfo: true,
		},
		TitleID:   strings.ToUpper(minecraftTitleID),
		XboxToken: fmt.Sprintf("XBL3.0 x=%v;%v", t.AuthorizationToken.DisplayClaims.UserInfo[0].UserHash, t.AuthorizationToken.Token),
	}, &resp); err != nil {
		return err
	}

	p.id = resp.Data.PlayFabID
	p.session = resp.Data.SessionTicket
	p.entityToken = resp.Data.EntityToken.EntityToken
	return nil
}

// acquireEntityToken acquires the entity entityToken that will be used for the rest of the session, and updates the PlayFab
// instance with the new entityToken.
func (p *PlayFab) acquireEntityToken() error {
	var resp entityTokenResponse
	if err := p.request(fmt.Sprintf("Authentication/GetEntityToken?sdk=%s", minecraftDefaultSDK), entityTokenRequest{Entity: entityData{
		ID:   p.id,
		Type: "master_player_account",
	}}, &resp); err != nil {
		return err
	}

	p.entityToken = resp.Data.EntityToken
	return nil
}

// acquireMCToken acquires the MCToken used for various other Minecraft services.
func (p *PlayFab) acquireMCToken() error {
	request := mcTokenRequest{
		Device: mcTokenDevice{
			ApplicationType:    "MinecraftPE",
			Capabilities:       []string{"RayTracing"},
			GameVersion:        protocol.CurrentVersion,
			ID:                 uuid.New().String(),
			Memory:             fmt.Sprint(16 * (1024 * 1024 * 1024)), // 16 GB
			Platform:           "Windows10",
			PlayFabTitleID:     strings.ToUpper(minecraftTitleID),
			StorePlatform:      "uwp.store",
			TreatmentOverrides: nil,
			Type:               "Windows10",
		},
		User: mcTokenUser{
			Language:     "en",
			LanguageCode: "en-US",
			RegionCode:   "US",
			Token:        p.session,
			TokenType:    "PlayFab",
		},
	}

	var resp mcTokenResponse
	if err := p.requestExternal(
		"https://authorization.franchise.minecraft-services.net/api/v1.0/session/start",
		request,
		&resp,
	); err != nil {
		return err
	}
	if len(resp.Result.AuthorizationHeader) == 0 {
		return fmt.Errorf("invalid mctoken response")
	}

	request.Device.TreatmentOverrides = []string{"mc-maelstrom-disable", "mc-enable-new-marketplace-button", "mc-pf-retry-enabled", "mc-enable-submit-feedback", "mcmktvlt-offerids-recos_lgbm3c", "mc-rp-nycminions", "mc-reco-algo13_20231212", "mc-oneds-prod", "mc-rp-icons", "mc-persona-realms", "mc-nyc-jaws-v3", "mc-store-new-morebycreator-exp2", "mc-aatest-evergreencf", "mc-en-ic", "mc-rp-hero-row-timer-3", "mc-disable-legacypatchnotes", "mc-enable-service-entitlements-managercf", "mc-signaling-usewebsockets", "mc-rp-morelicensedsidebar", "mc-ul-wish2", "mc-live-events", "mc-signaling-useturn", "mc-sunsetting_1", "mcherorowtest2"}

	if err := p.requestExternal(
		"https://authorization.franchise.minecraft-services.net/api/v1.0/session/start",
		request,
		&resp,
	); err != nil {
		return err
	}
	if len(resp.Result.AuthorizationHeader) == 0 {
		return fmt.Errorf("invalid mctoken response")
	}

	p.mcToken = resp.Result.AuthorizationHeader
	return nil
}
