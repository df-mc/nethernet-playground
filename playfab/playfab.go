package playfab

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
)

// PlayFab represents an instance of a Minecraft PlayFab client.
type PlayFab struct {
	src    oauth2.TokenSource
	client *http.Client

	id      string
	session string

	mcToken     string
	entityToken string
}

// New creates a new PlayFab client with the given entityToken source.
func New(client *http.Client, src oauth2.TokenSource) (*PlayFab, error) {
	p := &PlayFab{
		src:    src,
		client: client,
	}
	if err := p.acquireLoginToken(); err != nil {
		return nil, err
	}
	if err := p.acquireEntityToken(); err != nil {
		return nil, err
	}
	if err := p.acquireMCToken(); err != nil {
		return nil, err
	}
	return p, nil
}

// ID returns the PlayFab ID of the client.
func (p *PlayFab) ID() string {
	return p.id
}

// Session returns the PlayFab session ticket of the client.
func (p *PlayFab) Session() string {
	return p.session
}

// MCToken returns the Minecraft token of the client.
func (p *PlayFab) MCToken() string {
	return p.mcToken
}

// EntityToken returns the Entity token of the client.
func (p *PlayFab) EntityToken() string {
	return p.entityToken
}

// request sends a request to the PlayFab API.
func (p *PlayFab) request(url string, body any, res any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s.playfabapi.com/%s", minecraftTitleID, url), bytes.NewBuffer(b))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", minecraftUserAgent)
	req.Header.Set("X-PlayFabSDK", minecraftDefaultSDK)
	req.Header.Set("X-ReportErrorAsSuccess", "true")
	if len(p.entityToken) > 0 {
		req.Header.Set("X-EntityToken", p.entityToken)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return json.NewDecoder(resp.Body).Decode(&res)
}

// requestExternal sends a request outside the PlayFab API.
func (p *PlayFab) requestExternal(url string, body any, res any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(b))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", minecraftUserAgent)
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return json.NewDecoder(resp.Body).Decode(&res)
}
