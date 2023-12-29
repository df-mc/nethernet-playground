package xbxlive

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

type XBXLive struct {
	src    oauth2.TokenSource
	client *http.Client

	key *ecdsa.PrivateKey

	token string
	xuid  string
}

func New(client *http.Client, src oauth2.TokenSource) (*XBXLive, error) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := &XBXLive{
		src:    src,
		client: client,

		key: key,
	}
	if err := p.acquireToken(); err != nil {
		return nil, err
	}
	return p, nil
}

func (x *XBXLive) acquireToken() error {
	token, err := x.src.Token()
	if err != nil {
		return err
	}
	t, err := auth.RequestXBLToken(context.Background(), token, "http://xboxlive.com")
	if err != nil {
		return err
	}

	x.xuid = t.AuthorizationToken.DisplayClaims.UserInfo[0].XUID
	x.token = fmt.Sprintf("XBL3.0 x=%v;%v", t.AuthorizationToken.DisplayClaims.UserInfo[0].UserHash, t.AuthorizationToken.Token)
	return nil
}

func (x *XBXLive) request(url string, body any, res any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(b))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en,en-US,en")
	req.Header.Set("Authorization", x.token)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "XboxServicesAPI/2022.10.20221025.1 c")
	req.Header.Set("x-xbl-contract-version", "107")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Host", "sessiondirectory.xboxlive.com")
	req.Header.Set("Connection", "Keep-Alive")
	req.Header.Set("Cache-Control", "no-cache")
	sign(req, b, x.key)

	resp, err := x.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return json.NewDecoder(resp.Body).Decode(&res)
}

func sign(request *http.Request, body []byte, key *ecdsa.PrivateKey) {
	currentTime := windowsTimestamp()
	hash := sha256.New()

	// Signature policy version (0, 0, 0, 1) + 0 byte.
	buf := bytes.NewBuffer([]byte{0, 0, 0, 1, 0})
	// Timestamp + 0 byte.
	_ = binary.Write(buf, binary.BigEndian, currentTime)
	buf.Write([]byte{0})
	hash.Write(buf.Bytes())

	// HTTP method, generally POST + 0 byte.
	hash.Write([]byte("POST"))
	hash.Write([]byte{0})
	// Request uri path + raw query + 0 byte.
	hash.Write([]byte(request.URL.Path + request.URL.RawQuery))
	hash.Write([]byte{0})

	// Authorization header if present, otherwise an empty string + 0 byte.
	hash.Write([]byte(request.Header.Get("Authorization")))
	hash.Write([]byte{0})

	// Body data (only up to a certain limit, but this limit is practically never reached) + 0 byte.
	hash.Write(body)
	hash.Write([]byte{0})

	// Sign the checksum produced, and combine the 'r' and 's' into a single signature.
	r, s, _ := ecdsa.Sign(rand.Reader, key, hash.Sum(nil))
	signature := append(r.Bytes(), s.Bytes()...)

	// The signature begins with 12 bytes, the first being the signature policy version (0, 0, 0, 1) again,
	// and the other 8 the timestamp again.
	buf = bytes.NewBuffer([]byte{0, 0, 0, 1})
	_ = binary.Write(buf, binary.BigEndian, currentTime)

	// Append the signature to the other 12 bytes, and encode the signature with standard base64 encoding.
	sig := append(buf.Bytes(), signature...)
	request.Header.Set("Signature", base64.StdEncoding.EncodeToString(sig))
}

func windowsTimestamp() int64 {
	return (time.Now().Unix() + 11644473600) * 10000000
}
