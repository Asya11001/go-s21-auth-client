package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"
)

type Credentials struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type Client struct {
	client      *http.Client
	credentials Credentials
	token       TokenResponse
	mu          sync.Mutex
}

var (
	TokenUrl = "https://auth.sberclass.ru/auth/realms/EduPowerKeycloak/protocol/openid-connect/token"
)

func (ac *Client) getAccessToken() error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	data := fmt.Sprintf(
		"grant_type=password&client_id=s21-open-api&username=%s&password=%s",
		ac.credentials.Login, ac.credentials.Password,
	)

	req, err := http.NewRequest("POST", TokenUrl, bytes.NewBuffer([]byte(data)))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ac.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get access token: %s", string(body))
	}

	err = json.Unmarshal(body, &ac.token)
	if err != nil {
		return err
	}

	ac.token.ExpiresIn = int(time.Now().Unix()) + ac.token.ExpiresIn - 600
	return nil
}

func NewClient(credentials Credentials) *Client {
	return &Client{
		client:      &http.Client{},
		credentials: credentials,
	}
}

func (ac *Client) Do(req *http.Request) (*http.Response, error) {
	ac.mu.Lock()
	if ac.token.AccessToken == "" || time.Now().Unix() >= int64(ac.token.ExpiresIn) {
		ac.mu.Unlock()
		if err := ac.getAccessToken(); err != nil {
			return nil, err
		}
	} else {
		ac.mu.Unlock()
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ac.token.AccessToken))

	return ac.client.Do(req)
}
