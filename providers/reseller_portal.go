package providers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/Securepoint/oauth2_proxy/api"
	"github.com/patrickmn/go-cache"
)

type ResellerPortalProvider struct {
	*ProviderData
	*cache.Cache
	sync.Mutex
}

func NewResellerPortalProvider(p *ProviderData) *ResellerPortalProvider {
	p.ProviderName = "Reseller Portal"
	if p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "my.securepoint.de",
			Path:   "/oauth2/authorize",
		}
	}
	if p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "my.securepoint.de",
			Path:   "/oauth2/access_token",
		}
	}
	if p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{
			Scheme: "https",
			Host:   "my.securepoint.de",
			Path:   "/api/user",
		}
	}
	if p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}
	if p.Scope == "" {
		p.Scope = "basic"
	}

	return &ResellerPortalProvider{
		ProviderData: p,
		Cache:        cache.New(1*time.Minute, 10*time.Minute),
	}
}

func getResellerPortalHeader(access_token string) http.Header {
	header := make(http.Header)
	header.Set("Accept", "application/json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", access_token))
	return header
}

func (p *ResellerPortalProvider) GetEmailAddress(s *SessionState) (string, error) {

	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header = getResellerPortalHeader(s.AccessToken)

	type result struct {
		Email string
	}
	var r result
	err = api.RequestJson(req, &r)
	if err != nil {
		return "", err
	}
	if r.Email == "" {
		return "", errors.New("no email")
	}
	log.Printf("Email %s", r.Email)
	return r.Email, nil
}

func (p *ResellerPortalProvider) ValidateSessionState(s *SessionState) bool {
	return validateToken(p, s.AccessToken, getResellerPortalHeader(s.AccessToken))
}

func (p *ResellerPortalProvider) Redeem(redirectURL, code string) (s *SessionState, err error) {

	if code == "" {
		err = errors.New("missing code")
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return
	}

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err == nil {
		s = &SessionState{
			AccessToken:  jsonResponse.AccessToken,
			ExpiresOn:    time.Now().Add(time.Duration(jsonResponse.ExpiresIn) * time.Second).Truncate(time.Second),
			RefreshToken: jsonResponse.RefreshToken,
		}
		return
	}

	err = fmt.Errorf("no access token found %s", body)
	return
}

func (p *ResellerPortalProvider) RefreshSessionIfNeeded(s *SessionState) (bool, error) {

	p.Lock()
	defer p.Unlock()

	if s == nil || s.ExpiresOn.After(time.Now()) || s.RefreshToken == "" {
		return false, nil
	}

	oldExpiresOn := s.ExpiresOn
	oldAccessToken := s.AccessToken
	AccessToken, found := p.Cache.Get(oldAccessToken)

	if found {
		s.AccessToken = AccessToken.(string)
		log.Printf("refresh access token by previous request %s (expired on %s)", s, oldExpiresOn)
		return false, nil
	}

	err := p.redeemRefreshToken(s)
	if err != nil {
		p.Cache.Delete(oldAccessToken)
		return false, err
	}

	log.Printf("refreshed access token %s (expired on %s)", s, oldExpiresOn)
	p.Cache.Set(oldAccessToken, s.AccessToken, cache.DefaultExpiration)

	return true, nil
}

func (p *ResellerPortalProvider) redeemRefreshToken(s *SessionState) (err error) {

	//log.Printf("old refresh_token %s", s.RefreshToken)

	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("refresh_token", s.RefreshToken)
	params.Add("grant_type", "refresh_token")
	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("\n\ngot %d with %s from %q %s\n\n", resp.StatusCode, params.Encode(), p.RedeemURL.String(), body)
		return
	}

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}

	err = json.Unmarshal(body, &jsonResponse)

	if err == nil {
		//log.Printf("new refresh_token %s", jsonResponse.RefreshToken)
		s.AccessToken = jsonResponse.AccessToken
		s.ExpiresOn = time.Now().Add(time.Duration(jsonResponse.ExpiresIn) * time.Second).Truncate(time.Second)
		s.RefreshToken = jsonResponse.RefreshToken
	}
	return
}
