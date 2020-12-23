package sso

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// SSO struct
type SSO struct {
	Token        string
	RefreshToken string
	ExpiredAt    time.Time
	RefExpiredAt time.Time
}

// ConnectSSO function
func (sso *SSO) ConnectSSO() (SSO, error) {
	t := time.Now()
	body := url.Values{}
	body.Set("client_id", "admin-cli")

	var err error

	switch {
	case t.After(sso.ExpiredAt) && t.Before(sso.RefExpiredAt):
		// refresh the token
		body.Set("grant_type", "refresh_token")
		body.Set("refresh_token", sso.RefreshToken)

		err = sso.getToken(body)

	case t.After(sso.RefExpiredAt) || sso.Token == "":
		// get new token
		body.Set("grant_type", "password")
		body.Set("username", os.Getenv("SSO_USERNAME"))
		body.Set("password", os.Getenv("SSO_PASSWORD"))

		err = sso.getToken(body)
	}

	return *sso, err

}

func (sso *SSO) getToken(body url.Values) error {

	req, errReq := http.NewRequest(http.MethodPost, os.Getenv("SSO_TOKEN_URL"), strings.NewReader(body.Encode()))
	if errReq != nil {
		return errReq
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, errRes := http.DefaultClient.Do(req)
	if errRes != nil {
		return errRes
	}

	resByte, errBod := ioutil.ReadAll(res.Body)
	if errBod != nil {
		return errBod
	}

	var data map[string]interface{}
	if err := json.Unmarshal(resByte, &data); err != nil {
		return err
	}

	t := time.Now()

	expire, _ := time.ParseDuration(fmt.Sprintf("%.0f", data["expires_in"]) + "s")
	refExpire, _ := time.ParseDuration(fmt.Sprintf("%.0f", data["refresh_expires_in"]) + "s")

	sso.Token = data["access_token"].(string)
	sso.RefreshToken = data["refresh_token"].(string)
	sso.ExpiredAt = t.Add(expire)
	sso.RefExpiredAt = t.Add(refExpire)

	return nil
}
