package vault

import (
	"errors"
	"fmt"
	"github.com/jcmturner/restclient"
	"net/http"
	"time"
)

type Login struct {
	loginResponse
	request    *restclient.Request
	validUntil time.Time
}

type loginResponse struct {
	LeaseID       string      `json:"lease_id"`
	Renewable     bool        `json:"renewable"`
	LeaseDuration int         `json:"lease_duration"`
	Data          interface{} `json:"data"`
	Auth          struct {
		ClientToken   string   `json:"client_token"`
		Policies      []string `json:"policies"`
		LeaseDuration int      `json:"lease_duration"`
		Renewable     bool     `json:"renewable"`
		Metadata      struct {
			AppID  string `json:"app-id"`
			UserID string `json:"user-id"`
		} `json:"metadata"`
	} `json:"auth"`
}

func (l *Login) NewRequest(c *restclient.Config, a, u string) (err error) {
	o := restclient.NewPostOperation().WithPath("/v1/auth/app-id/login").WithResponseTarget(l).WithSendDataString(fmt.Sprintf(`
			{
				"app_id":"%s",
				"user_id": "%s"}
			}`, a, u)).WithResponseTarget(&l)
	req, err := restclient.BuildRequest(c, o)
	l.request = req
	return
}

func (l *Login) Process() (err error) {
	httpCode, err := restclient.Send(l.request)
	if err != nil {
		return
	}
	if *httpCode != http.StatusOK {
		err = errors.New("Did not get an HTTP 200 code on login")
	}
	if l.loginResponse.Auth.LeaseDuration > 0 {
		l.validUntil = time.Now().Add(time.Duration(l.loginResponse.Auth.LeaseDuration) * time.Second)
	}
	return
}

func (l *Login) GetToken() (token string, err error) {
	// If token no longer valid re-request it first. A zero value for ValidUntil means it never expires
	if !l.validUntil.IsZero() && time.Now().After(l.validUntil) {
		err = l.Process()
		if err != nil {
			return
		}
	}
	token = l.Auth.ClientToken
	return
}
