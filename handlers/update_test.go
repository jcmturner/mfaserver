package handlers

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"github.com/jcmturner/gootp"
	"github.com/jcmturner/mfaserver/config"
	"github.com/jcmturner/mfaserver/testtools"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestUpdate(t *testing.T) {
	//Set up mock LDAP server
	l := testtools.NewLDAPServer(t)
	defer l.Stop()
	//Set up mock Vault instance
	ln, addr, appID, userID := testtools.RunMockVault(t)
	defer ln.Close()

	//Set up the MFA config
	c := config.NewConfig()
	c.WithVaultAppIdWrite(appID).WithVaultAppIdRead(appID).WithVaultUserId(userID).WithVaultEndPoint(addr)
	c.WithLDAPConnection("ldap://"+l.Listener.Addr().String(), "", "{username}")
	c.MFAServer.Loggers.Debug = log.New(os.Stdout, "MFA Debug: ", log.Ldate|log.Ltime|log.Lshortfile)
	c.MFAServer.Loggers.Info = log.New(os.Stdout, "MFA Info: ", log.Ldate|log.Ltime|log.Lshortfile)
	c.MFAServer.Loggers.Warning = log.New(os.Stdout, "MFA Warn: ", log.Ldate|log.Ltime|log.Lshortfile)
	c.MFAServer.Loggers.Error = log.New(os.Stderr, "MFA Error: ", log.Ldate|log.Ltime|log.Lshortfile)

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { Update(w, r, c) }))
	defer s.Close()

	udata := enroleRequestData{Username: "validuser",
		Domain:   "testdom",
		Issuer:   "testapp",
		Password: "validpassword"}

	secret, _ := createAndStoreSecret(c, &udata)

	var tests = []struct {
		Json     string
		HttpCode int
	}{
		{`{"domain": "testdom", "username": "validuser", "password": "validpassword", "issuer": "testapp", "otp": "%s"}`, http.StatusOK},
		{`{"domain": "testdom", "username": "validuser", "password": "validpassword", "issuer": "testapp", "otp": "%s"}`, http.StatusOK},
		{`{"domain": "testdom", "username": "validuser", "password": "validpassword", "issuer": "testapp", "otp": "1234567"}`, http.StatusUnauthorized},
		{`{"domain": "somethingelse", "username": "validuser", "password": "validpassword", "issuer": "testapp", "otp": "%s"}`, http.StatusUnauthorized},
		{`{"domain": "testdom", "username": "invaliduser", "password": "validpassword", "issuer": "testapp", "otp": "%s"}`, http.StatusUnauthorized},
		{`{"domain": "testdom", "username": "validuser", "password": "invalidpassword", "issuer": "testapp", "otp": "%s"}`, http.StatusUnauthorized},
		{`{"domain": "testdom", "username": "validuser", "password": "validpassword", "issuer": "somethingelse", "otp": "%s"}`, http.StatusUnauthorized},
		{`{"domain": "testdom", "username": "validuser", "password": "validpassword", "issuer": "testapp"}`, http.StatusBadRequest},
		{`{"domain": "testdom", "username": "validuser", "password": "validpassword", "otp": "%s"}`, http.StatusBadRequest},
		{`{"domain": "testdom", "username": "validuser", "issuer": "testapp", "otp": "%s"}`, http.StatusBadRequest},
		{`{"domain": "testdom", "password": "validpassword", "issuer": "testapp", "otp": "%s"}`, http.StatusBadRequest},
		{`{"username": "validuser", "password": "validpassword", "issuer": "testapp", "otp": "%s"}`, http.StatusBadRequest},
		{`"domain": "testdom", "username": "validuser", "password": "validpassword", "issuer": "testapp", "otp": "%s"}`, http.StatusBadRequest},
	}
	for _, test := range tests {
		otp, _, _ := gootp.GetTOTPNow(secret, sha1.New, 6)
		rdata := []byte(fmt.Sprintf(test.Json, otp))
		r, err := http.NewRequest("POST", s.URL+"/update", bytes.NewBuffer(rdata))
		if err != nil {
			t.Errorf("Error returned from creating request: %v", err)
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Errorf("Error returned from sending request: %v", err)
		}
		if resp.StatusCode != test.HttpCode {
			t.Errorf("Expected code %v, got %v for post data %v", test.HttpCode, resp.StatusCode, test.Json)
		}
		//Check the JSON response was correct format
		if resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			var dec *json.Decoder
			var j enroleResponseData
			dec = json.NewDecoder(resp.Body)
			err = dec.Decode(&j)
			secret = j.Secret
			if err != nil {
				body, _ := ioutil.ReadAll(r.Body)
				t.Errorf("Failed to marshal the response into the JSON object. Response: %s", body)
			}
		}
	}
}
