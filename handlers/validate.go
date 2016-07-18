package handlers

import (
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jcmturner/gootp"
	"github.com/jcmturner/mfaserver/config"
	"github.com/jcmturner/mfaserver/ldap"
	"github.com/jcmturner/mfaserver/secrets"
	"io"
	"net/http"
)

type validateRequestData struct {
	Issuer   string `json:"issuer"`
	Domain   string `json:"domain"`
	Username string `json:"username"`
	Password string `json:"password"`
	OTP      string `json:"otp"`
}

func ValidateOTP(w http.ResponseWriter, r *http.Request, c *config.Config) {
	//Process the request data
	data, err, HTTPCode := processValidateRequestData(r, false)
	if err != nil {
		c.MFAServer.Loggers.Error.Println(err.Error())
		w.WriteHeader(HTTPCode)
		return
	}
	c.MFAServer.Loggers.Info.Printf("%s, OTP vaidation request received for %s/%s", r.RemoteAddr, data.Domain, data.Username)

	_, HTTPCode = twoFactorAuthenticate(c, r, &data)
	w.WriteHeader(HTTPCode)
	return
}

func processValidateRequestData(r *http.Request, admin bool) (validateRequestData, error, int) {
	//Process the JSON body
	var data validateRequestData
	defer r.Body.Close()
	var dec *json.Decoder
	//Set limit to reading 1MB. Probably a bit large. Prevents DOS by posting large amount of data
	dec = json.NewDecoder(io.LimitReader(r.Body, 1024))
	err := dec.Decode(&data)
	if err != nil {
		//We should fail safe
		return data, errors.New(fmt.Sprintf("%s, Could not parse data posted from client : %v", r.RemoteAddr, err)), http.StatusBadRequest
	}
	if data.Domain == "" || data.Username == "" || data.Issuer == "" {
		return data, errors.New(fmt.Sprintf("%s, Could not extract values correctly from the validation request.", r.RemoteAddr)), http.StatusBadRequest
	}
	if !admin && (data.Password == "" || data.OTP == "") {
		return data, errors.New(fmt.Sprintf("%s, Could not extract values correctly from the validation request.", r.RemoteAddr)), http.StatusBadRequest
	}
	return data, nil, 0
}

func twoFactorAuthenticate(c *config.Config, r *http.Request, data *validateRequestData) (bool, int) {
	//Check user password
	err := ldap.Authenticate(data.Username, data.Password, c)
	if err != nil {
		c.MFAServer.Loggers.Info.Printf("%s, OTP validation failed for %s/%s. LDAP authentication failed: %v", r.RemoteAddr, data.Domain, data.Username, err)
		return false, http.StatusUnauthorized
	}

	//Check the OTP value provided
	ok, err := checkOTP(c, data)
	if err != nil {
		//We should fail safe
		c.MFAServer.Loggers.Error.Printf("%s, Error during the validation of OTP for %s/%s : %v", r.RemoteAddr, data.Domain, data.Username, err)
		return false, http.StatusUnauthorized
	}
	if ok {
		c.MFAServer.Loggers.Info.Printf("%s, OTP validation passed for %s/%s", r.RemoteAddr, data.Domain, data.Username)
		//Respond with a 204 to indicate the check passed
		return true, http.StatusNoContent
	}

	//Fail safe
	c.MFAServer.Loggers.Info.Printf("%s, OTP validation failed for %s/%s", r.RemoteAddr, data.Domain, data.Username)
	//Respond with 401 to indicate the check failed
	return false, http.StatusUnauthorized
}

func checkOTP(c *config.Config, data *validateRequestData) (bool, error) {
	m, err := secrets.Read(c, "/"+data.Issuer+"/"+data.Domain+"/"+data.Username)
	if err != nil || m == nil {
		return false, err
	}
	s := m["mfa"].(string)
	generatedOTP, _, err := gootp.GetTOTPNow(s, sha1.New, 6)
	if err != nil {
		return false, err
	}
	if data.OTP == generatedOTP {
		return true, nil
	}
	//Fail safe
	return false, nil
}
