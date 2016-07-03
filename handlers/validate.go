package handlers

import (
	"crypto/sha1"
	"encoding/json"
	"github.com/jcmturner/gootp"
	"github.com/jcmturner/mfaserver/config"
	"github.com/jcmturner/mfaserver/secrets"
	"io"
	"net/http"
)

type validateRequestData struct {
	Domain   string `json:"domain"`
	Username string `json:"username"`
	OTP      int    `json:"otp"`
}

func checkOTP(c *config.Config, data *validateRequestData) (bool, error) {
	m, err := secrets.Read(&c.Vault, data.Domain+"/"+data.Username)
	if err != nil {
		return false, err
	}
	s := m["mfa"]
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

func ValidateOTP(w http.ResponseWriter, r *http.Request, c *config.Config) {
	//Process the JSON body
	var data validateRequestData
	defer r.Body.Close()
	var dec *json.Decoder
	//Set limit to reading 1MB. Probably a bit large. Prevents DOS by posting large amount of data
	dec = json.NewDecoder(io.LimitReader(r.Body, 1024))
	err := dec.Decode(&data)
	if err != nil {
		//TODO put logging here of the error.
		//We should fail safe
		w.WriteHeader(http.StatusUnauthorized)
	}
	if data.Domain == "" || data.Username == "" || data.OTP == 0 {
		w.WriteHeader(http.StatusBadRequest)
	}

	//Check the OTP value provided
	ok, err := checkOTP(c, &data)
	if err != nil {
		//TODO put logging here of the error.
		//We should fail safe
		w.WriteHeader(http.StatusUnauthorized)
	}
	if ok {
		//Respond with a 201 to indicate the check passed
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
	}
}
