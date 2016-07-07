package handlers

import (
	"encoding/json"
	"errors"
	"github.com/jcmturner/gootp"
	"github.com/jcmturner/mfaserver/config"
	"github.com/jcmturner/mfaserver/secrets"
	"io"
	"net/http"
)

type enroleRequestData struct {
	Domain   string `json:"domain"`
	Username string `json:"username"`
}

type enroleResponseData struct {
	Secret string `json:"secret"`
}

func Enrole(w http.ResponseWriter, r *http.Request, c *config.Config) {
	//Process the JSON body
	var data enroleRequestData
	defer r.Body.Close()
	var dec *json.Decoder
	//Set limit to reading 1MB. Probably a bit large. Prevents DOS by posting large amount of data
	dec = json.NewDecoder(io.LimitReader(r.Body, 1024))
	err := dec.Decode(&data)
	if err != nil {
		//We should fail safe
		c.MFAServer.Loggers.Error.Printf("%s, Could not parse data posted from client to the enrole api : %v\n", r.RemoteAddr, err)
		w.WriteHeader(http.StatusBadRequest)
	}
	if data.Domain == "" || data.Username == "" {
		c.MFAServer.Loggers.Warning.Printf("%s, Could extract values correctly from the enrolement request.\n", r.RemoteAddr)
		w.WriteHeader(http.StatusBadRequest)
	}
	c.MFAServer.Loggers.Info.Printf("%s, OTP enrolement request received for %s/%s\n", r.RemoteAddr, data.Domain, data.Username)

	s, err := createAndStoreSecret(c, &data)
	if err != nil {
		c.MFAServer.Loggers.Error.Printf("%s, OTP enrolement failed for %s/%s whilst generating and storing secret: %v", r.RemoteAddr, data.Domain, data.Username, err)
		w.WriteHeader(http.StatusInternalServerError)
	}
	d := enroleResponseData{Secret: s}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if err := json.NewEncoder(w).Encode(d); err != nil {
		c.MFAServer.Loggers.Error.Printf("%s, OTP enrolement failed for %s/%s whilst returning body data: %v", r.RemoteAddr, data.Domain, data.Username, err)
	}
}

func createAndStoreSecret(c *config.Config, data *enroleRequestData) (string, error) {
	//TODO need to check the user does not already exist in vault
	s, err := gootp.GenerateOTPSecret(32)
	if err != nil {
		return "", errors.New("Could not generate secret: " + err.Error())
	}
	err = secrets.Store(c, "/"+data.Domain+"/"+data.Username, "mfa", s)
	if err != nil {
		return "", errors.New("Could not store secret in the vault: " + err.Error())
	}
	c.MFAServer.Loggers.Info.Printf("Successfully created and stored secret for %s/%s", data.Domain, data.Username)
	return s, nil
}
