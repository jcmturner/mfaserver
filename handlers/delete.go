package handlers

import (
	"encoding/json"
	"errors"
	"github.com/jcmturner/mfaserver/config"
	"github.com/jcmturner/mfaserver/secrets"
	"net/http"
)

func DeleteOTP(w http.ResponseWriter, r *http.Request, c *config.Config) {
	//Process the request data
	data, err, HTTPCode := processValidateRequestData(r)
	if err != nil {
		c.MFAServer.Loggers.Error.Println(err.Error())
		w.WriteHeader(HTTPCode)
		return
	}
	c.MFAServer.Loggers.Info.Printf("%s, OTP deletion request received for %s/%s", r.RemoteAddr, data.Domain, data.Username)

	ok, HTTPCode := twoFactorAuthenticate(c, r, &data)
	if !ok {
		w.WriteHeader(HTTPCode)
		d := messageResponseData{Message: "Cannot delete user's secret as either 2FA failed or user has not been enroled"}
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		json.NewEncoder(w).Encode(d)
		return
	}
	err = deleteSecret(c, &data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		d := messageResponseData{Message: "Error in deleting user's MFA secret"}
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		json.NewEncoder(w).Encode(d)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	return
}

func deleteSecret(c *config.Config, data *validateRequestData) error {
	err := secrets.Delete(c, "/"+data.Issuer+"/"+data.Domain+"/"+data.Username)
	if err != nil {
		return errors.New("Could not delete secret in the vault: " + err.Error())
	}
	c.MFAServer.Loggers.Info.Printf("Successfully created and stored secret for %s/%s", data.Domain, data.Username)
	return nil
}
