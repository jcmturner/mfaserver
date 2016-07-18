package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/jcmturner/mfaserver/config"
	"github.com/jcmturner/mfaserver/ldap"
	"github.com/jcmturner/mfaserver/secrets"
	"net/http"
	"strings"
)

func DeleteOTP(w http.ResponseWriter, r *http.Request, c *config.Config) {
	//Process the request data
	admin := checkAdminAuth(c, r)
	data, err, HTTPCode := processValidateRequestData(r, admin)
	setNoCacheHeaders(w)
	if err != nil {
		c.MFAServer.Loggers.Error.Println(err.Error())
		w.WriteHeader(HTTPCode)
		return
	}
	c.MFAServer.Loggers.Info.Printf("%s, OTP deletion request received for %s:%s/%s", r.RemoteAddr, data.Issuer, data.Domain, data.Username)
	if !admin {
		//Not an admin so check if they are deleting their own secret
		c.MFAServer.Loggers.Info.Printf("%s, Deletion request for %s:%s/%s was not made by an administrator.", r.RemoteAddr, data.Issuer, data.Domain, data.Username)
		ok, HTTPCode := twoFactorAuthenticate(c, r, &data)
		if !ok {
			c.MFAServer.Loggers.Info.Printf("%s, Deletion request for %s:%s/%s denied as not made by an administrator or the user themselves.", r.RemoteAddr, data.Issuer, data.Domain, data.Username)
			w.WriteHeader(HTTPCode)
			d := messageResponseData{Message: "Cannot delete user's secret as either 2FA failed or user has not been enroled"}
			w.Header().Set("Content-Type", "application/json; charset=UTF-8")
			json.NewEncoder(w).Encode(d)
			return
		}
	}
	err = deleteSecret(c, &data)
	if err != nil {
		c.MFAServer.Loggers.Error.Printf("Failed to delete secret for %s:%s/%s: %v", data.Issuer, data.Domain, data.Username, err)
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
	c.MFAServer.Loggers.Info.Printf("Successfully deleted stored secret for %s:%s/%s", data.Issuer, data.Domain, data.Username)
	return nil
}

func checkAdminAuth(c *config.Config, r *http.Request) bool {
	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return false
	}
	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		return false
	}
	err = ldap.AdminAuthorise(pair[0], pair[1], c)
	if err != nil {
		c.MFAServer.Loggers.Info.Printf("Administrator authorisation failed for user %s", pair[0])
		return false
	}
	c.MFAServer.Loggers.Info.Printf("Administrator authorisation passed for user %s", pair[0])
	return true
}
