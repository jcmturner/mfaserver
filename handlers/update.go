package handlers

import (
	"encoding/json"
	"fmt"
	"github.com/jcmturner/mfaserver/config"
	"github.com/jcmturner/mfaserver/ldap"
	"github.com/jcmturner/mfaserver/secrets"
	"net/http"
	"net/url"
)

func Update(w http.ResponseWriter, r *http.Request, c *config.Config) {
	data, err, HTTPCode := processValidateRequestData(r)
	if err != nil {
		c.MFAServer.Loggers.Error.Println(err.Error())
		w.WriteHeader(HTTPCode)
		return
	}
	c.MFAServer.Loggers.Info.Printf("%s, OTP update request received for %s/%s\n", r.RemoteAddr, data.Domain, data.Username)

	err = ldap.Authenticate(data.Username, data.Password, c)
	if err != nil {
		c.MFAServer.Loggers.Info.Printf("%s, OTP update failed for %s/%s. LDAP authentication failed: %v", r.RemoteAddr, data.Domain, data.Username, err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !secrets.Exists(c, "/"+data.Issuer+"/"+data.Domain+"/"+data.Username, "mfa") {
		c.MFAServer.Loggers.Info.Printf("%s, OTP update failed for %s/%s as the user has not yet enroled.", r.RemoteAddr, data.Domain, data.Username)
		w.WriteHeader(http.StatusForbidden)
		d := messageResponseData{Message: "Forbidden - User has not enroled"}
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		json.NewEncoder(w).Encode(d)
		return
	}

	//Check the OTP value provided
	ok, err := checkOTP(c, &data)
	if err != nil {
		//We should fail safe
		c.MFAServer.Loggers.Error.Printf("%s, Error during the update of OTP for %s/%s : %v", r.RemoteAddr, data.Domain, data.Username, err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if !ok {
		c.MFAServer.Loggers.Info.Printf("%s, OTP validation failed during update for %s/%s", r.RemoteAddr, data.Domain, data.Username)
		//Respond with 401 to indicate the check failed
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	c.MFAServer.Loggers.Info.Printf("%s, OTP validation passed for update of %s/%s", r.RemoteAddr, data.Domain, data.Username)

	udata := enroleRequestData{Username: data.Username,
		Domain:   data.Domain,
		Issuer:   data.Issuer,
		Password: data.Password}
	s, err := createAndStoreSecret(c, &udata)
	if err != nil {
		c.MFAServer.Loggers.Error.Printf("%s, OTP update failed for %s/%s whilst generating and storing secret: %v", r.RemoteAddr, data.Domain, data.Username, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if r.Header.Get("Accept-Encoding") == "image/png" {
		gAuthURL := fmt.Sprintf("otpauth://totp/%s:%s@%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30", url.QueryEscape(data.Issuer), data.Username, data.Domain, s, url.QueryEscape(data.Issuer))
		img, err := getQRCodeBytes(gAuthURL)
		if err != nil {
			c.MFAServer.Loggers.Error.Printf("%s, OTP update failed for %s/%s whilst generating QR code: %v", r.RemoteAddr, data.Domain, data.Username, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Write(img)
	} else {
		d := enroleResponseData{Secret: s}
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		if err := json.NewEncoder(w).Encode(d); err != nil {
			c.MFAServer.Loggers.Error.Printf("%s, OTP update failed for %s/%s whilst returning body data: %v", r.RemoteAddr, data.Domain, data.Username, err)
		}
	}
}
