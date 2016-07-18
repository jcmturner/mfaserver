package handlers

import (
	"encoding/json"
	"fmt"
	"github.com/jcmturner/mfaserver/config"
	"net/http"
	"net/url"
)

func Update(w http.ResponseWriter, r *http.Request, c *config.Config) {
	data, err, HTTPCode := processValidateRequestData(r, false)
	setNoCacheHeaders(w)
	if err != nil {
		c.MFAServer.Loggers.Error.Println(err.Error())
		w.WriteHeader(HTTPCode)
		return
	}
	c.MFAServer.Loggers.Info.Printf("%s, OTP update request received for %s/%s\n", r.RemoteAddr, data.Domain, data.Username)

	ok, HTTPCode := twoFactorAuthenticate(c, r, &data)
	if !ok {
		w.WriteHeader(HTTPCode)
		d := messageResponseData{Message: "Cannot update user's secret as either 2FA failed or user has not been enroled"}
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		json.NewEncoder(w).Encode(d)
		return
	}

	udata := enrolRequestData{Username: data.Username,
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
		d := enrolResponseData{Secret: s}
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		if err := json.NewEncoder(w).Encode(d); err != nil {
			c.MFAServer.Loggers.Error.Printf("%s, OTP update failed for %s/%s whilst returning body data: %v", r.RemoteAddr, data.Domain, data.Username, err)
		}
	}
}
