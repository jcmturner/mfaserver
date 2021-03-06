package handlers

import (
	"encoding/json"
	"errors"
	"github.com/jcmturner/gootp"
	"github.com/jcmturner/mfaserver/config"
	"github.com/jcmturner/mfaserver/secrets"
	"io"
	"net/http"

	"fmt"
	"github.com/jcmturner/goqr"
	"github.com/jcmturner/mfaserver/ldap"
	"net/url"
)

type enrolRequestData struct {
	Domain   string `json:"domain"`
	Username string `json:"username"`
	Password string `json:"password"`
	Issuer   string `json:"issuer"`
}

type enrolResponseData struct {
	Secret string `json:"secret"`
}

type messageResponseData struct {
	Message string `json:"message"`
}

func Enrol(w http.ResponseWriter, r *http.Request, c *config.Config) {
	data, err, HTTPCode := processEnrolRequestData(r)
	setNoCacheHeaders(w)
	if err != nil {
		c.MFAServer.Loggers.Error.Println(err.Error())
		w.WriteHeader(HTTPCode)
		return
	}
	c.MFAServer.Loggers.Info.Printf("%s, OTP enrolement request received for %s/%s\n", r.RemoteAddr, data.Domain, data.Username)

	err = ldap.Authenticate(data.Username, data.Password, c)
	if err != nil {
		c.MFAServer.Loggers.Info.Printf("%s, OTP enrolement failed for %s/%s. LDAP authentication failed: %v", r.RemoteAddr, data.Domain, data.Username, err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if secrets.Exists(c, "/"+data.Issuer+"/"+data.Domain+"/"+data.Username, "mfa") {
		c.MFAServer.Loggers.Info.Printf("%s, OTP enrolement failed for %s/%s as the user already has enroled.", r.RemoteAddr, data.Domain, data.Username)
		w.WriteHeader(http.StatusForbidden)
		d := messageResponseData{Message: "Forbidden - User already enroled"}
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		json.NewEncoder(w).Encode(d)
		return
	}

	s, err := createAndStoreSecret(c, &data)
	if err != nil {
		c.MFAServer.Loggers.Error.Printf("%s, OTP enrolement failed for %s/%s whilst generating and storing secret: %v", r.RemoteAddr, data.Domain, data.Username, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if r.Header.Get("Accept-Encoding") == "image/png" {
		gAuthURL := fmt.Sprintf("otpauth://totp/%s:%s@%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30", url.QueryEscape(data.Issuer), data.Username, data.Domain, s, url.QueryEscape(data.Issuer))
		img, err := getQRCodeBytes(gAuthURL)
		if err != nil {
			c.MFAServer.Loggers.Error.Printf("%s, OTP enrolement failed for %s/%s whilst generating QR code: %v", r.RemoteAddr, data.Domain, data.Username, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(http.StatusCreated)
		w.Write(img)
	} else {
		d := enrolResponseData{Secret: s}
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(d); err != nil {
			c.MFAServer.Loggers.Error.Printf("%s, OTP enrolement failed for %s/%s whilst returning body data: %v", r.RemoteAddr, data.Domain, data.Username, err)
		}
	}
}

func processEnrolRequestData(r *http.Request) (enrolRequestData, error, int) {
	var data enrolRequestData
	defer r.Body.Close()
	var dec *json.Decoder
	//Set limit to reading 1MB. Probably a bit large. Prevents DOS by posting large amount of data
	dec = json.NewDecoder(io.LimitReader(r.Body, 1024))
	err := dec.Decode(&data)
	if err != nil {
		return data, errors.New(fmt.Sprintf("%s, Could not parse data posted from client to the enrole api : %v\n", r.RemoteAddr, err)), http.StatusBadRequest
	}
	if data.Domain == "" || data.Username == "" || data.Password == "" || data.Issuer == "" {
		return data, errors.New(fmt.Sprintf("%s, Could extract values correctly from the enrolement request.\n", r.RemoteAddr)), http.StatusBadRequest
	}
	return data, nil, 0
}

func createAndStoreSecret(c *config.Config, data *enrolRequestData) (string, error) {
	s, err := gootp.GenerateOTPSecret(32)
	if err != nil {
		return "", errors.New("Could not generate secret: " + err.Error())
	}
	err = secrets.Store(c, "/"+data.Issuer+"/"+data.Domain+"/"+data.Username, "mfa", s)
	if err != nil {
		return "", errors.New("Could not store secret in the vault: " + err.Error())
	}
	c.MFAServer.Loggers.Info.Printf("Successfully created and stored secret for %s/%s", data.Domain, data.Username)
	return s, nil
}

func getQRCodeBytes(u string) ([]byte, error) {
	code, err := goqr.Encode(u, goqr.H)
	if err != nil {
		return nil, err
	}
	return code.PNG(), nil
}
