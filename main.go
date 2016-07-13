package main

import (
	"flag"
	"github.com/jcmturner/mfaserver/config"
	"github.com/jcmturner/mfaserver/handlers"
	"github.com/jcmturner/mfaserver/version"
	"log"
	"net/http"
	"os/user"
)

func main() {
	//Locate config file
	usr, _ := user.Current()
	dir := usr.HomeDir
	configPath := flag.String("config", dir+"/mfaserver-config.json", "Specify the path to the configuration file")
	//Load config
	c, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to configure MFA Server: %v\n", err)
	}

	//Set up handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		handlers.ValidateOTP(w, r, c)
	})
	mux.HandleFunc("/enrole", func(w http.ResponseWriter, r *http.Request) {
		handlers.Enrole(w, r, c)
	})
	//mux.HandleFunc("/update", handlers.UpdateMFASecret)

	c.MFAServer.Loggers.Info.Printf(`MFA Server - Configuration Complete:
	Version: %s
	Listenning socket: %s
	TLS enabled: %t`, version.Version, *c.MFAServer.ListenerSocket, c.MFAServer.TLS.Enabled)

	//Start server
	if c.MFAServer.TLS.Enabled {
		err = http.ListenAndServeTLS(*c.MFAServer.ListenerSocket, *c.MFAServer.TLS.CertificateFile, *c.MFAServer.TLS.KeyFile, mux)
	} else {
		err = http.ListenAndServe(*c.MFAServer.ListenerSocket, mux)
	}
	log.Fatal(err)
}
