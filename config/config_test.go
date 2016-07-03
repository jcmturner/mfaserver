package config

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/jcmturner/mfaserver/testtools"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
)

func TestConfig_NewConfig(t *testing.T) {
	c := NewConfig()
	assert.IsType(t, &Config{}, c, "Object is not a config type")
	assert.Equal(t, "0.0.0.0:8443", *c.MFAServer.ListenerSocket, "Default listener socket not as expected")
	assert.Equal(t, "secrets/mfa", *c.Vault.MFASecretsPath, "Default secrets path in vault not as expected")
}

func TestConfig_WithVaultEndPoint(t *testing.T) {
	c := NewConfig()
	ep := "http://endpoint"
	a := c.WithVaultEndPoint(ep)
	assert.Equal(t, ep, *a.Vault.VaultReSTClientConfig.EndPoint, "Vault endpoint not as expected")
}

func TestConfig_WithVaultAppIdRead(t *testing.T) {
	c := NewConfig()
	i := "test"
	c.WithVaultAppIdRead(i)
	assert.Equal(t, i, *c.Vault.AppIDRead, "AppID for read operations not as expected")
}

func TestConfig_WithVaultAppIdWrite(t *testing.T) {
	c := NewConfig()
	i := "test"
	c.WithVaultAppIdWrite(i)
	assert.Equal(t, i, *c.Vault.AppIDWrite, "AppID for write operations not as expected")
}

func TestConfig_WithVaultUserIdFile(t *testing.T) {
	c := NewConfig()

	//Create temp userid file
	f, _ := ioutil.TempFile(os.TempDir(), "userid")
	defer os.Remove(f.Name())
	userid := "0ecd7b5d-4885-45c1-a03f-5949e485c6bf"
	u := fmt.Sprintf(`{
	"UserId": "%s"
	}`, userid)
	f.WriteString(u)
	f.Close()

	c.WithVaultUserIdFile(f.Name())
	assert.Equal(t, f.Name(), *c.Vault.UserIDFile, "UserID file not as expected")
	assert.Equal(t, userid, *c.Vault.UserID, "UserID not as expected")

	fi, _ := ioutil.TempFile(os.TempDir(), "userid-invalid-content")
	defer os.Remove(f.Name())
	fi.WriteString(userid)
	_, err := c.WithVaultUserIdFile(fi.Name())
	assert.Error(t, err, "Should have errored when passed an invalid userID file content")
	expectedErrMsg := "UserId file could not be parsed"
	assert.Equal(t, expectedErrMsg, err.Error()[0:len(expectedErrMsg)], "Error message for invalid userID file content not as expected")

	_, err = c.WithVaultUserIdFile(f.Name() + "invalidPath")
	assert.Error(t, err, "Should have errored when passed an invalid userID file path")
	expectedErrMsg = "Could not open UserId file at " + f.Name() + "invalidPath"
	assert.Equal(t, expectedErrMsg, err.Error()[0:len(expectedErrMsg)], "Error message for invalid userID file path not as expected")
}

func TestConfig_WithVaultUserId(t *testing.T) {
	c := NewConfig()
	userid := "0ecd7b5d-4885-45c1-a03f-5949e485c6bf"
	c.WithVaultUserId(userid)
	assert.Equal(t, userid, *c.Vault.UserID, "UserID not as expected")
}

func TestConfig_WithVaultMFASecretsPath(t *testing.T) {
	c := NewConfig()
	p := "secret/testing"
	c.WithVaultMFASecretsPath(p)
	assert.Equal(t, p, *c.Vault.MFASecretsPath, "Vault secrets path not as expected")
}

func TestConfig_WithVaultCACert(t *testing.T) {
	certBytes, _ := testtools.GenerateSelfSignedTLSKeyPairData(t)
	cert, _ := x509.ParseCertificate(certBytes)
	//Have to add test cert into a certPool to compare in the assertion as this is all we can get back from the TLSClientConfig of the http.Client and certPool has no public mechanism to extract certs from it
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)

	c := NewConfig()
	a := c.WithVaultCACert(cert)
	transport := a.Vault.VaultConfig.HttpClient.Transport
	assert.Equal(t, certPool, transport.(*http.Transport).TLSClientConfig.RootCAs, "Certificate not set to be trusted in HTTP Client")
}

func TestConfig_WithVaultCAFilePath(t *testing.T) {
	certBytes, _ := testtools.GenerateSelfSignedTLSKeyPairData(t)
	cert, _ := x509.ParseCertificate(certBytes)
	//Have to add test cert into a certPool to compare in the assertion as this is all we can get back from the TLSClientConfig of the http.Client and certPool has no public mechanism to extract certs from it
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)

	//Get certifcate from test TLS server, output in PEM format to file
	certOut, _ := ioutil.TempFile(os.TempDir(), "cert")
	defer os.Remove(certOut.Name())
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	c := NewConfig()
	c.WithVaultCAFilePath(certOut.Name())
	transport := c.Vault.VaultConfig.HttpClient.Transport
	assert.Equal(t, certPool, transport.(*http.Transport).TLSClientConfig.RootCAs, "Certificate not set to be trusted in HTTP Client")
}

func TestConfig_WithMFAListenerSocket(t *testing.T) {
	c := NewConfig()
	s := "127.0.0.1:7443"
	_, err := c.WithMFAListenerSocket(s)
	assert.NoError(t, err)
	if err != nil {
		t.Fatalf("Error setting the MFA Listener socket: %v", err)
	}
	assert.Equal(t, s, *c.MFAServer.ListenerSocket, "MFA listener socket not set as expected")

	invalid := "127.265.0.1:70000"
	_, err = c.WithMFAListenerSocket(invalid)
	assert.Error(t, err, "Setting listener socket did not error for invalid socket")
}

func TestConfig_WithMFATLS(t *testing.T) {
	c := NewConfig()
	certPath, keyPath := testtools.GenerateSelfSignedTLSKeyPairFiles(t)
	defer os.Remove(certPath)
	defer os.Remove(keyPath)

	_, err := c.WithMFATLS(certPath, keyPath)
	if err != nil {
		t.Fatalf("Error setting certificate and key file paths for TLS: %v", err)
	}
	assert.Equal(t, certPath, *c.MFAServer.TLS.CertificateFile, "Error setting TLS cert file path. Unexpected value")
	assert.Equal(t, keyPath, *c.MFAServer.TLS.KeyFile, "Error setting TLS key file path. Unexpected value")
}

func TestLoad(t *testing.T) {
	certPath, keyPath := testtools.GenerateSelfSignedTLSKeyPairFiles(t)
	//Create temp userid file
	f, _ := ioutil.TempFile(os.TempDir(), "userid")
	defer os.Remove(f.Name())
	userid := "0ecd7b5d-4885-45c1-a03f-5949e485c6bf"
	u := fmt.Sprintf(`{
	"UserId": "%s"
	}`, userid)
	f.WriteString(u)
	f.Close()

	ep := "https://127.0.0.1:8200"

	completeJson := fmt.Sprintf(`{
		"Vault": {
			"VaultConnection": {
				"EndPoint": "%s",
				"TrustCACert": "%s"
			},
			"AppIDRead": "appidread",
			"AppIDWrite": "appidwrite",
			"UserIDFile": "%s",
			"MFASecretsPath": "/secrets/testload"
			},
		"MFAServer": {
			"ListenerSocket": "127.0.0.1:7443",
			"TLS": {
				"Enabled": true,
				"CertificateFile": "%s",
				"KeyFile": "%s"
				}
		}
	}`, ep, certPath, f.Name(), certPath, keyPath)

	testConfigFile, _ := ioutil.TempFile(os.TempDir(), "config")
	defer os.Remove(testConfigFile.Name())
	testConfigFile.WriteString(completeJson)
	testConfigFile.Close()
	c, err := Load(testConfigFile.Name())
	if err != nil {
		t.Fatalf("Error loading configuration JSON: %v", err)
	}
	assert.IsType(t, &Config{}, c, "Object is not a config type")
	assert.Equal(t, ep, *c.Vault.VaultReSTClientConfig.EndPoint, "Vault endpoint not as expected")
	assert.Equal(t, certPath, *c.Vault.VaultReSTClientConfig.TrustCACert, "Vault TrustCACert not as expected")
	assert.Equal(t, "appidread", *c.Vault.AppIDRead, "Vault AppIDRead not as expected")
	assert.Equal(t, "appidwrite", *c.Vault.AppIDWrite, "Vault AppIDWrite not as expected")
	assert.Equal(t, f.Name(), *c.Vault.UserIDFile, "Vault UserIDFile not as expected")
	assert.Equal(t, userid, *c.Vault.UserID, "Vault UserID not as expected")
	assert.Equal(t, "/secrets/testload", *c.Vault.MFASecretsPath, "Vault MFASecretsPath not as expected")
	assert.Equal(t, "127.0.0.1:7443", *c.MFAServer.ListenerSocket, "MFAServer ListenerSocket not as expected")
	assert.Equal(t, true, c.MFAServer.TLS.Enabled, "MFAServer ListenerSocket not as expected")
	assert.Equal(t, certPath, *c.MFAServer.TLS.CertificateFile, "MFAServer TLS CertificateFile not as expected")
	assert.Equal(t, keyPath, *c.MFAServer.TLS.KeyFile, "MFAServer TLS KeyFile not as expected")
}
