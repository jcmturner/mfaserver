package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	vaultAPI "github.com/hashicorp/vault/api"
	"github.com/jcmturner/mfaserver/vault"
	"github.com/jcmturner/restclient"
	"io/ioutil"
	"net"
	"net/http"
)

type Config struct {
	Vault     VaultConf `json:"Vault"`
	MFAServer MFAServer `json:"MFAServer"`
}

type VaultConf struct {
	VaultReSTClientConfig *restclient.Config `json:"VaultConnection"`
	AppIDRead             *string            `json:"AppIDRead"`
	AppIDWrite            *string            `json:"AppIDWrite"`
	UserIDFile            *string            `json:"UserIDFile"`
	UserID                *string            `json:"UserID"`
	MFASecretsPath        *string            `json:"MFASecretsPath"`
	VaultConfig           *vaultAPI.Config
	VaultClient           *vaultAPI.Client
	VaultLogin            *vault.Login
}

type UserIdFile struct {
	UserID string `json:"UserId"`
}

type MFAServer struct {
	ListenerSocket *string `json:"ListenerSocket"`
	TLS            TLS     `json:"TLS"`
}

type TLS struct {
	Enabled         bool    `json:"Enabled"`
	CertificateFile *string `json:"CertificateFile"`
	KeyFile         *string `json:"KeyFile"`
}

func NewConfig() *Config {
	defSecPath := "secrets/mfa"
	defSocket := "0.0.0.0:8443"
	return &Config{
		Vault: VaultConf{
			VaultReSTClientConfig: restclient.NewConfig(),
			VaultConfig:           vaultAPI.DefaultConfig(),
			MFASecretsPath:        &defSecPath,
		},
		MFAServer: MFAServer{
			ListenerSocket: &defSocket,
		},
	}
}

func Load(cfgPath string) (*Config, error) {
	j, err := ioutil.ReadFile(cfgPath)
	if err != nil {
		return nil, errors.New("Configuration file could not be openned: " + cfgPath + " " + err.Error())
	}

	c := NewConfig()
	err = json.Unmarshal(j, c)
	if err != nil {
		return nil, errors.New("Configuration file could not be parsed: " + err.Error())
	}
	c.WithVaultConfig(vaultAPI.DefaultConfig())
	c.Vault.VaultConfig.Address = *c.Vault.VaultReSTClientConfig.EndPoint
	if c.Vault.VaultReSTClientConfig.TrustCACert != nil {
		c.WithVaultCAFilePath(*c.Vault.VaultReSTClientConfig.TrustCACert)
	}
	if c.Vault.UserID == nil {
		if c.Vault.UserIDFile == nil {
			return nil, errors.New("Configuration file does not define a UserId or UserIdFile to use to access Vault")
		} else {
			c.WithVaultUserIdFile(*c.Vault.UserIDFile)
		}
	}
	if c.MFAServer.TLS.Enabled {
		_, err = c.WithMFATLS(*c.MFAServer.TLS.CertificateFile, *c.MFAServer.TLS.KeyFile)
		if err != nil {
			return nil, errors.New("TLS configuration for MFA Server not valid: " + err.Error())
		}
	}

	return c, nil
}

func (c *Config) WithVaultUserId(u string) *Config {
	c.Vault.UserID = &u
	return c
}

func (c *Config) WithVaultUserIdFile(u string) (*Config, error) {
	j, err := ioutil.ReadFile(u)
	if err != nil {
		return c, errors.New("Could not open UserId file at " + u + " " + err.Error())
	}
	var uf UserIdFile
	err = json.Unmarshal(j, &uf)
	if err != nil {
		return c, errors.New("UserId file could not be parsed: " + err.Error())
	}
	c.Vault.UserIDFile = &u
	c.Vault.UserID = &uf.UserID
	return c, nil
}

func (c *Config) WithVaultAppIdRead(a string) *Config {
	c.Vault.AppIDRead = &a
	return c
}
func (c *Config) WithVaultAppIdWrite(a string) *Config {
	c.Vault.AppIDWrite = &a
	return c
}

func (c *Config) WithVaultEndPoint(e string) *Config {
	c.Vault.VaultReSTClientConfig.WithEndPoint(e)
	c.Vault.VaultConfig.Address = e
	return c
}

func (c *Config) WithVaultMFASecretsPath(p string) *Config {
	c.Vault.MFASecretsPath = &p
	return c
}

func (c *Config) WithVaultConfig(cfg *vaultAPI.Config) *Config {
	c.Vault.VaultConfig = cfg
	return c
}

func (c *Config) WithVaultCACert(cert *x509.Certificate) *Config {
	if len(cert.Raw) == 0 {
		panic("Certifcate provided is empty")
	}
	tlsConfig := &tls.Config{RootCAs: x509.NewCertPool()}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	if c.Vault.VaultConfig == nil {
		c.Vault.VaultConfig = vaultAPI.DefaultConfig()
	}
	c.Vault.VaultConfig.HttpClient.Transport = transport
	tlsConfig.RootCAs.AddCert(cert)
	c.Vault.VaultReSTClientConfig.WithCACert(cert)
	return c
}

func (c *Config) WithVaultCAFilePath(caFilePath string) *Config {
	c.Vault.VaultReSTClientConfig.WithCAFilePath(caFilePath)
	tlsConfig := &tls.Config{RootCAs: x509.NewCertPool()}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	if c.Vault.VaultConfig == nil {
		c.Vault.VaultConfig = vaultAPI.DefaultConfig()
	}
	c.Vault.VaultConfig.HttpClient.Transport = transport
	// Load our trusted certificate path
	pemData, err := ioutil.ReadFile(caFilePath)
	if err != nil {
		panic(err)
	}
	ok := tlsConfig.RootCAs.AppendCertsFromPEM(pemData)
	if !ok {
		panic("Couldn't load PEM data")
	}

	return c
}

func (c *Config) WithMFAListenerSocket(s string) (*Config, error) {
	if _, err := net.ResolveTCPAddr("tcp", s); err != nil {
		return c, errors.New("Invalid listener socket defined for MFA server")
	}
	c.MFAServer.ListenerSocket = &s
	return c, nil
}

func (c *Config) WithMFATLS(certPath, keyPath string) (*Config, error) {
	if err := isValidPEMFile(certPath); err != nil {
		return c, errors.New("MFA Server TLS certificate not valid: " + err.Error())
	}
	if err := isValidPEMFile(keyPath); err != nil {
		return c, errors.New("MFA Server TLS key not valid: " + err.Error())
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		cert, _ := ioutil.ReadFile(certPath)
		key, _ := ioutil.ReadFile(keyPath)
		fmt.Printf("Cert: \n %s\n Key: \n %s", cert, key)
		return c, errors.New("Key pair provided not valid: " + err.Error())
	}
	c.MFAServer.TLS = TLS{
		Enabled:         true,
		CertificateFile: &certPath,
		KeyFile:         &keyPath,
	}
	return c, nil
}

func isValidPEMFile(p string) error {
	pemData, err := ioutil.ReadFile(p)
	if err != nil {
		return err
	}
	block, rest := pem.Decode(pemData)
	if len(rest) > 0 || block.Type == "" {
		return errors.New(fmt.Sprintf("Not valid PEM format: Rest: %v Type: %v", len(rest), block.Type))
	}
	return nil
}
