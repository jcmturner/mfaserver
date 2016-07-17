package secrets

import (
	"errors"
	vaultAPI "github.com/hashicorp/vault/api"
	"github.com/jcmturner/mfaserver/config"
	"github.com/jcmturner/mfaserver/vault"
)

func vaultClientLogin(conf *config.Config) error {
	conf.MFAServer.Loggers.Debug.Println("Call to get login token to the Vault")
	if conf.Vault.VaultLogin == nil {
		conf.MFAServer.Loggers.Debug.Println("No cached login token, will perform new login request to the Vault.")
		var l vault.Login
		err := l.NewRequest(conf.Vault.VaultReSTClientConfig, *conf.Vault.AppIDWrite, *conf.Vault.UserID)
		if err != nil {
			return errors.New("Error creating vault login request: " + err.Error())
		}
		conf.Vault.VaultLogin = &l
	}
	token, err := conf.Vault.VaultLogin.GetToken()
	if err != nil {
		return errors.New("Error getting login token to the Vault: " + err.Error())
	}
	conf.MFAServer.Loggers.Debug.Println("Retrieved token for Vault access")
	if conf.Vault.VaultClient == nil {
		//There has never been a client created
		conf.MFAServer.Loggers.Debug.Println("Creating new Vault client object")
		c, err := vaultAPI.NewClient(conf.Vault.VaultConfig)
		if err != nil {
			return errors.New("Unable to create Vault client: " + err.Error())
		}
		conf.Vault.VaultClient = c
	}
	conf.MFAServer.Loggers.Debug.Println("Setting login token on Vault client")
	conf.Vault.VaultClient.SetToken(token)
	return nil
}

func Store(conf *config.Config, p string, k string, v string) error {
	if err := vaultClientLogin(conf); err != nil {
		conf.MFAServer.Loggers.Error.Printf("Problem logging into the Vault during write/store operation: %v\n", err)
		return err
	}
	logical := conf.Vault.VaultClient.Logical()
	toWrite := map[string]interface{}{
		k: v,
	}
	_, err := logical.Write(*conf.Vault.MFASecretsPath+p, toWrite)
	if err != nil {
		conf.MFAServer.Loggers.Error.Printf("Could not write secret into the Vault at %s: %v\n", *conf.Vault.MFASecretsPath+p, err)
		return err
	}
	//s, err = logical.Read(*conf.MFASecretsPath)
	return nil
}

func Read(conf *config.Config, p string) (map[string]interface{}, error) {
	if err := vaultClientLogin(conf); err != nil {
		conf.MFAServer.Loggers.Error.Printf("Problem logging into the Vault during read operation: %v\n", err)
		return nil, err
	}
	logical := conf.Vault.VaultClient.Logical()
	s, err := logical.Read(*conf.Vault.MFASecretsPath + p)
	if err != nil {
		conf.MFAServer.Loggers.Error.Printf("Issue when reading secret from Vault at %s: %v\n", *conf.Vault.MFASecretsPath+p, err)
	}
	if s == nil {
		return nil, err
	}
	return s.Data, err
}

func Exists(conf *config.Config, p string, k string) bool {
	if err := vaultClientLogin(conf); err != nil {
		conf.MFAServer.Loggers.Error.Printf("Problem logging into the Vault during list operation: %v\n", err)
		return false
	}
	logical := conf.Vault.VaultClient.Logical()
	//Tried using the List method in the following line but it did not return any data when it should have.
	s, err := logical.Read(*conf.Vault.MFASecretsPath + p)
	if err != nil {
		conf.MFAServer.Loggers.Error.Printf("Issue when listing secrets from Vault at %s: %v\n", *conf.Vault.MFASecretsPath+p, err)
		return false
	}
	if s == nil {
		return false
	}
	_, ok := s.Data[k]
	return ok
}
