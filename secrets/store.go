package secrets

import (
	"errors"
	vaultAPI "github.com/hashicorp/vault/api"
	"github.com/jcmturner/mfaserver/config"
	"github.com/jcmturner/mfaserver/vault"
)

func vaultClientLogin(conf *config.VaultConf) error {
	if conf.VaultLogin == nil {
		var l vault.Login
		l.NewRequest(conf.VaultReSTClientConfig, *conf.AppIDWrite, *conf.UserID)
		l.Process()
		conf.VaultLogin = &l
	}
	token, err := conf.VaultLogin.GetToken()
	if err != nil {
		return err
	}
	if conf.VaultClient == nil {
		//There has never been a client created
		c, err := vaultAPI.NewClient(conf.VaultConfig)
		if err != nil {
			return errors.New("Unable to create vault client: " + err.Error())
		}
		conf.VaultClient = c
	}
	conf.VaultClient.SetToken(token)
	return nil
}

func Store(conf *config.VaultConf, p string, k string, v string) bool {
	if err := vaultClientLogin(conf); err != nil {
		return false
	}
	logical := conf.VaultClient.Logical()
	toWrite := map[string]interface{}{
		k: v,
	}
	_, err := logical.Write(*conf.MFASecretsPath+p, toWrite)
	if err != nil {
		return false
	}
	//s, err = logical.Read(*conf.MFASecretsPath)
	return true
}

func Read(conf *config.VaultConf, p string) (map[string]interface{}, error) {
	if err := vaultClientLogin(conf); err != nil {
		return nil, err
	}
	logical := conf.VaultClient.Logical()
	s, err := logical.Read(*conf.MFASecretsPath + p)
	return s.Data, err
}
