package ldap

import (
	"github.com/jcmturner/mfaserver/config"
	"strings"
)

func Authenticate(u, p string, c *config.Config) error {
	err := c.LDAP.LDAPConnection.Connect()
	if err != nil {
		return err
	}
	u = strings.Replace(*c.LDAP.UserDN, "{username}", u, -1)
	//defer c.LDAP.LDAPConnection.Close()
	err = c.LDAP.LDAPConnection.Bind(u, p)
	return err
}
