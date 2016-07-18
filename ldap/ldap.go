package ldap

import (
	"errors"
	"fmt"
	"github.com/jcmturner/mfaserver/config"
	"github.com/mavricknz/ldap"
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

func AdminAuthorise(u, p string, c *config.Config) error {
	var attributes []string = []string{*c.LDAP.AdminMembershipAttr}
	m := strings.Replace(*c.LDAP.AdminMemberUserDN, "{username}", u, -1)
	f := fmt.Sprintf("(%s=%s)", *c.LDAP.AdminMembershipAttr, m)
	r := ldap.NewSimpleSearchRequest(*c.LDAP.AdminGroupDN, ldap.ScopeBaseObject, f, attributes)

	err := c.LDAP.LDAPConnection.Connect()
	if err != nil {
		return err
	}

	err = c.LDAP.LDAPConnection.Bind(u, p)
	if err != nil {
		return err
	}

	sr, err := c.LDAP.LDAPConnection.Search(r)
	if err != nil {
		return err
	}

	members := sr.Entries[0].GetAttributeValues(*c.LDAP.AdminMembershipAttr)
	for _, b := range members {
		if b == m {
			return nil
		}
	}
	return errors.New("Admin authorisation failed.")
}
