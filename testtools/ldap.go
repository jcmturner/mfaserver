package testtools

import (
	ldap "github.com/vjeantet/ldapserver"
	"testing"
)

func NewLDAPServer(t *testing.T) *ldap.Server {
	//Create a new LDAP Server
	server := ldap.NewServer()

	routes := ldap.NewRouteMux()
	routes.Bind(func(w ldap.ResponseWriter, m *ldap.Message) {
		handleBind(w, m, t)
	})
	server.Handle(routes)

	// listen on 10389
	go server.ListenAndServe("127.0.0.1:0")
	t.Log("LDAP Server: Mock LDAP server running")

	return server
}

func handleBind(w ldap.ResponseWriter, m *ldap.Message, t *testing.T) {
	r := m.GetBindRequest()
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	if r.AuthenticationChoice() == "simple" {
		if string(r.Name()) == "validuser" && string(r.AuthenticationSimple()) == "validpassword" {
			t.Logf("LDAP Server: Bind success User=%s, Pass=%s", string(r.Name()), string(r.AuthenticationSimple()))
			w.Write(res)
			return
		}
		t.Logf("LDAP Server: Bind failed User=%s, Pass=%s", string(r.Name()), string(r.AuthenticationSimple()))
		res.SetResultCode(ldap.LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage("invalid credentials")
	} else {
		t.Logf("LDAP Server: Authentication choice not supported")
		res.SetResultCode(ldap.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("LDAP Server: Authentication choice not supported")
	}
	w.Write(res)
}
