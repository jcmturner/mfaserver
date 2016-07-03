package testtools

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/go-uuid"
	vaultAPI "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/audit"
	auditFile "github.com/hashicorp/vault/builtin/audit/file"
	auditSyslog "github.com/hashicorp/vault/builtin/audit/syslog"
	credAppId "github.com/hashicorp/vault/builtin/credential/app-id"
	credAwsEc2 "github.com/hashicorp/vault/builtin/credential/aws-ec2"
	credCert "github.com/hashicorp/vault/builtin/credential/cert"
	credGitHub "github.com/hashicorp/vault/builtin/credential/github"
	credLdap "github.com/hashicorp/vault/builtin/credential/ldap"
	credUserpass "github.com/hashicorp/vault/builtin/credential/userpass"
	"github.com/hashicorp/vault/builtin/logical/aws"
	"github.com/hashicorp/vault/builtin/logical/cassandra"
	"github.com/hashicorp/vault/builtin/logical/consul"
	"github.com/hashicorp/vault/builtin/logical/mssql"
	"github.com/hashicorp/vault/builtin/logical/mysql"
	"github.com/hashicorp/vault/builtin/logical/pki"
	"github.com/hashicorp/vault/builtin/logical/postgresql"
	"github.com/hashicorp/vault/builtin/logical/ssh"
	"github.com/hashicorp/vault/builtin/logical/transit"
	vaultHTTP "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/physical"
	"github.com/hashicorp/vault/vault"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

func RunMockVault(t *testing.T) (net.Listener, string, string, string) {
	test_app_id, _ := uuid.GenerateUUID()
	test_user_id, _ := uuid.GenerateUUID()
	logger := log.New(os.Stderr, "Mock Vault: ", log.LstdFlags)
	inm := physical.NewInmem(logger)
	coreConfig := &vault.CoreConfig{
		AuditBackends: map[string]audit.Factory{
			"file":   auditFile.Factory,
			"syslog": auditSyslog.Factory,
		},
		CredentialBackends: map[string]logical.Factory{
			"cert":     credCert.Factory,
			"aws-ec2":  credAwsEc2.Factory,
			"app-id":   credAppId.Factory,
			"github":   credGitHub.Factory,
			"userpass": credUserpass.Factory,
			"ldap":     credLdap.Factory,
		},
		LogicalBackends: map[string]logical.Factory{
			"aws":        aws.Factory,
			"consul":     consul.Factory,
			"postgresql": postgresql.Factory,
			"cassandra":  cassandra.Factory,
			"pki":        pki.Factory,
			"transit":    transit.Factory,
			"mssql":      mssql.Factory,
			"mysql":      mysql.Factory,
			"ssh":        ssh.Factory,
		},
		Physical:     inm,
		Logger:       logger,
		DisableMlock: true,
	}

	core, _ := vault.NewCore(coreConfig)
	key, token := vault.TestCoreInit(t, core)
	if _, err := core.Unseal(vault.TestKeyCopy(key)); err != nil {
		t.Fatalf("unseal err: %s", err)
	}
	sealed, err := core.Sealed()
	if err != nil {
		t.Fatalf("Mock Vault Error unsealing: %s", err)
	}
	if sealed {
		t.Fatal("Mock Vault sealed but shouldn't be")
	}

	ln, addr := vaultHTTP.TestServer(t, core)
	cfg := vaultAPI.DefaultConfig()
	cfg.Address = addr

	c, _ := vaultAPI.NewClient(cfg)
	c.SetToken(token)
	err = c.Sys().EnableAuth("app-id", "app-id", "app-id")
	if err != nil {
		t.Fatalf("Error enabling app-id on mock vault: %v", err)
	}

	req, err := http.NewRequest("POST", addr+"/v1/auth/app-id/map/app-id/"+test_app_id, bytes.NewBufferString(`{"value":"root", "display_name":"test"}`))
	req.Header.Set("X-Vault-Token", token)
	if err != nil {
		t.Fatalf("Error creating http request to set up app-id for mock vault: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Error setting up app-id for mock vault: HTTP code: %v Error: %v", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusNoContent {
		defer resp.Body.Close()
		html, _ := ioutil.ReadAll(resp.Body)
		t.Fatalf("Error setting up app-id for mock vault: HTTP code: %v Response: %v", resp.StatusCode, string(html))
	}

	req, err = http.NewRequest("POST", addr+"/v1/auth/app-id/map/user-id/"+test_user_id, bytes.NewBufferString(fmt.Sprintf(`{"value":"%s"}`, test_app_id)))
	req.Header.Set("X-Vault-Token", token)
	if err != nil {
		t.Fatalf("Error creating http request to map user-id to app-id for mock vault: %v", err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Error mapping user-id to app-id for mock vault: HTTP code: %v Error: %v", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusNoContent {
		defer resp.Body.Close()
		html, _ := ioutil.ReadAll(resp.Body)
		t.Fatalf("Error mapping user-id to app-id for mock vault: HTTP code: %v Response: %v", resp.StatusCode, string(html))
	}
	return ln, addr, test_app_id, test_user_id

}

func GenerateSelfSignedTLSKeyPairFiles(t *testing.T) (string, string) {
	derBytes, priv := GenerateSelfSignedTLSKeyPairData(t)
	certOut, _ := ioutil.TempFile(os.TempDir(), "testCert")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	keyOut, _ := ioutil.TempFile(os.TempDir(), "testKey")
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	return certOut.Name(), keyOut.Name()
}

func GenerateSelfSignedTLSKeyPairData(t *testing.T) ([]byte, *rsa.PrivateKey) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 2 * 365 * 24)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: true,
	}
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))
	template.DNSNames = append(template.DNSNames, "testhost.example.com")
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Errorf("Error creating certifcate for testing: %v", err)
	}
	return derBytes, priv
}
