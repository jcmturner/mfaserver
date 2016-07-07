package secrets

import (
	"github.com/jcmturner/mfaserver/config"
	"github.com/jcmturner/mfaserver/testtools"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

const (
	testMFAUser        = "domain/testuser"
	testMFARef         = "mfa"
	testMFASecret      = "1234567890"
	testMFASecretsPath = "secret/domain/testuser"
)

func mockVault(t *testing.T) (*config.Config, net.Listener) {
	ln, addr, appID, userID := testtools.RunMockVault(t)

	conf := config.NewConfig()
	conf.WithVaultAppIdRead(appID)
	conf.WithVaultAppIdWrite(appID)
	conf.WithVaultUserId(userID)
	conf.WithVaultEndPoint(addr)
	conf.WithVaultMFASecretsPath(testMFASecretsPath)
	return conf, ln
}

func TestStore(t *testing.T) {
	conf, ln := mockVault(t)
	defer ln.Close()

	if err := Store(conf, testMFAUser, testMFARef, testMFASecret); err != nil {
		t.Fatalf("Error when storing secret")
	}
}

func TestStoreAndRead(t *testing.T) {
	conf, ln := mockVault(t)
	defer ln.Close()

	if err := Store(conf, testMFAUser, testMFARef, testMFASecret); err != nil {
		t.Fatalf("Error when storing secret")
	}
	m, err := Read(conf, testMFAUser)
	if err != nil {
		t.Errorf("Could not read secret back from vault: %v", err)
	}
	assert.Equal(t, testMFASecret, m[testMFARef], "Secret read is not the value expected")
}
