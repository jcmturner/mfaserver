package vault

import (
	"github.com/jcmturner/mfaserver/testtools"
	"github.com/jcmturner/restclient"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestLogin_NewRequest(t *testing.T) {
	c := restclient.NewConfig().WithEndPoint("https://sometestendpoint:8200")
	var l Login
	err := l.NewRequest(c, "01bd2fe7-e5ab-47c8-ad48-9888ae6348a5", "0ecd7b5d-4885-45c1-a03f-5949e485c6bf")
	assert.NoError(t, err, "Error creating the Login request object: %v", err)
}

func TestLogin_Process(t *testing.T) {
	ln, addr, test_app_id, test_user_id := testtools.RunMockVault(t)
	defer ln.Close()
	c := restclient.NewConfig().WithEndPoint(addr)
	var l Login
	l.NewRequest(c, test_app_id, test_user_id)
	err := l.process()
	assert.NoError(t, err, "Error processing the Login request: %v", err)
}

func TestLogin_GetToken(t *testing.T) {
	ln, addr, test_app_id, test_user_id := testtools.RunMockVault(t)
	defer ln.Close()
	c := restclient.NewConfig().WithEndPoint(addr)
	//c := restclient.NewConfig().WithEndPoint("https://10.80.31.10:8200").WithCAFilePath("/Users/turnerj/git/vault-dev-env/server.crt")
	var l Login
	l.NewRequest(c, test_app_id, test_user_id)
	//l.NewRequest(c, "01bd2fe7-e5ab-47c8-ad48-9888ae6348a5", "0ecd7b5d-4885-45c1-a03f-5949e485c6bf")
	token, err := l.GetToken()
	t.Logf("token: %s", token)
	assert.NoError(t, err, "Error getting token from the Login request: %v", err)
	assert.Len(t, token, 36, "Length of the client token returned is not 36")
	//Get token again. Should be the same as the previous one as the token will not yet have expired
	token2, _ := l.GetToken()
	assert.Equal(t, token, token2, "Tokens are not the same, cached token should have been used. Token1: %s Token2: %s", token, token2)
	//Force a token expiry to get a new one
	l.validUntil = time.Now().Add(time.Second * -10)
	token3, _ := l.GetToken()
	assert.NotEqual(t, token, token3, "Tokens are the same, cached token should NOT have been used. Token1: %s Token2: %s", token, token2)
}
