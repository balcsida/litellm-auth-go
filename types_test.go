package litellmauth

import (
	"errors"
	"testing"
	"time"
)

func TestCredentialOIDCRefreshCloneAndValidate(t *testing.T) {
	refresh := validOIDCRefresh("https://idp.example.com/token")
	credential := Credential{Key: oidcJWT(time.Now().Add(time.Hour)), AuthMethod: AuthMethodOIDC, OIDCRefresh: &refresh}
	cloned := credential.Clone()
	cloned.OIDCRefresh.Scopes[0] = "changed"
	cloned.OIDCRefresh.RefreshToken = "changed"
	if credential.OIDCRefresh.Scopes[0] != "openid" || credential.OIDCRefresh.RefreshToken != "refresh" {
		t.Fatalf("clone mutated original")
	}
	if err := credential.Validate(); err != nil {
		t.Fatal(err)
	}
	credential.OIDCRefresh.RefreshToken = "bad token"
	if !errors.Is(credential.Validate(), ErrInvalidCredential) {
		t.Fatalf("Validate() = %v", credential.Validate())
	}
}
