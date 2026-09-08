package tokenstore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	litellmauth "github.com/balcsida/litellm-auth-go"
)

func TestFileStoreKeepsPKCEMetadata(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "token.json"))
	if err != nil {
		t.Fatal(err)
	}
	credential := litellmauth.Credential{
		BaseURL: "https://proxy.example.com", Key: "sk-k", AuthMethod: litellmauth.AuthMethodPKCE,
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		RefreshToken: "llm_srefresh_x", ClientID: "llm_dcrc_x", TokenEndpoint: "https://proxy.example.com/token",
		RevocationEndpoint: "https://proxy.example.com/revoke", Resource: "https://proxy.example.com",
	}
	if err := store.Save(context.Background(), credential); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := store.Load(context.Background(), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.RefreshToken != credential.RefreshToken || loaded.ClientID != credential.ClientID ||
		loaded.TokenEndpoint != credential.TokenEndpoint || loaded.RevocationEndpoint != credential.RevocationEndpoint ||
		loaded.Resource != credential.Resource || loaded.AuthMethod != litellmauth.AuthMethodPKCE {
		t.Fatalf("PKCE metadata lost across the file store: %+v", loaded)
	}
}

func TestFileStoreRejectsRefreshSecretsInMetadata(t *testing.T) {
	for _, test := range []struct {
		name  string
		apply func(*litellmauth.Credential, string)
	}{
		{"base URL", func(c *litellmauth.Credential, secret string) { c.BaseURL += "/" + secret }},
		{"user ID", func(c *litellmauth.Credential, secret string) { c.UserID = secret }},
		{"team ID", func(c *litellmauth.Credential, secret string) { c.TeamID = secret }},
		{"team alias", func(c *litellmauth.Credential, secret string) { c.TeamAlias = secret }},
		{"auth method", func(c *litellmauth.Credential, secret string) { c.AuthMethod = litellmauth.AuthMethod(secret) }},
		{"issuer", func(c *litellmauth.Credential, secret string) { c.Issuer = secret }},
		{"subject", func(c *litellmauth.Credential, secret string) { c.Subject = secret }},
		{"scope", func(c *litellmauth.Credential, secret string) { c.Scopes = []string{secret} }},
		{"team list ID", func(c *litellmauth.Credential, secret string) { c.Teams = []litellmauth.Team{{ID: secret}} }},
		{"team list alias", func(c *litellmauth.Credential, secret string) {
			c.Teams = []litellmauth.Team{{ID: "team-1", Alias: secret}}
		}},
		{"metadata name", func(c *litellmauth.Credential, secret string) { c.AttributionMetadata = map[string]any{secret: "safe"} }},
		{"metadata value", func(c *litellmauth.Credential, secret string) {
			c.AttributionMetadata = map[string]any{"field": secret}
		}},
		{"client ID", func(c *litellmauth.Credential, secret string) { c.ClientID = secret }},
		{"token endpoint", func(c *litellmauth.Credential, secret string) { c.TokenEndpoint = c.BaseURL + "/" + secret }},
		{"revocation endpoint", func(c *litellmauth.Credential, secret string) { c.RevocationEndpoint = c.BaseURL + "/" + secret }},
		{"resource", func(c *litellmauth.Credential, secret string) { c.Resource = c.BaseURL + "/" + secret }},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(privateTempDir(t), "token.json")
			store, err := NewFileStore(path)
			if err != nil {
				t.Fatal(err)
			}
			credential := validCredential("access-secret")
			credential.ExpiresAt = credential.IssuedAt.Add(time.Hour)
			credential.RefreshToken = "refresh-secret"
			test.apply(&credential, "prefix-"+credential.RefreshToken+"-suffix")
			if err := store.Save(context.Background(), credential); !errors.Is(err, litellmauth.ErrProtocol) {
				t.Errorf("Save() error = %v, want ErrProtocol", err)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("Save() wrote unsafe credential: %v", err)
			}
			// Build a tampered file without going through the store's save guard.
			credential.RefreshToken = ""
			stored, err := credentialForSave(credential)
			if err != nil {
				t.Fatal(err)
			}
			stored.RefreshToken = "refresh-secret"
			body, err := json.Marshal(stored)
			if err != nil {
				t.Fatal(err)
			}
			writeTokenFile(t, path, string(body))
			if _, err := store.Load(context.Background(), nil); !errors.Is(err, litellmauth.ErrProtocol) {
				t.Errorf("Load() error = %v, want ErrProtocol", err)
			}
		})
	}
}
