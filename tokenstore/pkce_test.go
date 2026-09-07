package tokenstore

import (
	"context"
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
