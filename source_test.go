package litellmauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/balcsida/litellm-auth-go/internal/testserver"
)

func TestStaticSourceReturnsIndependentCredential(t *testing.T) {
	source, err := NewStaticSource("sk-static", SourceConfig{
		BaseURL:     "https://proxy.example.com",
		NonExpiring: true,
		Scopes:      []string{"scope-a"},
	})
	if err != nil {
		t.Fatal(err)
	}

	first, err := source.Credential(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first.Scopes[0] = "changed"

	second, err := source.Credential(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second.Key != "sk-static" ||
		second.AuthMethod != AuthMethodStatic ||
		second.TokenType != "Bearer" ||
		second.Scopes[0] != "scope-a" {
		t.Fatalf("credential = %#v", second)
	}
}

func TestStaticSourceFailsClosedWithoutLifetime(t *testing.T) {
	_, err := NewStaticSource("sk-static", SourceConfig{})
	if !errors.Is(err, ErrCredentialExpiryUnknown) {
		t.Fatalf("NewStaticSource() error = %v", err)
	}
}

func TestSourceFuncImplementsSource(t *testing.T) {
	var source Source = SourceFunc(func(context.Context) (Credential, error) {
		return Credential{
			Key: "sk-key", AuthMethod: AuthMethodStatic, NonExpiring: true,
		}, nil
	})
	credential, err := source.Credential(context.Background())
	if err != nil || credential.Key != "sk-key" {
		t.Fatalf("Credential() = %#v, %v", credential, err)
	}
}

func TestStaticSourceHonorsCanceledContext(t *testing.T) {
	source, err := NewStaticSource("sk-static", SourceConfig{NonExpiring: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Credential(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Credential() error = %v", err)
	}
}

func TestSourceConfigExplicitExpiry(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour)
	source, err := NewStaticSource("sk-static", SourceConfig{ExpiresAt: expiresAt})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := source.Credential(context.Background())
	if err != nil || !credential.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("Credential() = %#v, %v", credential, err)
	}
}

func TestSSOSourceCachesFreshCredentialAndCanInvalidate(t *testing.T) {
	requests := 0
	server := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			_, _ = io.WriteString(w, `{"login_id":"login-1","poll_secret":"secret","user_code":"CODE","expires_in":60}`)
		case http.MethodGet:
			_, _ = io.WriteString(w, `{"status":"ready","key":"sk-sso"}`)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
		}
	}))
	defer server.Close()

	client, err := New(server.URL, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewSSOSource(client, AuthenticateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for range 2 {
		credential, err := source.Credential(context.Background())
		if err != nil || credential.Key != "sk-sso" {
			t.Fatalf("Credential() = %#v, %v", credential, err)
		}
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want one start and one poll", requests)
	}

	source.Invalidate()
	if _, err := source.Credential(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests != 4 {
		t.Fatalf("requests after invalidate = %d, want 4", requests)
	}
}
