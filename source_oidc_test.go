package litellmauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/balcsida/litellm-auth-go/internal/testserver"
)

func TestOIDCSourceReusesFreshCredential(t *testing.T) {
	now := time.Now()
	store := &oidcSourceStore{credential: oidcSourceCredential(now.Add(time.Hour), ptr(validOIDCRefresh("https://idp.example.com/token")))}
	client, err := New("https://proxy.example.com")
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewOIDCSource(client, store)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }

	credential, err := source.Credential(context.Background())
	if err != nil || credential.Key != store.credential.Key || store.saveCalls != 0 {
		t.Fatalf("Credential() = %#v, %v; saves = %d", credential, err, store.saveCalls)
	}
}

func TestOIDCSourceRefreshesNearExpiryCredentialAndSavesRotation(t *testing.T) {
	now := time.Now()
	requests := 0
	server := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || string(body) != "client_id=client&grant_type=refresh_token&refresh_token=refresh" {
			t.Fatalf("request = %s %q", r.Method, body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"`+oidcJWT(time.Now().Add(time.Hour))+`","token_type":"Bearer","refresh_token":"rotated"}`)
	}))
	defer server.Close()

	store := &oidcSourceStore{credential: oidcSourceCredential(now.Add(credentialClockSkew), ptr(validOIDCRefresh(server.URL)))}
	client, err := New(server.URL, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewOIDCSource(client, store)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }

	credential, err := source.Credential(context.Background())
	if err != nil || requests != 1 || store.saveCalls != 1 || credential.OIDCRefresh.RefreshToken != "rotated" || store.credential.OIDCRefresh.RefreshToken != "rotated" {
		t.Fatalf("Credential() = %#v, %v; requests = %d saves = %d stored = %#v", credential, err, requests, store.saveCalls, store.credential)
	}
}

func TestOIDCSourceRefreshFailurePreservesStoredCredential(t *testing.T) {
	now := time.Now()
	server := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadRequest) }))
	defer server.Close()
	stored := oidcSourceCredential(now.Add(-time.Hour), ptr(validOIDCRefresh(server.URL)))
	store := &oidcSourceStore{credential: stored}
	client, _ := New(server.URL, WithHTTPClient(server.Client()))
	source, err := NewOIDCSource(client, store)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }

	_, err = source.Credential(context.Background())
	if err == nil || store.saveCalls != 0 || store.credential.Key != stored.Key || store.credential.OIDCRefresh.RefreshToken != "refresh" {
		t.Fatalf("Credential() error = %v; saves = %d stored = %#v", err, store.saveCalls, store.credential)
	}
}

func TestOIDCSourceRequiresLoginWithoutRefreshMetadata(t *testing.T) {
	now := time.Now()
	store := &oidcSourceStore{credential: Credential{Key: "header.eyJleHAiOjF9.signature", AuthMethod: AuthMethodOIDC, TokenType: "Bearer", ExpiresAt: now.Add(-time.Hour)}}
	client, _ := New("https://proxy.example.com")
	source, err := NewOIDCSource(client, store)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }

	if _, err := source.Credential(context.Background()); !errors.Is(err, ErrCredentialStale) || store.saveCalls != 0 {
		t.Fatalf("Credential() error = %v; saves = %d", err, store.saveCalls)
	}
}

func TestOIDCSourceHonorsCanceledContext(t *testing.T) {
	client, _ := New("https://proxy.example.com")
	store := &oidcSourceStore{}
	source, err := NewOIDCSource(client, store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := source.Credential(ctx); !errors.Is(err, context.Canceled) || store.loadCalls != 0 {
		t.Fatalf("Credential() error = %v; loads = %d", err, store.loadCalls)
	}
}

func TestOIDCSourceConcurrentCallsShareRefresh(t *testing.T) {
	now := time.Now()
	started := make(chan struct{})
	release := make(chan struct{})
	requests := 0
	server := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		close(started)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"`+oidcJWT(time.Now().Add(time.Hour))+`","token_type":"Bearer"}`)
	}))
	defer server.Close()
	store := &oidcSourceStore{credential: oidcSourceCredential(now.Add(-time.Hour), ptr(validOIDCRefresh(server.URL)))}
	client, _ := New(server.URL, WithHTTPClient(server.Client()))
	source, err := NewOIDCSource(client, store)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }

	errs := make(chan error, 2)
	for range 2 {
		go func() { _, err := source.Credential(context.Background()); errs <- err }()
	}
	<-started
	close(release)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if requests != 1 || store.saveCalls != 1 {
		t.Fatalf("requests = %d saves = %d", requests, store.saveCalls)
	}
}

func TestOIDCSourceStringIsSecretFree(t *testing.T) {
	client, _ := New("https://proxy.example.com")
	source, err := NewOIDCSource(client, &oidcSourceStore{})
	if err != nil || source.String() != "refreshing OIDC authentication source" || source.GoString() != source.String() {
		t.Fatalf("source = %v; error = %v", source, err)
	}
}

type oidcSourceStore struct {
	mu         sync.Mutex
	credential Credential
	loadCalls  int
	saveCalls  int
}

func (s *oidcSourceStore) Load(ctx context.Context, _ *url.URL) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadCalls++
	return s.credential.Clone(), nil
}

func (s *oidcSourceStore) Save(ctx context.Context, credential Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saveCalls++
	s.credential = credential.Clone()
	return nil
}

func oidcSourceCredential(expiresAt time.Time, refresh *OIDCRefresh) Credential {
	return Credential{Key: oidcJWT(expiresAt), AuthMethod: AuthMethodOIDC, TokenType: "Bearer", ExpiresAt: expiresAt, OIDCRefresh: refresh}
}

func ptr[T any](value T) *T { return &value }
