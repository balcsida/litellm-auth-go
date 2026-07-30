package litellmauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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
	if err != nil || requests != 1 || store.saveCalls != 1 || credential.OIDCRefresh.RefreshToken != "rotated" || store.credential.OIDCRefresh.RefreshToken != "rotated" || len(store.baseURLs) != 2 || store.baseURLs[0] != server.URL || store.baseURLs[1] != server.URL {
		t.Fatalf("Credential() = %#v, %v; requests = %d saves = %d bases = %q stored = %#v", credential, err, requests, store.saveCalls, store.baseURLs, store.credential)
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
	if err == nil || !errors.Is(err, ErrLoginRequired) || store.saveCalls != 0 || store.credential.Key != stored.Key || store.credential.OIDCRefresh.RefreshToken != "refresh" {
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

	if _, err := source.Credential(context.Background()); !errors.Is(err, ErrLoginRequired) || store.saveCalls != 0 {
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

	if _, err := source.Credential(ctx); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrLoginRequired) || store.loadCalls != 0 {
		t.Fatalf("Credential() error = %v; loads = %d", err, store.loadCalls)
	}
}

func TestOIDCSourceCanceledRefreshPreservesStoredCredential(t *testing.T) {
	now := time.Now()
	started := make(chan struct{})
	release := make(chan struct{})
	server := testserver.New(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	stored := oidcSourceCredential(now.Add(-time.Hour), ptr(validOIDCRefresh(server.URL)))
	store := &oidcSourceStore{credential: stored}
	client, _ := New(server.URL, WithHTTPClient(server.Client()))
	source, err := NewOIDCSource(client, store)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 1)
	go func() { _, err := source.Credential(ctx); errs <- err }()
	<-started
	cancel()
	err = <-errs
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrLoginRequired) || store.saveCalls != 0 || store.credential.Key != stored.Key || store.credential.OIDCRefresh.RefreshToken != "refresh" {
		t.Fatalf("Credential() error = %v; saves = %d stored = %#v", err, store.saveCalls, store.credential)
	}
}

func TestOIDCSourceRejectsStoredCredentialFromOtherOrigin(t *testing.T) {
	client, err := New("https://proxy-a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	store := &oidcSourceStore{loadErr: ErrOriginMismatch}
	source, err := NewOIDCSource(client, store)
	if err != nil {
		t.Fatal(err)
	}

	_, err = source.Credential(context.Background())
	if !errors.Is(err, ErrOriginMismatch) || !errors.Is(err, ErrLoginRequired) || len(store.baseURLs) != 1 || store.baseURLs[0] != "https://proxy-a.example.com" {
		t.Fatalf("Credential() error = %v; bases = %q", err, store.baseURLs)
	}
}

func TestOIDCSourceInitialLoadCancellationRequiresLogin(t *testing.T) {
	client, _ := New("https://proxy.example.com")
	started := make(chan struct{})
	store := &oidcSourceStore{blockLoad: 1, loadStarted: started}
	source, err := NewOIDCSource(client, store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 1)
	go func() { _, err := source.Credential(ctx); errs <- err }()
	<-started
	cancel()
	assertSafeOIDCLoginError(t, <-errs, context.Canceled, "refresh-token")
}

func TestOIDCSourceWaitingForRefreshHonorsCancellation(t *testing.T) {
	now := time.Now()
	started := make(chan struct{})
	release := make(chan struct{})
	loads := make(chan int, 3)
	server := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"`+oidcJWT(time.Now().Add(time.Hour))+`","token_type":"Bearer"}`)
	}))
	defer server.Close()
	store := &oidcSourceStore{credential: oidcSourceCredential(now.Add(-time.Hour), ptr(validOIDCRefresh(server.URL))), loads: loads}
	client, _ := New(server.URL, WithHTTPClient(server.Client()))
	source, err := NewOIDCSource(client, store)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }

	firstDone := make(chan error, 1)
	go func() { _, err := source.Credential(context.Background()); firstDone <- err }()
	<-started
	for call := 0; call < 2; {
		call = <-loads
	}
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() { _, err := source.Credential(ctx); errs <- err }()
	if call := <-loads; call != 3 {
		t.Fatalf("load call = %d, want 3", call)
	}
	cancel()

	select {
	case err := <-errs:
		assertSafeOIDCLoginError(t, err, context.Canceled, "refresh-token")
		close(release)
		if err := <-firstDone; err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		close(release)
		<-firstDone
		<-errs
		t.Fatal("canceled caller remained blocked behind refresh")
	}
}

func TestOIDCSourceHidesLoadErrorSecrets(t *testing.T) {
	client, _ := New("https://proxy.example.com")
	cause := errors.New("refresh-token-load-secret")
	source, err := NewOIDCSource(client, &oidcSourceStore{loadErr: cause})
	if err != nil {
		t.Fatal(err)
	}
	_, err = source.Credential(context.Background())
	assertSafeOIDCLoginError(t, err, cause, "refresh-token-load-secret")
}

func TestOIDCSourceHidesSaveErrorSecrets(t *testing.T) {
	now := time.Now()
	server := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"`+oidcJWT(time.Now().Add(time.Hour))+`","token_type":"Bearer"}`)
	}))
	defer server.Close()
	cause := errors.New("refresh-token-save-secret")
	store := &oidcSourceStore{credential: oidcSourceCredential(now.Add(-time.Hour), ptr(validOIDCRefresh(server.URL))), saveErr: cause}
	client, _ := New(server.URL, WithHTTPClient(server.Client()))
	source, err := NewOIDCSource(client, store)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }
	_, err = source.Credential(context.Background())
	assertSafeOIDCLoginError(t, err, cause, "refresh-token-save-secret")
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
	mu          sync.Mutex
	credential  Credential
	loadErr     error
	loadCalls   int
	saveCalls   int
	baseURLs    []string
	blockLoad   int
	loadStarted chan struct{}
	loads       chan int
	saveErr     error
}

func (s *oidcSourceStore) Load(ctx context.Context, baseURL *url.URL) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	s.mu.Lock()
	s.loadCalls++
	if baseURL == nil {
		s.baseURLs = append(s.baseURLs, "")
	} else {
		s.baseURLs = append(s.baseURLs, baseURL.String())
	}
	credential, err := s.credential.Clone(), s.loadErr
	block := s.blockLoad == s.loadCalls
	call := s.loadCalls
	started := s.loadStarted
	loads := s.loads
	s.mu.Unlock()
	if loads != nil {
		loads <- call
	}
	if block {
		close(started)
		<-ctx.Done()
		return Credential{}, ctx.Err()
	}
	return credential, err
}

func (s *oidcSourceStore) Save(ctx context.Context, credential Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.saveCalls++
	s.credential = credential.Clone()
	err := s.saveErr
	s.mu.Unlock()
	return err
}

func assertSafeOIDCLoginError(t *testing.T, err, cause error, secret string) {
	t.Helper()
	if !errors.Is(err, ErrLoginRequired) || !errors.Is(err, cause) || strings.Contains(err.Error(), secret) || strings.Contains(fmt.Sprint(err), secret) {
		t.Fatalf("error = %v", err)
	}
}

func oidcSourceCredential(expiresAt time.Time, refresh *OIDCRefresh) Credential {
	return Credential{Key: oidcJWT(expiresAt), AuthMethod: AuthMethodOIDC, TokenType: "Bearer", ExpiresAt: expiresAt, OIDCRefresh: refresh}
}

func ptr[T any](value T) *T { return &value }
