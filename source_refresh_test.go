package litellmauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type memoryStore struct {
	mu         sync.Mutex
	credential Credential
	loadErr    error
	saveErr    error
	saves      int
}

func (m *memoryStore) Load(context.Context, *url.URL) (Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadErr != nil {
		return Credential{}, m.loadErr
	}
	return m.credential.Clone(), nil
}

func (m *memoryStore) Save(_ context.Context, credential Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	m.credential = credential.Clone()
	m.saves++
	return nil
}

func (m *memoryStore) saveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saves
}

func (idp *fakeIdP) devicePollCount() int {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.devicePolls
}

func (idp *fakeIdP) deviceCallCount() int {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.deviceCalls
}

func (idp *fakeIdP) discoveryCallCount() int {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.discoveryCalls
}

func (idp *fakeIdP) tokenCallCount() int {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.tokenCalls
}

// staleOIDCSource logs in through the fake IdP and returns a source over a
// store holding that credential, expired when stale is true.
func staleOIDCSource(t *testing.T, idp *fakeIdP, stale bool) (*RefreshingSource, *memoryStore) {
	t.Helper()
	client := idp.client(t)
	credential, err := client.AuthenticateOIDC(context.Background(), OIDCOptions{Provider: idp.provider(), OnSession: idp.browse})
	if err != nil {
		t.Fatalf("AuthenticateOIDC: %v", err)
	}
	if stale {
		credential.ExpiresAt = time.Now().Add(-time.Hour)
	}
	store := &memoryStore{credential: credential}
	source, err := NewRefreshingSource(client, store)
	if err != nil {
		t.Fatalf("NewRefreshingSource: %v", err)
	}
	return source, store
}

func TestRefreshingSourceFreshCredentialMakesNoTokenRequest(t *testing.T) {
	idp := newFakeIdP(t)
	source, store := staleOIDCSource(t, idp, false)
	before := idp.tokenCallCount()

	got, err := source.Credential(context.Background())
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	got.Scopes[0] = "mutated"
	if store.credential.Scopes[0] == "mutated" {
		t.Fatal("returned credential must be a clone")
	}
	if idp.tokenCallCount() != before || store.saveCount() != 0 {
		t.Fatal("a fresh credential must not trigger a refresh")
	}
}

func TestRefreshingSourceRefreshesOnceForConcurrentCallers(t *testing.T) {
	idp := newFakeIdP(t)
	source, store := staleOIDCSource(t, idp, true)
	before := idp.tokenCallCount()

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := source.Credential(context.Background())
			if err == nil && !got.Fresh(time.Now()) {
				err = errors.New("credential is not fresh")
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Credential: %v", err)
		}
	}
	if calls := idp.tokenCallCount() - before; calls != 1 {
		t.Fatalf("token requests = %d; want 1", calls)
	}
	if saves := store.saveCount(); saves != 1 {
		t.Fatalf("saves = %d; want 1", saves)
	}
}

func TestRefreshingSourceRejectedRefreshLeavesStoreUntouched(t *testing.T) {
	idp := newFakeIdP(t)
	source, store := staleOIDCSource(t, idp, true)
	idp.disabledUser = true

	if _, err := source.Credential(context.Background()); !errors.Is(err, ErrRefreshRejected) {
		t.Fatalf("err = %v; want ErrRefreshRejected", err)
	}
	if store.saveCount() != 0 {
		t.Fatal("a rejected refresh must not save")
	}
}

func TestRefreshingSourceStaleWithoutRefreshToken(t *testing.T) {
	idp := newFakeIdP(t)
	source, store := staleOIDCSource(t, idp, true)
	store.credential.RefreshToken = ""
	before := idp.tokenCallCount()

	if _, err := source.Credential(context.Background()); !errors.Is(err, ErrCredentialStale) {
		t.Fatalf("err = %v; want ErrCredentialStale", err)
	}
	if idp.tokenCallCount() != before {
		t.Fatal("no token request expected without a refresh token")
	}
}

func TestRefreshingSourceReturnsLoadErrorUnchanged(t *testing.T) {
	idp := newFakeIdP(t)
	source, store := staleOIDCSource(t, idp, true)
	store.loadErr = ErrNoCredential

	if _, err := source.Credential(context.Background()); err != ErrNoCredential {
		t.Fatalf("err = %v; want ErrNoCredential unchanged", err)
	}
}

func TestRefreshingSourceWaiterHonoursContext(t *testing.T) {
	idp := newFakeIdP(t)
	source, _ := staleOIDCSource(t, idp, true)
	idp.holdRefresh = make(chan struct{})

	first := make(chan error, 1)
	go func() {
		_, err := source.Credential(context.Background())
		first <- err
	}()
	for deadline := time.Now().Add(5 * time.Second); len(source.refresh) != 0; {
		if time.Now().After(deadline) {
			t.Fatal("first caller never started refreshing")
		}
		time.Sleep(time.Millisecond)
	}

	ctx, cancel := context.WithCancel(context.Background())
	second := make(chan error, 1)
	go func() {
		_, err := source.Credential(ctx)
		second <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := <-second; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter err = %v; want context.Canceled", err)
	}
	close(idp.holdRefresh)
	if err := <-first; err != nil {
		t.Fatalf("first caller: %v", err)
	}
}

func TestRefreshingSourceRenewsPKCECredential(t *testing.T) {
	proxy := newFakePKCEProxy(t)
	client := proxy.client(t)
	credential, err := client.AuthenticatePKCE(context.Background(), PKCEOptions{OnSession: proxy.browse})
	if err != nil {
		t.Fatalf("AuthenticatePKCE: %v", err)
	}
	credential.ExpiresAt = time.Now().Add(-time.Hour)
	store := &memoryStore{credential: credential}
	source, err := NewRefreshingSource(client, store)
	if err != nil {
		t.Fatal(err)
	}

	got, err := source.Credential(context.Background())
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	if got.Key == credential.Key || store.saveCount() != 1 {
		t.Fatal("stale PKCE credential must be renewed and saved")
	}
}

func TestClientRefreshRejectsUnrefreshableCredentials(t *testing.T) {
	client, err := New("https://proxy.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range []Credential{
		{AuthMethod: AuthMethodLiteLLMSSO, RefreshToken: "rt-secret"},
		{AuthMethod: AuthMethodPKCE},
		{AuthMethod: AuthMethodOIDC},
	} {
		if _, err := client.Refresh(context.Background(), credential); !errors.Is(err, ErrRefreshRejected) {
			t.Fatalf("Refresh(%s) err = %v; want ErrRefreshRejected", credential.AuthMethod, err)
		}
	}
}

func TestNewRefreshingSourceValidatesArguments(t *testing.T) {
	client, err := New("https://proxy.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRefreshingSource(nil, &memoryStore{}); err == nil {
		t.Fatal("nil client must be rejected")
	}
	if _, err := NewRefreshingSource(client, nil); err == nil {
		t.Fatal("nil store must be rejected")
	}
	source, err := NewRefreshingSource(client, &memoryStore{credential: Credential{Key: "sk-secret", RefreshToken: "rt-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{source.String(), source.GoString(), fmt.Sprintf("%v %+v %#v", source, source, source)} {
		if strings.Contains(text, "secret") {
			t.Fatalf("output leaks a secret: %q", text)
		}
	}
}
