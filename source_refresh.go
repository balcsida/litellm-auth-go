package litellmauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// CredentialStore loads and saves one stored credential. tokenstore.FileStore
// implements it; the interface lives here because tokenstore imports this
// package.
type CredentialStore interface {
	Load(context.Context, *url.URL) (Credential, error)
	Save(context.Context, Credential) error
}

// Refresh renews a PKCE or OIDC credential with its refresh token. Any other
// credential, or one without a refresh token, yields ErrRefreshRejected.
func (c *Client) Refresh(ctx context.Context, credential Credential) (Credential, error) {
	if credential.RefreshToken != "" {
		switch credential.AuthMethod {
		case AuthMethodPKCE:
			return c.RefreshPKCE(ctx, credential)
		case AuthMethodOIDC:
			return c.RefreshOIDC(ctx, OIDCProvider{
				Issuer:   credential.Issuer,
				ClientID: credential.ClientID,
				Scope:    strings.Join(credential.Scopes, " "),
				TokenURL: credential.TokenEndpoint,
			}, credential)
		}
	}
	return Credential{}, fmt.Errorf("%w: credential cannot be refreshed", ErrRefreshRejected)
}

// RefreshingSource loads a stored credential and renews it, saving the result,
// when it is stale.
type RefreshingSource struct {
	client  *Client
	store   CredentialStore
	baseURL *url.URL
	now     func() time.Time

	// refresh is a one-slot semaphore, created full; holding the token means
	// holding the right to refresh.
	refresh chan struct{}
}

// NewRefreshingSource creates a source over store that refreshes through client.
func NewRefreshingSource(client *Client, store CredentialStore) (*RefreshingSource, error) {
	if client == nil {
		return nil, errors.New("LiteLLM refreshing source client must not be nil")
	}
	if store == nil {
		return nil, errors.New("LiteLLM refreshing source store must not be nil")
	}
	baseURL, err := url.Parse(client.baseURL)
	if err != nil {
		return nil, errors.New("LiteLLM refreshing source client base URL is invalid")
	}
	refresh := make(chan struct{}, 1)
	refresh <- struct{}{}
	return &RefreshingSource{client: client, store: store, baseURL: baseURL, now: time.Now, refresh: refresh}, nil
}

// Credential returns the stored credential, renewing it first when stale.
func (s *RefreshingSource) Credential(ctx context.Context) (Credential, error) {
	if s == nil || s.client == nil || s.store == nil || s.now == nil || s.refresh == nil {
		return Credential{}, ErrSourceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	credential, err := s.store.Load(ctx, s.baseURL)
	if err != nil {
		return Credential{}, err
	}
	if credential.Fresh(s.now()) {
		return credential.Clone(), nil
	}

	select {
	case <-ctx.Done():
		return Credential{}, ctx.Err()
	case <-s.refresh:
	}
	defer func() { s.refresh <- struct{}{} }()

	// Another caller may have refreshed while this one waited.
	credential, err = s.store.Load(ctx, s.baseURL)
	if err != nil {
		return Credential{}, err
	}
	if credential.Fresh(s.now()) {
		return credential.Clone(), nil
	}
	if credential.RefreshToken == "" {
		return Credential{}, ErrCredentialStale
	}
	credential, err = s.client.Refresh(ctx, credential)
	if err != nil {
		return Credential{}, err
	}
	if err := credential.Validate(); err != nil {
		return Credential{}, err
	}
	if !credential.Fresh(s.now()) {
		return Credential{}, ErrCredentialStale
	}
	if err := s.store.Save(ctx, credential); err != nil {
		return Credential{}, err
	}
	return credential.Clone(), nil
}

// String returns a secret-free description.
func (*RefreshingSource) String() string { return "refreshing stored credential source" }

// GoString returns a secret-free description.
func (s *RefreshingSource) GoString() string { return s.String() }
