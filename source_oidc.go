package litellmauth

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"time"
)

// OIDCCredentialStore loads and saves OIDC credentials without depending on a storage package.
type OIDCCredentialStore interface {
	Load(context.Context, *url.URL) (Credential, error)
	Save(context.Context, Credential) error
}

// OIDCSource refreshes a stored OIDC credential when it is no longer fresh.
type OIDCSource struct {
	client  *Client
	store   OIDCCredentialStore
	baseURL *url.URL
	now     func() time.Time
	mu      sync.Mutex
}

// NewOIDCSource creates a source backed by a refreshable OIDC credential store.
func NewOIDCSource(client *Client, store OIDCCredentialStore) (*OIDCSource, error) {
	if client == nil {
		return nil, errors.New("OIDC source client must not be nil")
	}
	if store == nil {
		return nil, errors.New("OIDC credential store must not be nil")
	}
	baseURL, err := url.Parse(client.baseURL)
	if err != nil {
		return nil, errors.New("OIDC source client URL is invalid")
	}
	return &OIDCSource{client: client, store: store, baseURL: baseURL, now: time.Now}, nil
}

// Credential returns the stored credential or refreshes it once for concurrent callers.
func (s *OIDCSource) Credential(ctx context.Context) (Credential, error) {
	if s == nil || s.client == nil || s.store == nil || s.baseURL == nil || s.now == nil {
		return Credential{}, ErrSourceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Credential{}, oidcLoginRequired(err)
	}
	credential, err := s.store.Load(ctx, s.baseURL)
	if err != nil {
		return Credential{}, oidcLoginRequired(err)
	}
	if credential.Fresh(s.now()) {
		return credential.Clone(), nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Credential{}, oidcLoginRequired(err)
	}
	credential, err = s.store.Load(ctx, s.baseURL)
	if err != nil {
		return Credential{}, oidcLoginRequired(err)
	}
	if credential.Fresh(s.now()) {
		return credential.Clone(), nil
	}
	if credential.AuthMethod != AuthMethodOIDC || credential.OIDCRefresh == nil {
		return Credential{}, oidcLoginRequired(ErrCredentialStale)
	}
	credential, err = s.client.Refresh(ctx, credential)
	if err != nil {
		return Credential{}, oidcLoginRequired(err)
	}
	if err := credential.Validate(); err != nil {
		return Credential{}, oidcLoginRequired(err)
	}
	if !credential.Fresh(s.now()) {
		return Credential{}, oidcLoginRequired(ErrCredentialStale)
	}
	if err := s.store.Save(ctx, credential); err != nil {
		return Credential{}, oidcLoginRequired(err)
	}
	return credential.Clone(), nil
}

// String returns a secret-free description.
func (*OIDCSource) String() string { return "refreshing OIDC authentication source" }

// GoString returns a secret-free description.
func (s *OIDCSource) GoString() string { return s.String() }

func oidcLoginRequired(err error) error { return oidcLoginRequiredError{cause: err} }

type oidcLoginRequiredError struct{ cause error }

func (oidcLoginRequiredError) Error() string      { return ErrLoginRequired.Error() }
func (e oidcLoginRequiredError) String() string   { return e.Error() }
func (e oidcLoginRequiredError) GoString() string { return e.Error() }
func (e oidcLoginRequiredError) Unwrap() []error  { return []error{ErrLoginRequired, e.cause} }
