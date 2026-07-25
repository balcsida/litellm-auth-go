package litellmauth

import (
	"context"
	"errors"
	"sync"
	"time"
)

// StaticSource returns one immutable configured credential.
type StaticSource struct {
	credential Credential
}

// NewStaticSource creates a static source.
func NewStaticSource(key string, config SourceConfig) (*StaticSource, error) {
	credential, err := credentialFromSource(key, AuthMethodStatic, config, time.Now())
	if err != nil {
		return nil, err
	}
	return &StaticSource{credential: credential.Clone()}, nil
}

// Credential returns an independent credential copy.
func (s *StaticSource) Credential(ctx context.Context) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	if s == nil {
		return Credential{}, ErrSourceUnavailable
	}
	return s.credential.Clone(), nil
}

// String returns a secret-free description.
func (*StaticSource) String() string { return "static authentication source" }

// GoString returns a secret-free description.
func (s *StaticSource) GoString() string { return s.String() }

// SSOSource adapts the existing LiteLLM CLI SSO client to Source.
type SSOSource struct {
	client  *Client
	options AuthenticateOptions
	now     func() time.Time

	mu     sync.Mutex
	cached *Credential
}

// NewSSOSource creates an SSO source.
func NewSSOSource(client *Client, options AuthenticateOptions) (*SSOSource, error) {
	if client == nil {
		return nil, errors.New("LiteLLM SSO source client must not be nil")
	}
	return &SSOSource{
		client:  client,
		options: options,
		now:     time.Now,
	}, nil
}

// Credential authenticates through LiteLLM CLI SSO.
func (s *SSOSource) Credential(ctx context.Context) (Credential, error) {
	if s == nil || s.client == nil || s.now == nil {
		return Credential{}, ErrSourceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}

	if s.cached != nil && s.cached.Fresh(s.now()) {
		return s.cached.Clone(), nil
	}
	credential, err := s.client.Authenticate(ctx, s.options)
	if err != nil {
		return Credential{}, err
	}
	credential.AuthMethod = AuthMethodLiteLLMSSO
	if credential.TokenType == "" {
		credential.TokenType = "Bearer"
	}
	if err := credential.Validate(); err != nil {
		return Credential{}, err
	}
	if !credential.Fresh(s.now()) {
		return Credential{}, ErrCredentialStale
	}
	cloned := credential.Clone()
	s.cached = &cloned
	return credential.Clone(), nil
}

// Invalidate clears the cached SSO credential.
func (s *SSOSource) Invalidate() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.cached = nil
	s.mu.Unlock()
}

// String returns a secret-free description.
func (*SSOSource) String() string { return "LiteLLM CLI SSO source" }

// GoString returns a secret-free description.
func (s *SSOSource) GoString() string { return s.String() }
