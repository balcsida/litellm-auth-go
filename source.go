package litellmauth

import (
	"context"
	"time"
)

// Source acquires one authentication credential.
type Source interface {
	Credential(context.Context) (Credential, error)
}

// SourceFunc adapts a function to Source.
type SourceFunc func(context.Context) (Credential, error)

// Credential calls f.
func (f SourceFunc) Credential(ctx context.Context) (Credential, error) {
	if f == nil {
		return Credential{}, ErrSourceUnavailable
	}
	return f(ctx)
}

// SourceConfig supplies non-secret metadata and lifetime policy.
type SourceConfig struct {
	BaseURL     string
	AuthMethod  AuthMethod
	TokenType   string
	ExpiresAt   time.Time
	NonExpiring bool
	Issuer      string
	Subject     string
	Scopes      []string
}

func credentialFromSource(key string, defaultMethod AuthMethod, config SourceConfig, now time.Time) (Credential, error) {
	method := config.AuthMethod
	if method == "" {
		method = defaultMethod
	}
	tokenType := config.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	credential := Credential{
		BaseURL:     config.BaseURL,
		Key:         key,
		AuthMethod:  method,
		TokenType:   tokenType,
		Issuer:      config.Issuer,
		Subject:     config.Subject,
		Scopes:      append([]string(nil), config.Scopes...),
		IssuedAt:    now,
		ExpiresAt:   config.ExpiresAt,
		NonExpiring: config.NonExpiring,
	}
	if err := credential.Validate(); err != nil {
		return Credential{}, err
	}
	return credential, nil
}
