package litellmauth

import (
	"context"
	"errors"
	"os"
	"regexp"
	"time"
)

var environmentNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// EnvSource reads a token from one environment variable on every call.
type EnvSource struct {
	name      string
	config    SourceConfig
	lookupEnv func(string) (string, bool)
	now       func() time.Time
}

// NewEnvSource creates an environment credential source.
func NewEnvSource(name string, config SourceConfig) (*EnvSource, error) {
	if !environmentNamePattern.MatchString(name) {
		return nil, errors.New("invalid credential environment variable name")
	}
	if config.AuthMethod == "" {
		config.AuthMethod = AuthMethodEnvironment
	}
	return &EnvSource{
		name:      name,
		config:    config,
		lookupEnv: os.LookupEnv,
		now:       time.Now,
	}, nil
}

// Credential reads and validates the current environment value.
func (s *EnvSource) Credential(ctx context.Context) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	if s == nil || s.lookupEnv == nil || s.now == nil {
		return Credential{}, ErrSourceUnavailable
	}
	key, ok := s.lookupEnv(s.name)
	if !ok || key == "" {
		return Credential{}, ErrSourceUnavailable
	}
	return credentialFromSource(key, AuthMethodEnvironment, s.config, s.now())
}

// String returns a secret-free description.
func (s *EnvSource) String() string {
	if s == nil {
		return "environment authentication source"
	}
	return "environment authentication source " + s.name
}

// GoString returns a secret-free description.
func (s *EnvSource) GoString() string { return s.String() }
