package litellmauth

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxSourceTokenBytes = 1 << 20

// TokenFileSource reads a rotating token file on every call.
type TokenFileSource struct {
	path   string
	config SourceConfig
	now    func() time.Time
}

// NewTokenFileSource creates a rotating file source.
func NewTokenFileSource(path string, config SourceConfig) (*TokenFileSource, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("credential token file path is required")
	}
	if config.AuthMethod == "" {
		config.AuthMethod = AuthMethodFile
	}
	return &TokenFileSource{
		path:   filepath.Clean(path),
		config: config,
		now:    time.Now,
	}, nil
}

// Credential re-reads and validates the token file.
func (s *TokenFileSource) Credential(ctx context.Context) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	if s == nil || s.now == nil {
		return Credential{}, ErrSourceUnavailable
	}

	file, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return Credential{}, ErrSourceUnavailable
	}
	if err != nil {
		return Credential{}, ErrSourceOutput
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxSourceTokenBytes+1))
	if err != nil {
		return Credential{}, ErrSourceOutput
	}
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	if len(data) > maxSourceTokenBytes {
		return Credential{}, ErrSourceOutput
	}

	key := strings.TrimSuffix(string(data), "\n")
	key = strings.TrimSuffix(key, "\r")
	if key == "" {
		return Credential{}, ErrSourceUnavailable
	}
	return credentialFromSource(key, AuthMethodFile, s.config, s.now())
}

// String returns a secret-free description.
func (*TokenFileSource) String() string { return "rotating token file source" }

// GoString returns a secret-free description.
func (s *TokenFileSource) GoString() string { return s.String() }
