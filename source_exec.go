package litellmauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	defaultExecTimeout        = 10 * time.Second
	defaultExecMaxOutputBytes = 64 << 10
)

// ExecSourceConfig configures an external credential helper.
type ExecSourceConfig struct {
	BaseURL        string
	Timeout        time.Duration
	MaxOutputBytes int
	AllowedEnv     []string
}

// ExecSource executes one helper without a shell.
type ExecSource struct {
	path           string
	args           []string
	baseURL        string
	timeout        time.Duration
	maxOutputBytes int
	allowedEnv     []string
	lookupEnv      func(string) (string, bool)
	now            func() time.Time
}

type execCredentialOutput struct {
	Token       string   `json:"token"`
	TokenType   string   `json:"token_type"`
	ExpiresAt   string   `json:"expires_at"`
	NonExpiring bool     `json:"non_expiring"`
	Issuer      string   `json:"issuer"`
	Subject     string   `json:"subject"`
	Scopes      []string `json:"scopes"`
}

// NewExecSource creates an external-command source.
func NewExecSource(path string, args []string, config ExecSourceConfig) (*ExecSource, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("credential helper path is required")
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultExecTimeout
	}
	if timeout < 0 {
		return nil, errors.New("credential helper timeout must be positive")
	}
	maxOutput := config.MaxOutputBytes
	if maxOutput == 0 {
		maxOutput = defaultExecMaxOutputBytes
	}
	if maxOutput < 1 {
		return nil, errors.New("credential helper output limit must be positive")
	}
	allowedEnv := make([]string, 0, len(config.AllowedEnv))
	seenEnv := make(map[string]struct{}, len(config.AllowedEnv))
	for _, name := range config.AllowedEnv {
		if !environmentNamePattern.MatchString(name) {
			return nil, errors.New("invalid credential helper environment variable name")
		}
		if _, exists := seenEnv[name]; exists {
			continue
		}
		seenEnv[name] = struct{}{}
		allowedEnv = append(allowedEnv, name)
	}
	return &ExecSource{
		path:           path,
		args:           append([]string(nil), args...),
		baseURL:        config.BaseURL,
		timeout:        timeout,
		maxOutputBytes: maxOutput,
		allowedEnv:     allowedEnv,
		lookupEnv:      os.LookupEnv,
		now:            time.Now,
	}, nil
}

// Credential executes and parses the helper.
func (s *ExecSource) Credential(ctx context.Context) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	if s == nil || s.lookupEnv == nil || s.now == nil {
		return Credential{}, ErrSourceUnavailable
	}

	runCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	command := exec.CommandContext(runCtx, s.path, s.args...)
	command.Env = s.environment()
	command.Stderr = io.Discard
	command.WaitDelay = s.timeout

	var output limitedBuffer
	output.limit = s.maxOutputBytes
	command.Stdout = &output

	if err := command.Run(); err != nil {
		if errors.Is(err, exec.ErrWaitDelay) {
			return Credential{}, ErrSourceOutput
		}
		if runCtx.Err() != nil {
			return Credential{}, runCtx.Err()
		}
		return Credential{}, ErrSourceOutput
	}
	if output.overflow {
		return Credential{}, ErrSourceOutput
	}

	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	decoder.DisallowUnknownFields()
	var decoded execCredentialOutput
	if err := decoder.Decode(&decoded); err != nil {
		return Credential{}, ErrSourceOutput
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Credential{}, ErrSourceOutput
	}

	var expiresAt time.Time
	if decoded.ExpiresAt != "" {
		parsed, err := time.Parse(time.RFC3339, decoded.ExpiresAt)
		if err != nil {
			return Credential{}, ErrSourceOutput
		}
		expiresAt = parsed
	}
	credential, err := credentialFromSource(decoded.Token, AuthMethodExec, SourceConfig{
		BaseURL:     s.baseURL,
		AuthMethod:  AuthMethodExec,
		TokenType:   decoded.TokenType,
		ExpiresAt:   expiresAt,
		NonExpiring: decoded.NonExpiring,
		Issuer:      decoded.Issuer,
		Subject:     decoded.Subject,
		Scopes:      decoded.Scopes,
	}, s.now())
	if err != nil {
		if errors.Is(err, ErrCredentialExpiryUnknown) ||
			errors.Is(err, ErrInvalidCredential) {
			return Credential{}, ErrSourceOutput
		}
		return Credential{}, err
	}
	return credential, nil
}

func (s *ExecSource) environment() []string {
	env := make([]string, 0, len(s.allowedEnv))
	for _, name := range s.allowedEnv {
		if value, ok := s.lookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return env
}

// String returns a secret-free description.
func (*ExecSource) String() string { return "external credential helper source" }

// GoString returns a secret-free description.
func (s *ExecSource) GoString() string { return s.String() }

type limitedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	if b.overflow {
		return len(data), nil
	}
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		b.overflow = true
		return len(data), nil
	}
	if len(data) > remaining {
		_, _ = b.Buffer.Write(data[:remaining])
		b.overflow = true
		return len(data), nil
	}
	return b.Buffer.Write(data)
}
