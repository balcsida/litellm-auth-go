package litellmauth

import (
	"context"
	"errors"
	"fmt"
)

var (
	ErrUnsupportedProxy = errors.New("proxy does not support LiteLLM CLI SSO")
	ErrProtocol         = errors.New("invalid LiteLLM CLI SSO response")
	ErrLoginExpired     = errors.New("LiteLLM CLI login session expired")
	ErrTeamRequired     = errors.New("team selection required")
	ErrNoCredential     = errors.New("no stored LiteLLM credential")
	ErrCredentialStale  = errors.New("stored LiteLLM credential is expired")
	ErrOriginMismatch   = errors.New("stored credential belongs to a different LiteLLM proxy")
)

type HTTPError struct {
	Op         string
	StatusCode int
	Detail     string
	Retryable  bool
}

func (e HTTPError) Error() string {
	return fmt.Sprintf("LiteLLM CLI SSO %s: HTTP %d", e.Op, e.StatusCode)
}

func (e HTTPError) GoString() string { return e.Error() }

func (e HTTPError) Is(target error) bool {
	want, ok := target.(HTTPError)
	if !ok {
		if pointer, ok := target.(*HTTPError); ok && pointer != nil {
			want = *pointer
		} else {
			return false
		}
	}
	return e.Op == want.Op && e.StatusCode == want.StatusCode && e.Retryable == want.Retryable
}

type TeamRequiredError struct {
	Teams []Team
}

func (e TeamRequiredError) Error() string { return ErrTeamRequired.Error() }

func (e TeamRequiredError) Unwrap() error { return ErrTeamRequired }

type LoginTimeoutError struct{}

func (LoginTimeoutError) Error() string { return "LiteLLM CLI login timed out" }

func (LoginTimeoutError) Unwrap() []error {
	return []error{context.DeadlineExceeded, ErrLoginExpired}
}
