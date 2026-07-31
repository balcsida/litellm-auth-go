package litellmauth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxHTTPErrorDetailBytes = 512

var detailSecretPattern = regexp.MustCompile(`[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}|sk-[A-Za-z0-9_-]+`)

var (
	// ErrUnsupportedProxy reports a proxy without the LiteLLM CLI SSO endpoints.
	ErrUnsupportedProxy = errors.New("proxy does not support LiteLLM CLI SSO")
	// ErrProtocol reports an invalid LiteLLM CLI SSO response.
	ErrProtocol = errors.New("invalid LiteLLM CLI SSO response")
	// ErrLoginExpired reports an expired LiteLLM CLI SSO session.
	ErrLoginExpired = errors.New("LiteLLM CLI login session expired")
	// ErrTeamRequired reports that a team must be selected to finish login.
	ErrTeamRequired = errors.New("team selection required")
	// ErrNoCredential reports that no stored credential exists.
	ErrNoCredential = errors.New("no stored LiteLLM credential")
	// ErrCredentialStale reports that a stored credential is expired.
	ErrCredentialStale = errors.New("stored LiteLLM credential is expired")
	// ErrLoginRequired reports that the caller must authenticate again.
	ErrLoginRequired = errors.New("LiteLLM login required")
	// ErrOriginMismatch reports a credential issued by a different proxy URL.
	ErrOriginMismatch = errors.New("stored credential belongs to a different LiteLLM proxy")
	// ErrInvalidCredential reports a malformed or contradictory credential.
	ErrInvalidCredential = errors.New("invalid authentication credential")
	// ErrCredentialExpiryUnknown reports a credential without a known or explicitly unlimited lifetime.
	ErrCredentialExpiryUnknown = errors.New("authentication credential expiry is unknown")
	// ErrSourceUnavailable reports a configured source that did not produce a credential.
	ErrSourceUnavailable = errors.New("authentication source did not produce a credential")
	// ErrSourceOutput reports invalid external source output.
	ErrSourceOutput = errors.New("invalid authentication source output")
)

func nativeOIDCProtocolError() error { return fmt.Errorf("%w: native OIDC discovery", ErrProtocol) }

// HTTPError describes a non-successful LiteLLM CLI SSO response.
type HTTPError struct {
	// Op is the SSO operation that returned the response.
	Op string
	// StatusCode is the HTTP status code.
	StatusCode int
	// Detail is safe response detail when supplied by the proxy.
	Detail string
	// Retryable reports whether the request can be retried.
	Retryable bool

	loginExpired bool
	retryAfter   string
}

// Error returns a safe summary of the HTTP error.
func (e HTTPError) Error() string {
	return fmt.Sprintf("LiteLLM CLI SSO %s: HTTP %d", e.Op, e.StatusCode)
}

// GoString returns a safe summary of the HTTP error.
func (e HTTPError) GoString() string { return e.Error() }

// SafeDetail returns explicitly recognized, safe proxy guidance.
func (e HTTPError) SafeDetail() string {
	switch detail := safeHTTPErrorDetail(e.Detail); detail {
	case "configure shared cache",
		"configure a shared cache",
		"Invalid CLI login session; use a shared cache for multiple replicas",
		"Invalid CLI login session; configure a shared cache for multiple replicas":
		return detail
	default:
		return ""
	}
}

// Unwrap returns ErrLoginExpired for expired login sessions.
func (e HTTPError) Unwrap() error {
	if e.loginExpired {
		return ErrLoginExpired
	}
	return nil
}

// Is matches HTTP errors by operation, status code, and retryability.
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

func safeHTTPErrorDetail(detail string, secrets ...string) string {
	for _, secret := range secrets {
		if secret != "" {
			detail = strings.ReplaceAll(detail, secret, "[redacted]")
		}
	}
	detail = detailSecretPattern.ReplaceAllString(detail, "[redacted]")
	detail = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, detail)
	if len(detail) <= maxHTTPErrorDetailBytes {
		return detail
	}
	detail = detail[:maxHTTPErrorDetailBytes]
	for !utf8.ValidString(detail) {
		detail = detail[:len(detail)-1]
	}
	return detail
}

// TeamRequiredError contains the teams offered by a login session.
type TeamRequiredError struct {
	// Teams is the proxy-provided set of selectable teams.
	Teams []Team
}

// Error returns ErrTeamRequired's message.
func (e TeamRequiredError) Error() string { return ErrTeamRequired.Error() }

// Unwrap returns ErrTeamRequired.
func (e TeamRequiredError) Unwrap() error { return ErrTeamRequired }

// LoginTimeoutError reports a session timeout.
type LoginTimeoutError struct {
	callerDeadline bool
}

// Error returns the timeout message.
func (LoginTimeoutError) Error() string { return "LiteLLM CLI login timed out" }

// Unwrap returns the applicable timeout and expiry errors.
func (e LoginTimeoutError) Unwrap() []error {
	if e.callerDeadline {
		return []error{context.DeadlineExceeded}
	}
	return []error{context.DeadlineExceeded, ErrLoginExpired}
}
