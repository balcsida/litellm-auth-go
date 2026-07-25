package litellmauth

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Binding pairs one credential source with one request binder.
type Binding struct {
	Source Source
	Binder Binder
}

// String returns a secret-free description.
func (Binding) String() string { return "authentication binding" }

// GoString returns a secret-free description.
func (b Binding) GoString() string { return b.String() }

// Authenticator applies one or more independent credentials.
type Authenticator struct {
	bindings []Binding
	now      func() time.Time
}

// NewAuthenticator validates and copies bindings.
func NewAuthenticator(bindings ...Binding) (*Authenticator, error) {
	if len(bindings) == 0 {
		return nil, errors.New("at least one authentication binding is required")
	}
	copied := make([]Binding, len(bindings))
	for index, binding := range bindings {
		if binding.Source == nil || binding.Binder == nil {
			return nil, errors.New("authentication binding must include source and binder")
		}
		copied[index] = binding
	}
	return &Authenticator{bindings: copied, now: time.Now}, nil
}

// Apply acquires every credential before atomically replacing request headers.
func (a *Authenticator) Apply(ctx context.Context, request *http.Request) error {
	if a == nil || request == nil || a.now == nil {
		return errors.New("invalid authenticator")
	}
	credentials := make([]Credential, len(a.bindings))
	for index, binding := range a.bindings {
		credential, err := binding.Source.Credential(ctx)
		if err != nil {
			return authenticationStageError{stage: "source", err: err}
		}
		if credential.AuthMethod == "" {
			return ErrInvalidCredential
		}
		if err := credential.Validate(); err != nil {
			return err
		}
		if !credential.Fresh(a.now()) {
			return ErrCredentialStale
		}
		credentials[index] = credential
	}

	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	if clone.Header == nil {
		clone.Header = make(http.Header)
	}
	for index, binding := range a.bindings {
		if err := binding.Binder.Bind(clone, credentials[index]); err != nil {
			return authenticationStageError{stage: "binder", err: err}
		}
	}
	request.Header = clone.Header
	return nil
}

type authenticationStageError struct {
	stage string
	err   error
}

func (e authenticationStageError) Error() string {
	return "authentication " + e.stage + " failed"
}

func (e authenticationStageError) GoString() string { return e.Error() }

func (e authenticationStageError) Unwrap() error { return e.err }

// Transport returns a RoundTripper that clones and authenticates each request.
func (a *Authenticator) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &authTransport{authenticator: a, base: base}
}

type authTransport struct {
	authenticator *Authenticator
	base          http.RoundTripper
}

func (t *authTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t == nil || t.authenticator == nil || t.base == nil || request == nil {
		return nil, errors.New("invalid authentication transport")
	}
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	if clone.Header == nil {
		clone.Header = make(http.Header)
	}
	if err := t.authenticator.Apply(request.Context(), clone); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(clone)
}
