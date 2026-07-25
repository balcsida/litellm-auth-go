package litellmauth

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestAuthenticatorAppliesDualCredentials(t *testing.T) {
	gateway, err := NewStaticSource("sk-gateway", SourceConfig{NonExpiring: true})
	if err != nil {
		t.Fatal(err)
	}
	user, err := NewStaticSource("user-jwt", SourceConfig{NonExpiring: true})
	if err != nil {
		t.Fatal(err)
	}
	gatewayBinder, _ := NewBearerHeader("x-litellm-api-key")
	userBinder, _ := NewBearerHeader("Authorization")

	authenticator, err := NewAuthenticator(
		Binding{Source: gateway, Binder: gatewayBinder},
		Binding{Source: user, Binder: userBinder},
	)
	if err != nil {
		t.Fatal(err)
	}

	request, _ := http.NewRequest(http.MethodGet, "https://proxy.example.com", nil)
	if err := authenticator.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if got := request.Header.Get("x-litellm-api-key"); got != "Bearer sk-gateway" {
		t.Fatalf("gateway header = %q", got)
	}
	if got := request.Header.Get("Authorization"); got != "Bearer user-jwt" {
		t.Fatalf("user header = %q", got)
	}
}

func TestAuthenticatorAcquiresAllCredentialsBeforeBindingInOrder(t *testing.T) {
	var events []string
	source := func(name string) Source {
		return SourceFunc(func(context.Context) (Credential, error) {
			events = append(events, "source "+name)
			return Credential{
				Key:         "sk-" + name,
				AuthMethod:  AuthMethodStatic,
				NonExpiring: true,
			}, nil
		})
	}
	binder := func(name string) Binder {
		return BinderFunc(func(*http.Request, Credential) error {
			events = append(events, "binder "+name)
			return nil
		})
	}
	authenticator, err := NewAuthenticator(
		Binding{Source: source("first"), Binder: binder("first")},
		Binding{Source: source("second"), Binder: binder("second")},
	)
	if err != nil {
		t.Fatal(err)
	}

	request, _ := http.NewRequest(http.MethodGet, "https://proxy.example.com", nil)
	if err := authenticator.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	want := []string{"source first", "source second", "binder first", "binder second"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %q, want %q", events, want)
	}
}

func TestAuthenticatorDoesNotPartiallyMutateRequest(t *testing.T) {
	first, _ := NewStaticSource("sk-first", SourceConfig{NonExpiring: true})
	firstBinder, _ := NewBearerHeader("Authorization")
	sourceFailure := errors.New("source failed with sk-secret")
	second := SourceFunc(func(context.Context) (Credential, error) {
		return Credential{}, sourceFailure
	})
	secondBinder, _ := NewBearerHeader("x-litellm-api-key")

	authenticator, err := NewAuthenticator(
		Binding{Source: first, Binder: firstBinder},
		Binding{Source: second, Binder: secondBinder},
	)
	if err != nil {
		t.Fatal(err)
	}

	request, _ := http.NewRequest(http.MethodGet, "https://proxy.example.com", nil)
	request.Header.Set("X-Existing", "keep")
	err = authenticator.Apply(context.Background(), request)
	if err == nil || !errors.Is(err, sourceFailure) ||
		strings.Contains(err.Error(), "sk-secret") {
		t.Fatalf("Apply() error = %v", err)
	}
	if request.Header.Get("Authorization") != "" ||
		request.Header.Get("X-Existing") != "keep" {
		t.Fatalf("request mutated on failure: %#v", request.Header)
	}
}

func TestAuthenticatorDoesNotMutateRequestOnBinderFailure(t *testing.T) {
	source, _ := NewStaticSource("sk-key", SourceConfig{NonExpiring: true})
	firstBinder, _ := NewBearerHeader("Authorization")
	binderFailure := errors.New("binder failed with sk-secret")
	authenticator, err := NewAuthenticator(
		Binding{Source: source, Binder: firstBinder},
		Binding{Source: source, Binder: BinderFunc(func(*http.Request, Credential) error {
			return binderFailure
		})},
	)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://proxy.example.com", nil)
	request.Header.Set("X-Existing", "keep")

	err = authenticator.Apply(context.Background(), request)
	if err == nil || !errors.Is(err, binderFailure) ||
		strings.Contains(err.Error(), "sk-secret") {
		t.Fatalf("Apply() error = %v", err)
	}
	if request.Header.Get("Authorization") != "" ||
		request.Header.Get("X-Existing") != "keep" {
		t.Fatalf("request mutated on failure: %#v", request.Header)
	}
}

func TestAuthenticatorRejectsCredentialWithoutAuthMethod(t *testing.T) {
	source := SourceFunc(func(context.Context) (Credential, error) {
		return Credential{Key: "sk-secret", NonExpiring: true}, nil
	})
	binder, _ := NewBearerHeader("Authorization")
	authenticator, err := NewAuthenticator(Binding{Source: source, Binder: binder})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://proxy.example.com", nil)

	err = authenticator.Apply(context.Background(), request)
	if !errors.Is(err, ErrInvalidCredential) ||
		strings.Contains(err.Error(), "sk-secret") {
		t.Fatalf("Apply() error = %v", err)
	}
	if request.Header.Get("Authorization") != "" {
		t.Fatalf("request mutated on failure: %#v", request.Header)
	}
}

func TestAuthenticatorTransportClonesRequest(t *testing.T) {
	source, _ := NewStaticSource("sk-key", SourceConfig{NonExpiring: true})
	binder, _ := NewBearerHeader("Authorization")
	authenticator, _ := NewAuthenticator(Binding{Source: source, Binder: binder})

	original, _ := http.NewRequest(http.MethodGet, "https://proxy.example.com", nil)
	original.Header["X-Existing"] = []string{"keep"}
	base := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request == original {
			t.Fatal("transport reused original request")
		}
		if request.Header.Get("Authorization") != "Bearer sk-key" {
			t.Fatalf("Authorization = %q", request.Header.Get("Authorization"))
		}
		request.Header["X-Existing"][0] = "changed"
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       http.NoBody,
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})

	response, err := authenticator.Transport(base).RoundTrip(original)
	if err != nil || response.StatusCode != http.StatusNoContent {
		t.Fatalf("RoundTrip() = %#v, %v", response, err)
	}
	if original.Header.Get("Authorization") != "" ||
		original.Header.Get("X-Existing") != "keep" {
		t.Fatalf("original request mutated: %#v", original.Header)
	}
}

func TestAuthenticatorTransportUsesDefaultTransport(t *testing.T) {
	source, _ := NewStaticSource("sk-key", SourceConfig{NonExpiring: true})
	binder, _ := NewBearerHeader("Authorization")
	authenticator, _ := NewAuthenticator(Binding{Source: source, Binder: binder})

	transport, ok := authenticator.Transport(nil).(*authTransport)
	if !ok || transport.base != http.DefaultTransport {
		t.Fatalf("Transport(nil) = %#v", transport)
	}
}

func TestAuthenticatorHandlesNilHeaderMap(t *testing.T) {
	source, _ := NewStaticSource("sk-key", SourceConfig{NonExpiring: true})
	binder, _ := NewBearerHeader("Authorization")
	authenticator, _ := NewAuthenticator(Binding{Source: source, Binder: binder})

	request, _ := http.NewRequest(http.MethodGet, "https://proxy.example.com", nil)
	request.Header = nil
	if request.Header != nil {
		t.Fatal("test request unexpectedly has headers")
	}
	if err := authenticator.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if request.Header.Get("Authorization") != "Bearer sk-key" {
		t.Fatalf("Authorization = %q", request.Header.Get("Authorization"))
	}
}

func TestAuthenticatorWrapsUnsafeBinderErrors(t *testing.T) {
	source, _ := NewStaticSource("sk-key", SourceConfig{NonExpiring: true})
	binderFailure := errors.New("binder failed with sk-secret")
	binder := BinderFunc(func(*http.Request, Credential) error {
		return binderFailure
	})
	authenticator, _ := NewAuthenticator(Binding{Source: source, Binder: binder})
	request, _ := http.NewRequest(http.MethodGet, "https://proxy.example.com", nil)

	err := authenticator.Apply(context.Background(), request)
	if err == nil || !errors.Is(err, binderFailure) ||
		strings.Contains(err.Error(), "sk-secret") {
		t.Fatalf("Apply() error = %v", err)
	}
}

func TestNewAuthenticatorValidatesAndCopiesBindings(t *testing.T) {
	source, _ := NewStaticSource("sk-key", SourceConfig{NonExpiring: true})
	binder, _ := NewBearerHeader("Authorization")
	if _, err := NewAuthenticator(); err == nil {
		t.Fatal("NewAuthenticator() error = nil")
	}
	if _, err := NewAuthenticator(Binding{Binder: binder}); err == nil {
		t.Fatal("NewAuthenticator() accepted nil source")
	}
	if _, err := NewAuthenticator(Binding{Source: source}); err == nil {
		t.Fatal("NewAuthenticator() accepted nil binder")
	}

	bindings := []Binding{{Source: source, Binder: binder}}
	authenticator, err := NewAuthenticator(bindings...)
	if err != nil {
		t.Fatal(err)
	}
	bindings[0] = Binding{}
	request, _ := http.NewRequest(http.MethodGet, "https://proxy.example.com", nil)
	if err := authenticator.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
}
