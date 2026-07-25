package litellmauth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestEnvSourceReadsEachCallWithoutLeakingValue(t *testing.T) {
	source, err := NewEnvSource("LITELLM_API_KEY", SourceConfig{NonExpiring: true})
	if err != nil {
		t.Fatal(err)
	}
	value := "sk-first"
	source.lookupEnv = func(string) (string, bool) { return value, true }

	first, err := source.Credential(context.Background())
	if err != nil || first.Key != "sk-first" {
		t.Fatalf("first = %#v, %v", first, err)
	}

	value = "sk-second"
	second, err := source.Credential(context.Background())
	if err != nil || second.Key != "sk-second" {
		t.Fatalf("second = %#v, %v", second, err)
	}
	if second.AuthMethod != AuthMethodEnvironment {
		t.Fatalf("method = %q", second.AuthMethod)
	}
	for _, rendered := range []string{source.String(), source.GoString()} {
		if strings.Contains(rendered, value) {
			t.Fatalf("source formatting leaked value: %q", rendered)
		}
	}
}

func TestEnvSourceRejectsMissingEmptyAndInvalidName(t *testing.T) {
	if _, err := NewEnvSource("BAD-NAME", SourceConfig{NonExpiring: true}); err == nil {
		t.Fatal("NewEnvSource() accepted invalid name")
	}

	source, err := NewEnvSource("LITELLM_API_KEY", SourceConfig{NonExpiring: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range []struct {
		value string
		ok    bool
	}{
		{"", false},
		{"", true},
	} {
		source.lookupEnv = func(string) (string, bool) { return result.value, result.ok }
		if _, err := source.Credential(context.Background()); !errors.Is(err, ErrSourceUnavailable) {
			t.Fatalf("Credential() error = %v", err)
		}
	}
}

func TestEnvSourceRejectsWhitespaceTokenWithoutEcho(t *testing.T) {
	source, err := NewEnvSource("LITELLM_API_KEY", SourceConfig{NonExpiring: true})
	if err != nil {
		t.Fatal(err)
	}
	source.lookupEnv = func(string) (string, bool) { return "secret token", true }
	_, err = source.Credential(context.Background())
	if !errors.Is(err, ErrInvalidCredential) || strings.Contains(err.Error(), "secret token") {
		t.Fatalf("Credential() error = %v", err)
	}
}

func TestEnvSourceHonorsCanceledContext(t *testing.T) {
	source, err := NewEnvSource("LITELLM_API_KEY", SourceConfig{NonExpiring: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Credential(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Credential() error = %v", err)
	}
}
