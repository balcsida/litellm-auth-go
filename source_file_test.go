package litellmauth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTokenFileSourceReloadsRotatedToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("sk-first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := NewTokenFileSource(path, SourceConfig{NonExpiring: true})
	if err != nil {
		t.Fatal(err)
	}

	first, err := source.Credential(context.Background())
	if err != nil || first.Key != "sk-first" {
		t.Fatalf("first = %#v, %v", first, err)
	}

	if err := os.WriteFile(path, []byte("sk-second\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := source.Credential(context.Background())
	if err != nil || second.Key != "sk-second" ||
		second.AuthMethod != AuthMethodFile {
		t.Fatalf("second = %#v, %v", second, err)
	}
}

func TestTokenFileSourceRejectsMissingOversizedAndWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	source, err := NewTokenFileSource(path, SourceConfig{NonExpiring: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Credential(context.Background()); !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("missing error = %v", err)
	}

	if err := os.WriteFile(path, []byte("secret token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Credential(context.Background()); !errors.Is(err, ErrInvalidCredential) ||
		strings.Contains(err.Error(), "secret token") {
		t.Fatalf("whitespace error = %v", err)
	}

	if err := os.WriteFile(path, make([]byte, maxSourceTokenBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Credential(context.Background()); !errors.Is(err, ErrSourceOutput) {
		t.Fatalf("oversized error = %v", err)
	}
}

func TestTokenFileSourceRejectsBareCarriageReturn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("secret-token\r"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := NewTokenFileSource(path, SourceConfig{NonExpiring: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Credential(context.Background()); !errors.Is(err, ErrInvalidCredential) ||
		strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), path) {
		t.Fatalf("bare CR error = %v", err)
	}
}

func TestTokenFileSourceHonorsCanceledContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("sk-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := NewTokenFileSource(path, SourceConfig{NonExpiring: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Credential(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Credential() error = %v", err)
	}
}
