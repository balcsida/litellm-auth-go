package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	litellmauth "github.com/balcsida/litellm-auth-go"
)

func TestImportTokenRequiresExplicitBaseURLAndOneSource(t *testing.T) {
	store := new(fakeStore)
	deps, stdout, stderr := testDependencies(store)

	for _, args := range [][]string{
		{"import-token", "--from-env", "LITELLM_API_KEY", "--non-expiring"},
		{"--base-url", "https://proxy.example.com", "import-token", "--non-expiring"},
		{"--base-url", "https://proxy.example.com", "import-token", "--from-env", "A", "--from-file", "token", "--non-expiring"},
		{"--base-url", "https://proxy.example.com", "import-token", "--from-stdin", "--ttl", "0s"},
		{"--base-url", "https://proxy.example.com", "import-token", "--from-stdin", "--non-expiring", "--exec-arg", "unused"},
		{"--base-url", "https://proxy.example.com", "import-token", "--from-env", "BAD-NAME", "--non-expiring"},
	} {
		stdout.Reset()
		stderr.Reset()
		if err := execute(context.Background(), args, deps); err == nil {
			t.Fatalf("execute(%v) error = nil", args)
		}
		if stdout.Len() != 0 {
			t.Fatalf("execute(%v) stdout = %q", args, stdout)
		}
	}
}

func TestImportTokenFromEnvironmentStoresOriginBoundCredential(t *testing.T) {
	store := new(fakeStore)
	deps, stdout, stderr := testDependencies(store)
	deps.getenv = func(name string) string {
		switch name {
		case "LITELLM_API_KEY":
			return "sk-imported"
		default:
			return ""
		}
	}

	err := execute(context.Background(), []string{
		"--base-url", "https://proxy.example.com/",
		"import-token",
		"--from-env", "LITELLM_API_KEY",
		"--non-expiring",
	}, deps)
	if err != nil {
		t.Fatalf("execute() error = %v; stderr = %q", err, stderr)
	}
	if store.saved == nil ||
		store.saved.Key != "sk-imported" ||
		store.saved.BaseURL != "https://proxy.example.com" ||
		store.saved.AuthMethod != litellmauth.AuthMethodEnvironment ||
		!store.saved.NonExpiring {
		t.Fatalf("saved = %#v", store.saved)
	}
	if strings.Contains(stdout.String()+stderr.String(), "sk-imported") {
		t.Fatalf("output leaked token: stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestImportTokenUsesEnvironmentBaseURL(t *testing.T) {
	store := new(fakeStore)
	deps, _, _ := testDependencies(store)
	deps.getenv = func(name string) string {
		switch name {
		case "LITELLM_PROXY_URL":
			return "https://proxy.example.com/"
		case "LITELLM_API_KEY":
			return "sk-imported"
		default:
			return ""
		}
	}

	if err := execute(context.Background(), []string{
		"import-token", "--from-env", "LITELLM_API_KEY", "--non-expiring",
	}, deps); err != nil {
		t.Fatal(err)
	}
	if store.saved == nil || store.saved.BaseURL != "https://proxy.example.com" {
		t.Fatalf("saved = %#v", store.saved)
	}
}

func TestImportTokenFromFileStoresCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("sk-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := new(fakeStore)
	deps, _, _ := testDependencies(store)

	if err := execute(context.Background(), []string{
		"--base-url", "https://proxy.example.com",
		"import-token", "--from-file", path, "--ttl", "1h",
	}, deps); err != nil {
		t.Fatal(err)
	}
	if store.saved == nil ||
		store.saved.Key != "sk-file" ||
		store.saved.AuthMethod != litellmauth.AuthMethodFile ||
		!store.saved.ExpiresAt.Equal(testNow.Add(time.Hour)) {
		t.Fatalf("saved = %#v", store.saved)
	}
}

func TestImportTokenHTTPPolicy(t *testing.T) {
	for _, test := range []struct {
		name    string
		baseURL string
		allow   bool
		wantErr bool
	}{
		{name: "reject remote HTTP", baseURL: "http://proxy.example.com", wantErr: true},
		{name: "allow remote HTTP explicitly", baseURL: "http://proxy.example.com", allow: true},
		{name: "allow localhost HTTP", baseURL: "http://localhost:4000"},
		{name: "allow loopback HTTP", baseURL: "http://127.0.0.1:4000"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := new(fakeStore)
			deps, stdout, _ := testDependencies(store)
			args := []string{"--base-url", test.baseURL}
			if test.allow {
				args = append(args, "--allow-insecure-http")
			}
			args = append(args, "import-token", "--from-stdin", "--non-expiring")
			deps.stdin = strings.NewReader("sk-imported\n")
			err := execute(context.Background(), args, deps)
			if (err != nil) != test.wantErr {
				t.Fatalf("execute() error = %v", err)
			}
			if test.wantErr && (store.saved != nil || stdout.Len() != 0) {
				t.Fatalf("saved=%#v stdout=%q", store.saved, stdout)
			}
		})
	}
}

func TestImportTokenRejectsInvalidLifetimeOptions(t *testing.T) {
	for _, args := range [][]string{
		{"--expires-at", "not-a-time"},
		{"--expires-at", testNow.Add(time.Hour).Format(time.RFC3339), "--ttl", "1h"},
		{"--ttl", "1h", "--non-expiring"},
		{"--from-exec", os.Args[0], "--non-expiring"},
	} {
		store := new(fakeStore)
		deps, stdout, _ := testDependencies(store)
		deps.stdin = strings.NewReader("sk-imported\n")
		commandArgs := []string{"--base-url", "https://proxy.example.com", "import-token"}
		if args[0] != "--from-exec" {
			commandArgs = append(commandArgs, "--from-stdin")
		}
		commandArgs = append(commandArgs, args...)
		if err := execute(context.Background(), commandArgs, deps); err == nil {
			t.Fatalf("execute(%v) error = nil", commandArgs)
		}
		if store.saved != nil || stdout.Len() != 0 {
			t.Fatalf("execute(%v) saved=%#v stdout=%q", commandArgs, store.saved, stdout)
		}
	}
}

func TestImportTokenFromStdinNeverAcceptsTokenFlag(t *testing.T) {
	store := new(fakeStore)
	deps, _, _ := testDependencies(store)
	deps.stdin = bytes.NewBufferString("sk-stdin\n")

	root := newRoot(deps)
	command, _, err := root.Find([]string{"import-token"})
	if err != nil {
		t.Fatal(err)
	}
	if command.Flags().Lookup("token") != nil {
		t.Fatal("import-token exposes a --token flag")
	}

	if err := execute(context.Background(), []string{
		"--base-url", "https://proxy.example.com",
		"import-token", "--from-stdin", "--ttl", "1h",
	}, deps); err != nil {
		t.Fatal(err)
	}
	if store.saved == nil ||
		store.saved.Key != "sk-stdin" ||
		store.saved.AuthMethod != litellmauth.AuthMethodStdin ||
		!store.saved.ExpiresAt.After(testNow) {
		t.Fatalf("saved = %#v", store.saved)
	}
}

func TestImportTokenRejectsPositionalTokenWithoutLeakingIt(t *testing.T) {
	store := new(fakeStore)
	deps, stdout, stderr := testDependencies(store)
	secret := "sk-positional-secret"

	err := execute(context.Background(), []string{
		"--base-url", "https://proxy.example.com",
		"import-token", secret,
	}, deps)
	if err == nil {
		t.Fatal("execute() error = nil")
	}
	if strings.Contains(err.Error()+stdout.String()+stderr.String(), secret) {
		t.Fatalf("rejection leaked positional token: error=%q stdout=%q stderr=%q", err, stdout, stderr)
	}
}

func TestReadTokenFromStdinRejectsNilInput(t *testing.T) {
	if _, err := readTokenFromStdin(context.Background(), nil); !errors.Is(err, litellmauth.ErrSourceUnavailable) {
		t.Fatalf("readTokenFromStdin() error = %v", err)
	}
}

func TestReadTokenFromStdinReturnsOnCancellation(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := readTokenFromStdin(ctx, reader)
		result <- err
	}()
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("readTokenFromStdin() error = %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("readTokenFromStdin() did not return after cancellation")
	}
	_ = reader.Close()
}

func TestReadTokenFromStdinRejectsOversizedInput(t *testing.T) {
	input := strings.NewReader(strings.Repeat("x", maxStdinTokenBytes+1))
	if _, err := readTokenFromStdin(context.Background(), input); !errors.Is(err, litellmauth.ErrSourceOutput) {
		t.Fatalf("readTokenFromStdin() error = %v", err)
	}
}

func TestImportTokenUnknownLifetimeFailsClosed(t *testing.T) {
	store := new(fakeStore)
	deps, stdout, stderr := testDependencies(store)
	deps.getenv = func(name string) string {
		if name == "LITELLM_API_KEY" {
			return "sk-imported"
		}
		return ""
	}

	err := execute(context.Background(), []string{
		"--base-url", "https://proxy.example.com",
		"import-token", "--from-env", "LITELLM_API_KEY",
	}, deps)
	if !errors.Is(err, litellmauth.ErrCredentialExpiryUnknown) ||
		store.saved != nil || stdout.Len() != 0 {
		t.Fatalf("error=%v saved=%#v stdout=%q stderr=%q", err, store.saved, stdout, stderr)
	}
}

func TestImportTokenRejectsExpiredCredential(t *testing.T) {
	store := new(fakeStore)
	deps, stdout, stderr := testDependencies(store)
	deps.stdin = strings.NewReader("sk-expired\n")

	err := execute(context.Background(), []string{
		"--base-url", "https://proxy.example.com",
		"import-token", "--from-stdin",
		"--expires-at", testNow.Add(-time.Minute).Format(time.RFC3339),
	}, deps)
	if !errors.Is(err, litellmauth.ErrCredentialStale) ||
		store.saved != nil || stdout.Len() != 0 {
		t.Fatalf("error=%v saved=%#v stdout=%q stderr=%q", err, store.saved, stdout, stderr)
	}
}

func TestCLIExecHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_CLI_EXEC_HELPER") != "1" {
		return
	}
	if os.Getenv("CLI_EXEC_FAIL") == "1" {
		fmt.Fprint(os.Stdout, "sk-helper-stdout")
		fmt.Fprint(os.Stderr, "sk-helper-stderr")
		os.Exit(1)
	}
	fmt.Fprint(os.Stdout, `{"token":"sk-exec-import","non_expiring":true}`)
	os.Exit(0)
}

func TestImportTokenFromExecStoresCredential(t *testing.T) {
	t.Setenv("GO_WANT_CLI_EXEC_HELPER", "1")
	store := new(fakeStore)
	deps, stdout, stderr := testDependencies(store)

	err := execute(context.Background(), []string{
		"--base-url", "https://proxy.example.com",
		"import-token",
		"--from-exec", os.Args[0],
		"--exec-arg=-test.run=TestCLIExecHelperProcess",
		"--exec-env", "GO_WANT_CLI_EXEC_HELPER",
		"--exec-env", "PATH",
		"--exec-env", "SYSTEMROOT",
		"--exec-env", "WINDIR",
		"--exec-env", "TEMP",
		"--exec-env", "TMP",
	}, deps)
	if err != nil {
		t.Fatalf("execute() error = %v; stderr = %q", err, stderr)
	}
	if store.saved == nil ||
		store.saved.Key != "sk-exec-import" ||
		store.saved.AuthMethod != litellmauth.AuthMethodExec ||
		!store.saved.NonExpiring {
		t.Fatalf("saved = %#v", store.saved)
	}
	if strings.Contains(stdout.String()+stderr.String(), "sk-exec-import") {
		t.Fatalf("output leaked token: stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestImportTokenExecFailureDoesNotLeakHelperData(t *testing.T) {
	t.Setenv("GO_WANT_CLI_EXEC_HELPER", "1")
	t.Setenv("CLI_EXEC_FAIL", "1")
	store := new(fakeStore)
	deps, stdout, stderr := testDependencies(store)
	secretArg := "sk-secret-argument"

	err := execute(context.Background(), []string{
		"--base-url", "https://proxy.example.com",
		"import-token",
		"--from-exec", os.Args[0],
		"--exec-arg=-test.run=TestCLIExecHelperProcess",
		"--exec-arg", secretArg,
		"--exec-env", "GO_WANT_CLI_EXEC_HELPER",
		"--exec-env", "CLI_EXEC_FAIL",
		"--exec-env", "PATH",
	}, deps)
	if !errors.Is(err, litellmauth.ErrSourceOutput) || store.saved != nil || stdout.Len() != 0 {
		t.Fatalf("error=%v saved=%#v stdout=%q", err, store.saved, stdout)
	}
	output := stdout.String() + stderr.String()
	for _, secret := range []string{secretArg, "sk-helper-stdout", "sk-helper-stderr"} {
		if strings.Contains(output, secret) {
			t.Fatalf("output leaked %q: %q", secret, output)
		}
	}
}

func TestImportedTokenUsesExistingPrintTokenContract(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")
	var importStdout, importStderr bytes.Buffer
	if err := Execute(context.Background(), []string{
		"--base-url", "https://proxy.example.com",
		"--token-file", path,
		"import-token", "--from-stdin", "--non-expiring",
	}, strings.NewReader("sk-imported\n"), &importStdout, &importStderr); err != nil {
		t.Fatalf("import-token error = %v, stderr = %q", err, importStderr.String())
	}
	if strings.Contains(importStdout.String()+importStderr.String(), "sk-imported") {
		t.Fatalf("import output leaked token: stdout=%q stderr=%q", importStdout.String(), importStderr.String())
	}

	var stdout, stderr bytes.Buffer
	if err := Execute(context.Background(), []string{
		"--base-url", "https://proxy.example.com",
		"--token-file", path,
		"print-token",
	}, strings.NewReader(""), &stdout, &stderr); err != nil {
		t.Fatalf("print-token error = %v, stderr = %q", err, stderr.String())
	}
	if stdout.String() != "sk-imported\n" || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
