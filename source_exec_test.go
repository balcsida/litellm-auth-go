package litellmauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestExecSourceHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_EXEC_SOURCE_HELPER") != "1" {
		return
	}
	switch os.Getenv("EXEC_SOURCE_MODE") {
	case "success":
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"token":        "sk-exec",
			"token_type":   "Bearer",
			"non_expiring": true,
			"issuer":       "https://issuer.example.com",
			"subject":      "subject-1",
			"scopes":       []string{"litellm.invoke"},
		})
		os.Exit(0)
	case "trailing":
		fmt.Fprint(os.Stdout, `{"token":"sk-exec","non_expiring":true} {}`)
		os.Exit(0)
	case "secret-error":
		fmt.Fprint(os.Stdout, `{"token":"secret token","non_expiring":true}`)
		fmt.Fprint(os.Stderr, "stderr-secret")
		os.Exit(0)
	case "oversized":
		fmt.Fprint(os.Stdout, strings.Repeat("x", defaultExecMaxOutputBytes+1))
		os.Exit(0)
	case "sleep":
		time.Sleep(time.Second)
		os.Exit(0)
	case "inherited-stdout":
		if err := os.Setenv("EXEC_SOURCE_MODE", "descendant"); err != nil {
			os.Exit(2)
		}
		child := exec.Command(os.Args[0], "-test.run=TestExecSourceHelperProcess")
		child.Stdout = os.Stdout
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	case "descendant":
		time.Sleep(time.Second)
		os.Exit(0)
	default:
		os.Exit(2)
	}
}

func helperExecSource(t *testing.T, mode string) *ExecSource {
	t.Helper()
	source, err := NewExecSource(os.Args[0], []string{"-test.run=TestExecSourceHelperProcess"}, ExecSourceConfig{
		BaseURL: "https://proxy.example.com",
		Timeout: 2 * time.Second,
		AllowedEnv: []string{
			"GO_WANT_EXEC_SOURCE_HELPER",
			"EXEC_SOURCE_MODE",
			"PATH",
			"SYSTEMROOT",
			"WINDIR",
			"TEMP",
			"TMP",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	systemLookup := os.LookupEnv
	source.lookupEnv = func(name string) (string, bool) {
		switch name {
		case "GO_WANT_EXEC_SOURCE_HELPER":
			return "1", true
		case "EXEC_SOURCE_MODE":
			return mode, true
		default:
			return systemLookup(name)
		}
	}
	return source
}

func TestExecSourceParsesSafeJSONCredential(t *testing.T) {
	source := helperExecSource(t, "success")
	credential, err := source.Credential(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if credential.Key != "sk-exec" ||
		credential.AuthMethod != AuthMethodExec ||
		credential.TokenType != "Bearer" ||
		!credential.NonExpiring ||
		credential.Issuer != "https://issuer.example.com" ||
		credential.Subject != "subject-1" ||
		len(credential.Scopes) != 1 {
		t.Fatalf("credential = %#v", credential)
	}
}

func TestExecSourceRejectsUnsafeOutputWithoutLeakingIt(t *testing.T) {
	for _, mode := range []string{"trailing", "secret-error", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			source := helperExecSource(t, mode)
			_, err := source.Credential(context.Background())
			if err == nil {
				t.Fatal("Credential() error = nil")
			}
			for _, forbidden := range []string{"sk-exec", "secret token", "stderr-secret"} {
				if strings.Contains(err.Error(), forbidden) {
					t.Fatalf("error leaked %q: %v", forbidden, err)
				}
			}
		})
	}
}

func TestExecSourceTimeout(t *testing.T) {
	source := helperExecSource(t, "sleep")
	source.timeout = 10 * time.Millisecond
	_, err := source.Credential(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Credential() error = %v", err)
	}
}

func TestExecSourceBoundsInheritedStdoutWait(t *testing.T) {
	source := helperExecSource(t, "inherited-stdout")
	source.timeout = 10 * time.Millisecond
	start := time.Now()
	_, err := source.Credential(context.Background())
	if !errors.Is(err, ErrSourceOutput) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Credential() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Credential() took %s", elapsed)
	}
}

func TestExecSourceRejectsInvalidEnvironmentName(t *testing.T) {
	_, err := NewExecSource(os.Args[0], nil, ExecSourceConfig{
		AllowedEnv: []string{"BAD=VALUE"},
	})
	if err == nil {
		t.Fatal("NewExecSource() accepted invalid environment name")
	}
}
