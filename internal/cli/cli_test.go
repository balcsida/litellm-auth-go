package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	litellmauth "github.com/balcsida/litellm-auth-go"
	"github.com/balcsida/litellm-auth-go/tokenstore"
)

var testNow = time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)

type fakeClient struct {
	authenticate func(context.Context, litellmauth.AuthenticateOptions) (litellmauth.Credential, error)
}

func (c fakeClient) Authenticate(ctx context.Context, options litellmauth.AuthenticateOptions) (litellmauth.Credential, error) {
	return c.authenticate(ctx, options)
}

type fakeStore struct {
	credential litellmauth.Credential
	loadErr    error
	saveErr    error
	deleteErr  error
	loadBase   *url.URL
	saved      *litellmauth.Credential
	deletes    int
}

func (s *fakeStore) Load(_ context.Context, base *url.URL) (litellmauth.Credential, error) {
	s.loadBase = base
	return s.credential, s.loadErr
}

func (s *fakeStore) Save(_ context.Context, credential litellmauth.Credential) error {
	s.saved = &credential
	return s.saveErr
}

func (s *fakeStore) Delete(context.Context) error {
	s.deletes++
	return s.deleteErr
}

func testDependencies(store *fakeStore) (dependencies, *bytes.Buffer, *bytes.Buffer) {
	stdout, stderr := new(bytes.Buffer), new(bytes.Buffer)
	return dependencies{
		stdin:      strings.NewReader(""),
		stdout:     stdout,
		stderr:     stderr,
		getenv:     func(string) string { return "" },
		isTerminal: func() bool { return false },
		openBrowser: func(string) error {
			return nil
		},
		now: func() time.Time { return testNow },
		newClient: func(string, time.Duration, bool) (authClient, error) {
			return fakeClient{authenticate: func(_ context.Context, options litellmauth.AuthenticateOptions) (litellmauth.Credential, error) {
				return litellmauth.Credential{
					BaseURL:  "http://localhost:4000",
					Key:      "secret-key",
					UserID:   "user-1",
					IssuedAt: testNow,
				}, nil
			}}, nil
		},
		newStore: func(string) (credentialStore, error) { return store, nil },
	}, stdout, stderr
}

func TestLoginBaseURLPrecedence(t *testing.T) {
	for _, test := range []struct {
		name string
		env  string
		args []string
		want string
	}{
		{name: "default", want: "http://localhost:4000"},
		{name: "environment", env: "https://env.example.com", want: "https://env.example.com"},
		{name: "flag", env: "https://env.example.com", args: []string{"--base-url", "https://flag.example.com"}, want: "https://flag.example.com"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := new(fakeStore)
			deps, _, _ := testDependencies(store)
			deps.getenv = func(name string) string {
				if name == "LITELLM_PROXY_URL" {
					return test.env
				}
				return ""
			}
			var got string
			deps.newClient = func(base string, _ time.Duration, _ bool) (authClient, error) {
				got = base
				return fakeClient{authenticate: func(context.Context, litellmauth.AuthenticateOptions) (litellmauth.Credential, error) {
					return litellmauth.Credential{BaseURL: base, Key: "key", IssuedAt: testNow}, nil
				}}, nil
			}

			if err := execute(context.Background(), append(test.args, "login", "--no-browser"), deps); err != nil {
				t.Fatalf("execute() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("client base URL = %q, want %q", got, test.want)
			}
		})
	}
}

func TestLoginPassesGlobalOptions(t *testing.T) {
	store := new(fakeStore)
	deps, _, _ := testDependencies(store)
	var gotPath string
	var gotTimeout time.Duration
	var gotAllow bool
	deps.newStore = func(path string) (credentialStore, error) {
		gotPath = path
		return store, nil
	}
	deps.newClient = func(_ string, timeout time.Duration, allow bool) (authClient, error) {
		gotTimeout, gotAllow = timeout, allow
		return fakeClient{authenticate: func(context.Context, litellmauth.AuthenticateOptions) (litellmauth.Credential, error) {
			return successfulCredential(), nil
		}}, nil
	}

	err := execute(context.Background(), []string{
		"--token-file", "/tmp/custom-token.json",
		"--timeout", "3s",
		"--allow-insecure-http",
		"login", "--no-browser",
	}, deps)
	if err != nil {
		t.Fatalf("execute() error = %v", err)
	}
	if gotPath != "/tmp/custom-token.json" || gotTimeout != 3*time.Second || !gotAllow {
		t.Fatalf("path=%q timeout=%s allow=%v", gotPath, gotTimeout, gotAllow)
	}
}

func TestLoginPrintsSessionBeforeBrowserAndSavesBeforeSuccess(t *testing.T) {
	store := new(fakeStore)
	deps, stdout, _ := testDependencies(store)
	verificationURL, _ := url.Parse("https://proxy.example.com/verify")
	order := make([]string, 0, 3)
	deps.openBrowser = func(raw string) error {
		if !strings.Contains(stdout.String(), raw) || !strings.Contains(stdout.String(), "CODE-123") {
			t.Fatal("verification instructions were not printed before browser open")
		}
		order = append(order, "browser")
		return nil
	}
	deps.newClient = func(string, time.Duration, bool) (authClient, error) {
		return fakeClient{authenticate: func(ctx context.Context, options litellmauth.AuthenticateOptions) (litellmauth.Credential, error) {
			if err := options.OnSession(ctx, litellmauth.Session{VerificationURL: verificationURL, UserCode: "CODE-123"}); err != nil {
				return litellmauth.Credential{}, err
			}
			order = append(order, "authenticated")
			return litellmauth.Credential{BaseURL: "https://proxy.example.com", Key: "secret-key", UserID: "user-1", IssuedAt: testNow}, nil
		}}, nil
	}
	store.saveErr = errors.New("save failed")

	if err := execute(context.Background(), []string{"login"}, deps); err == nil {
		t.Fatal("execute() error = nil")
	}
	if strings.Contains(stdout.String(), "Authenticated") {
		t.Fatalf("success printed before save: %q", stdout)
	}
	if got := strings.Join(order, ","); got != "browser,authenticated" {
		t.Fatalf("operation order = %q", got)
	}
}

func TestLoginBrowserFailureContinuesManually(t *testing.T) {
	store := new(fakeStore)
	deps, stdout, stderr := testDependencies(store)
	opened := 0
	deps.openBrowser = func(string) error {
		opened++
		return errors.New("browser failed with secret-key")
	}
	deps.newClient = sessionClient("https://proxy.example.com/verify", "CODE-123", successfulCredential())

	if err := execute(context.Background(), []string{"login"}, deps); err != nil {
		t.Fatalf("execute() error = %v", err)
	}
	human := stdout.String() + stderr.String()
	if opened != 1 || !strings.Contains(human, "manually") || strings.Contains(human, "secret-key") {
		t.Fatalf("browser fallback output = %q, opened = %d", human, opened)
	}
}

func TestLoginNoBrowserNeverOpensBrowser(t *testing.T) {
	store := new(fakeStore)
	deps, _, _ := testDependencies(store)
	deps.openBrowser = func(string) error { t.Fatal("browser opened"); return nil }
	deps.newClient = sessionClient("https://proxy.example.com/verify", "CODE-123", successfulCredential())

	if err := execute(context.Background(), []string{"login", "--no-browser"}, deps); err != nil {
		t.Fatalf("execute() error = %v", err)
	}
}

func TestLoginTeamSelectionWithRealClient(t *testing.T) {
	for _, test := range []struct {
		name       string
		args       []string
		input      string
		terminal   bool
		singleTeam bool
		wantTeam   string
		wantErr    error
		wantHint   string
	}{
		{name: "single team automatic", singleTeam: true, wantTeam: "team-1"},
		{name: "interactive selection", input: "2\n", terminal: true, wantTeam: "team-2"},
		{name: "noninteractive requires flag", wantErr: litellmauth.ErrTeamRequired, wantHint: "--team"},
		{name: "explicit team", args: []string{"--team", "team-2"}, wantTeam: "team-2"},
		{name: "invalid explicit team", args: []string{"--team", "missing"}, wantErr: litellmauth.ErrProtocol},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := new(fakeStore)
			deps, stdout, stderr := testDependencies(store)
			deps.stdin = strings.NewReader(test.input)
			deps.isTerminal = func() bool { return test.terminal }
			server := teamServer(t, test.singleTeam)
			defer server.Close()
			deps.newClient = func(string, time.Duration, bool) (authClient, error) {
				return litellmauth.New(server.URL,
					litellmauth.WithHTTPClient(server.Client()),
					litellmauth.WithPollInterval(time.Millisecond),
				)
			}

			args := append([]string{"--base-url", server.URL, "login", "--no-browser"}, test.args...)
			err := execute(context.Background(), args, deps)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("execute() error = %v, want %v", err, test.wantErr)
			}
			if test.wantTeam != "" && (store.saved == nil || store.saved.TeamID != test.wantTeam) {
				t.Fatalf("saved credential = %#v, want team %q", store.saved, test.wantTeam)
			}
			if test.wantHint != "" && !strings.Contains(stderr.String(), test.wantHint) {
				t.Fatalf("stderr = %q, want hint %q", stderr, test.wantHint)
			}
			if human := stdout.String() + stderr.String(); strings.Contains(human, "secret-key") || strings.Contains(human, "poll-secret") {
				t.Fatalf("human output leaked a secret: %q", human)
			}
		})
	}
}

func TestLoginRejectsPollSecretBeforeTeamPrompt(t *testing.T) {
	secret := "poll-secret-abc"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			_, _ = fmt.Fprintf(w, `{"login_id":"login-1","poll_secret":%q,"user_code":"CODE","expires_in":60}`, secret)
			return
		}
		_, _ = fmt.Fprintf(w, `{"status":"ready","requires_team_selection":true,"team_details":[{"team_id":"team-1","team_alias":%q}]}`, "alias-"+secret)
	}))
	defer server.Close()
	store := new(fakeStore)
	deps, stdout, stderr := testDependencies(store)
	deps.stdin = strings.NewReader("1\n")
	deps.isTerminal = func() bool { return true }
	deps.newClient = func(string, time.Duration, bool) (authClient, error) {
		return litellmauth.New(server.URL, litellmauth.WithHTTPClient(server.Client()))
	}

	err := execute(context.Background(), []string{"login", "--no-browser"}, deps)
	human := stdout.String() + stderr.String()
	if !errors.Is(err, litellmauth.ErrProtocol) || strings.Contains(human, secret) || strings.Contains(human, "Select a team") {
		t.Fatalf("execute() error = %v; output = %q", err, human)
	}
}

func TestLoginRejectsCredentialKeyInMetadata(t *testing.T) {
	store := new(fakeStore)
	deps, stdout, stderr := testDependencies(store)
	deps.newClient = func(string, time.Duration, bool) (authClient, error) {
		return fakeClient{authenticate: func(context.Context, litellmauth.AuthenticateOptions) (litellmauth.Credential, error) {
			return litellmauth.Credential{
				BaseURL:  "https://proxy.example.com",
				Key:      "secret-key",
				UserID:   "user-secret-key",
				IssuedAt: testNow,
			}, nil
		}}, nil
	}

	err := execute(context.Background(), []string{"login", "--no-browser"}, deps)
	human := stdout.String() + stderr.String()
	if !errors.Is(err, litellmauth.ErrProtocol) || strings.Contains(human, "secret-key") || store.saved != nil {
		t.Fatalf("execute() error = %v; output = %q; saved = %#v", err, human, store.saved)
	}
}

func TestLoginSanitizesAllHumanOutput(t *testing.T) {
	store := new(fakeStore)
	deps, stdout, stderr := testDependencies(store)
	deps.newClient = sessionClient(
		"https://proxy.example.com/verify",
		"CODE\x1b[31m",
		litellmauth.Credential{
			BaseURL:   "https://proxy.example.com/\x1b[31m",
			Key:       "secret-key",
			UserID:    "user\x1b[31m",
			TeamID:    "team\x1b[31m",
			TeamAlias: "alias\x1b[31m",
			IssuedAt:  testNow,
		},
	)

	if err := execute(context.Background(), []string{"login", "--no-browser"}, deps); err != nil {
		t.Fatalf("execute() error = %v", err)
	}
	human := stdout.String() + stderr.String()
	if strings.Contains(human, "\x1b") || strings.Contains(human, "secret-key") {
		t.Fatalf("unsafe human output = %q", human)
	}
}

func TestLoginVerboseEventsAreSafe(t *testing.T) {
	store := new(fakeStore)
	deps, _, stderr := testDependencies(store)
	deps.newClient = func(string, time.Duration, bool) (authClient, error) {
		return fakeClient{authenticate: func(_ context.Context, options litellmauth.AuthenticateOptions) (litellmauth.Credential, error) {
			options.OnEvent(litellmauth.Event{Kind: litellmauth.EventPending, Attempt: 1})
			options.OnEvent(litellmauth.Event{Kind: litellmauth.EventRetrying, Attempt: 2, StatusCode: 503, Err: errors.New("secret-key\x1b[31m")})
			options.OnEvent(litellmauth.Event{Kind: litellmauth.EventTeamsRequired, Attempt: 3, Teams: []litellmauth.Team{{ID: "secret-key"}}})
			return successfulCredential(), nil
		}}, nil
	}

	if err := execute(context.Background(), []string{"--verbose", "login", "--no-browser"}, deps); err != nil {
		t.Fatalf("execute() error = %v", err)
	}
	if got := stderr.String(); !strings.Contains(got, "attempt 1") || !strings.Contains(got, "503") || strings.Contains(got, "secret-key") || strings.Contains(got, "\x1b") {
		t.Fatalf("verbose stderr = %q", got)
	}
}

func TestLoginCancellationIsQuietAndNonzero(t *testing.T) {
	store := new(fakeStore)
	deps, stdout, stderr := testDependencies(store)
	deps.newClient = func(string, time.Duration, bool) (authClient, error) {
		return fakeClient{authenticate: func(ctx context.Context, _ litellmauth.AuthenticateOptions) (litellmauth.Credential, error) {
			<-ctx.Done()
			return litellmauth.Credential{}, ctx.Err()
		}}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := execute(ctx, []string{"login"}, deps); !errors.Is(err, context.Canceled) {
		t.Fatalf("execute() error = %v", err)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("cancellation output: stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestTeamPromptReturnsOnCancellation(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	selector := teamSelector(dependencies{stdin: reader, stderr: io.Discard})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := selector(ctx, []litellmauth.Team{{ID: "team-1"}})
		result <- err
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("selector error = %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("team selector did not return after cancellation")
	}
	_ = reader.Close()
}

func TestUnknownErrorsDoNotLeakSecrets(t *testing.T) {
	store := new(fakeStore)
	deps, stdout, stderr := testDependencies(store)
	deps.newClient = func(string, time.Duration, bool) (authClient, error) {
		return fakeClient{authenticate: func(context.Context, litellmauth.AuthenticateOptions) (litellmauth.Credential, error) {
			return litellmauth.Credential{}, errors.New("secret-key poll-secret jwt.header.payload")
		}}, nil
	}

	if err := execute(context.Background(), []string{"login", "--no-browser"}, deps); err == nil {
		t.Fatal("execute() error = nil")
	}
	human := stdout.String() + stderr.String()
	for _, secret := range []string{"secret-key", "poll-secret", "jwt.header.payload"} {
		if strings.Contains(human, secret) {
			t.Fatalf("human output leaked %q: %q", secret, human)
		}
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr is empty")
	}
}

func TestLogoutIsIdempotentAndIgnoresIssuer(t *testing.T) {
	store := new(fakeStore)
	deps, _, _ := testDependencies(store)
	deps.getenv = func(string) string { return "https://ignored.example.com" }

	for range 2 {
		if err := execute(context.Background(), []string{"--base-url", "https://also-ignored.example.com", "logout"}, deps); err != nil {
			t.Fatalf("execute() error = %v", err)
		}
	}
	if store.deletes != 2 || store.loadBase != nil {
		t.Fatalf("deletes = %d, load base = %v", store.deletes, store.loadBase)
	}
}

func TestWhoamiFreshStaleAndMissing(t *testing.T) {
	for _, test := range []struct {
		name       string
		credential litellmauth.Credential
		loadErr    error
		wantErr    error
		want       []string
	}{
		{
			name: "fresh",
			credential: litellmauth.Credential{
				BaseURL: "https://proxy.example.com", Key: "secret-key", UserID: "user-1",
				TeamID: "team-1", TeamAlias: "Engineering", IssuedAt: testNow,
			},
			want: []string{"https://proxy.example.com", "user-1", "team-1", "Engineering", "fresh"},
		},
		{
			name: "stale",
			credential: litellmauth.Credential{
				BaseURL: "https://proxy.example.com", Key: "secret-key", UserID: "user-1",
				IssuedAt: testNow.Add(-25 * time.Hour),
			},
			want: []string{"stale"},
		},
		{name: "missing", loadErr: litellmauth.ErrNoCredential, wantErr: litellmauth.ErrNoCredential, want: []string{"not authenticated"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeStore{credential: test.credential, loadErr: test.loadErr}
			deps, stdout, stderr := testDependencies(store)

			err := execute(context.Background(), []string{"whoami"}, deps)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("execute() error = %v, want %v", err, test.wantErr)
			}
			human := stdout.String() + stderr.String()
			for _, want := range test.want {
				if !strings.Contains(strings.ToLower(human), strings.ToLower(want)) {
					t.Fatalf("output = %q, want %q", human, want)
				}
			}
			if strings.Contains(human, "secret-key") {
				t.Fatalf("whoami leaked key: %q", human)
			}
		})
	}
}

func TestWhoamiUsesOnlyExplicitIssuer(t *testing.T) {
	for _, test := range []struct {
		name string
		env  string
		args []string
		want string
	}{
		{name: "stored issuer"},
		{name: "environment", env: "https://env.example.com", want: "https://env.example.com"},
		{name: "flag", env: "https://env.example.com", args: []string{"--base-url", "https://flag.example.com"}, want: "https://flag.example.com"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeStore{credential: successfulCredential()}
			deps, _, _ := testDependencies(store)
			deps.getenv = func(string) string { return test.env }

			if err := execute(context.Background(), append(test.args, "whoami"), deps); err != nil {
				t.Fatalf("execute() error = %v", err)
			}
			if test.want == "" && store.loadBase != nil || test.want != "" && (store.loadBase == nil || store.loadBase.String() != test.want) {
				t.Fatalf("Load base = %v, want %q", store.loadBase, test.want)
			}
		})
	}
}

func TestWhoamiRejectsCredentialKeyInMetadata(t *testing.T) {
	store := &fakeStore{credential: litellmauth.Credential{
		BaseURL:   "https://proxy.example.com",
		Key:       "secret-key",
		TeamAlias: "alias-secret-key",
		IssuedAt:  testNow,
	}}
	deps, stdout, stderr := testDependencies(store)

	err := execute(context.Background(), []string{"whoami"}, deps)
	human := stdout.String() + stderr.String()
	if !errors.Is(err, litellmauth.ErrProtocol) || strings.Contains(human, "secret-key") || stdout.Len() != 0 {
		t.Fatalf("execute() error = %v; stdout = %q; stderr = %q", err, stdout, stderr)
	}
}

func TestPrintTokenExactOutputAndNoClient(t *testing.T) {
	store := &fakeStore{credential: successfulCredential()}
	deps, stdout, stderr := testDependencies(store)
	deps.newClient = func(string, time.Duration, bool) (authClient, error) {
		t.Fatal("print-token created auth client")
		return nil, nil
	}

	if err := execute(context.Background(), []string{"print-token"}, deps); err != nil {
		t.Fatalf("execute() error = %v", err)
	}
	if got := stdout.String(); got != "secret-key\n" {
		t.Fatalf("stdout = %q", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestPrintTokenFailuresLeaveStdoutEmpty(t *testing.T) {
	for _, test := range []struct {
		name       string
		credential litellmauth.Credential
		loadErr    error
		storeErr   error
		args       []string
		wantErr    error
	}{
		{name: "missing", loadErr: litellmauth.ErrNoCredential, wantErr: litellmauth.ErrNoCredential},
		{name: "stale", credential: litellmauth.Credential{Key: "secret-key", IssuedAt: testNow.Add(-25 * time.Hour)}, wantErr: litellmauth.ErrCredentialStale},
		{name: "invalid key", credential: litellmauth.Credential{Key: "bad key", IssuedAt: testNow}, wantErr: litellmauth.ErrProtocol},
		{name: "origin mismatch", loadErr: litellmauth.ErrOriginMismatch, args: []string{"--base-url", "https://other.example.com"}, wantErr: litellmauth.ErrOriginMismatch},
		{name: "malformed", loadErr: litellmauth.ErrProtocol, wantErr: litellmauth.ErrProtocol},
		{name: "store creation", storeErr: errors.New("store failed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeStore{credential: test.credential, loadErr: test.loadErr}
			deps, stdout, stderr := testDependencies(store)
			if test.storeErr != nil {
				deps.newStore = func(string) (credentialStore, error) { return nil, test.storeErr }
			}
			deps.newClient = func(string, time.Duration, bool) (authClient, error) {
				t.Fatal("print-token created auth client")
				return nil, nil
			}

			err := execute(context.Background(), append(test.args, "print-token"), deps)
			if err == nil || test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("execute() error = %v, want %v", err, test.wantErr)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q", stdout)
			}
			if stderr.Len() == 0 || strings.Contains(stderr.String(), "secret-key") {
				t.Fatalf("stderr = %q", stderr)
			}
		})
	}
}

func TestPrintTokenExplicitIssuerPrecedence(t *testing.T) {
	for _, test := range []struct {
		name string
		env  string
		args []string
		want string
	}{
		{name: "stored issuer"},
		{name: "environment", env: "https://env.example.com", want: "https://env.example.com"},
		{name: "flag", env: "https://env.example.com", args: []string{"--base-url", "https://flag.example.com"}, want: "https://flag.example.com"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeStore{credential: successfulCredential()}
			deps, _, _ := testDependencies(store)
			deps.getenv = func(string) string { return test.env }

			if err := execute(context.Background(), append(test.args, "print-token"), deps); err != nil {
				t.Fatalf("execute() error = %v", err)
			}
			if test.want == "" && store.loadBase != nil || test.want != "" && (store.loadBase == nil || store.loadBase.String() != test.want) {
				t.Fatalf("Load base = %v, want %q", store.loadBase, test.want)
			}
		})
	}
}

func TestPrintTokenBindsStoredTokenToBaseURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials", "token.json")
	store, err := tokenstore.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), successfulCredential()); err != nil {
		t.Fatal(err)
	}
	deps, stdout, _ := testDependencies(new(fakeStore))
	deps.newStore = func(string) (credentialStore, error) { return store, nil }

	err = execute(context.Background(), []string{"--base-url", "https://other.example.com", "print-token"}, deps)
	if !errors.Is(err, litellmauth.ErrOriginMismatch) || stdout.Len() != 0 {
		t.Fatalf("execute() error = %v, stdout = %q", err, stdout)
	}
}

func TestPrintTokenPerformsNoNetworkRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()
	store := &fakeStore{credential: successfulCredential()}
	deps, _, _ := testDependencies(store)
	deps.getenv = func(string) string { return server.URL }

	if err := execute(context.Background(), []string{"print-token"}, deps); err != nil {
		t.Fatalf("execute() error = %v", err)
	}
	if requests != 0 {
		t.Fatalf("HTTP requests = %d", requests)
	}
}

func TestGlobalAndLoginFlags(t *testing.T) {
	store := new(fakeStore)
	deps, stdout, _ := testDependencies(store)
	root := newRoot(deps)
	for _, name := range []string{"base-url", "token-file", "timeout", "allow-insecure-http", "verbose"} {
		if root.PersistentFlags().Lookup(name) == nil {
			t.Errorf("missing global flag --%s", name)
		}
	}
	login, _, err := root.Find([]string{"login"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"no-browser", "team"} {
		if login.Flags().Lookup(name) == nil {
			t.Errorf("missing login flag --%s", name)
		}
	}
	if err := execute(context.Background(), []string{"--help"}, deps); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), "completion") {
		t.Fatalf("help advertises unrequested completion command: %q", stdout)
	}
}

func sessionClient(rawURL, code string, credential litellmauth.Credential) func(string, time.Duration, bool) (authClient, error) {
	return func(string, time.Duration, bool) (authClient, error) {
		return fakeClient{authenticate: func(ctx context.Context, options litellmauth.AuthenticateOptions) (litellmauth.Credential, error) {
			u, _ := url.Parse(rawURL)
			if err := options.OnSession(ctx, litellmauth.Session{VerificationURL: u, UserCode: code}); err != nil {
				return litellmauth.Credential{}, err
			}
			return credential, nil
		}}, nil
	}
}

func successfulCredential() litellmauth.Credential {
	return litellmauth.Credential{
		BaseURL:  "https://proxy.example.com",
		Key:      "secret-key",
		UserID:   "user-1",
		IssuedAt: testNow,
	}
}

func teamServer(t *testing.T, single bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sso/cli/start"):
			_, _ = io.WriteString(w, `{"login_id":"login-1","poll_secret":"poll-secret","user_code":"CODE","expires_in":60}`)
		case r.Method == http.MethodGet && single:
			_, _ = io.WriteString(w, `{"status":"ready","key":"secret-key","user_id":"user-1","teams":["team-1"]}`)
		case r.Method == http.MethodGet && r.URL.Query().Get("team_id") == "":
			_, _ = io.WriteString(w, `{"status":"ready","requires_team_selection":true,"team_details":[{"team_id":"team-1","team_alias":"Engineering"},{"team_id":"team-2","team_alias":"Support"}]}`)
		case r.Method == http.MethodGet:
			team := r.URL.Query().Get("team_id")
			_, _ = fmt.Fprintf(w, `{"status":"ready","key":"secret-key","user_id":"user-1","team_id":%q,"team_details":[{"team_id":"team-1","team_alias":"Engineering"},{"team_id":"team-2","team_alias":"Support"}]}`, team)
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
}
