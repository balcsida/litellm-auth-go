package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	litellmauth "github.com/balcsida/litellm-auth-go"
	"github.com/balcsida/litellm-auth-go/internal/baseurl"
	"github.com/balcsida/litellm-auth-go/tokenstore"
	"github.com/cli/browser"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const defaultBaseURL = "http://localhost:4000"

type authClient interface {
	Authenticate(context.Context, litellmauth.AuthenticateOptions) (litellmauth.Credential, error)
}

type credentialStore interface {
	Load(context.Context, *url.URL) (litellmauth.Credential, error)
	Save(context.Context, litellmauth.Credential) error
	Delete(context.Context) error
}

type dependencies struct {
	stdin       io.Reader
	stdout      io.Writer
	stderr      io.Writer
	getenv      func(string) string
	isTerminal  func() bool
	openBrowser func(string) error
	now         func() time.Time
	newClient   func(string, time.Duration, bool) (authClient, error)
	newStore    func(string) (credentialStore, error)
}

type globalOptions struct {
	baseURL           string
	tokenFile         string
	timeout           time.Duration
	allowInsecureHTTP bool
	verbose           bool
}

// Execute runs litellm-auth with signal-aware context supplied by the caller.
func Execute(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return execute(ctx, args, defaultDependencies(stdin, stdout, stderr))
}

func execute(ctx context.Context, args []string, deps dependencies) error {
	command := newRoot(deps)
	command.SetArgs(args)
	err := command.ExecuteContext(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		printError(deps.stderr, err)
	}
	return err
}

func defaultDependencies(stdin io.Reader, stdout, stderr io.Writer) dependencies {
	return dependencies{
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		getenv: os.Getenv,
		isTerminal: func() bool {
			file, ok := stdin.(interface{ Fd() uintptr })
			return ok && term.IsTerminal(int(file.Fd()))
		},
		openBrowser: browser.OpenURL,
		now:         time.Now,
		newClient: func(raw string, timeout time.Duration, allowInsecureHTTP bool) (authClient, error) {
			options := []litellmauth.Option{litellmauth.WithMaxWait(timeout)}
			if allowInsecureHTTP {
				options = append(options, litellmauth.WithAllowInsecureHTTP())
			}
			return litellmauth.New(raw, options...)
		},
		newStore: func(path string) (credentialStore, error) { return tokenstore.NewFileStore(path) },
	}
}

func newRoot(deps dependencies) *cobra.Command {
	options := globalOptions{timeout: 10 * time.Minute}
	root := &cobra.Command{
		Use:               "litellm-auth",
		Short:             "Authenticate with a LiteLLM proxy",
		SilenceErrors:     true,
		SilenceUsage:      true,
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}
	root.SetIn(deps.stdin)
	root.SetOut(deps.stdout)
	root.SetErr(deps.stderr)
	root.PersistentFlags().StringVar(&options.baseURL, "base-url", "", "LiteLLM proxy base URL")
	root.PersistentFlags().StringVar(&options.tokenFile, "token-file", "", "credential file")
	root.PersistentFlags().DurationVar(&options.timeout, "timeout", 10*time.Minute, "login timeout")
	root.PersistentFlags().BoolVar(&options.allowInsecureHTTP, "allow-insecure-http", false, "allow non-loopback HTTP")
	root.PersistentFlags().BoolVar(&options.verbose, "verbose", false, "show safe login progress")
	root.AddCommand(
		newLoginCommand(&options, deps),
		newLogoutCommand(&options, deps),
		newWhoamiCommand(&options, deps),
		newPrintTokenCommand(&options, deps),
	)
	return root
}

func newLoginCommand(global *globalOptions, deps dependencies) *cobra.Command {
	var noBrowser bool
	var team string
	command := &cobra.Command{
		Use:   "login",
		Short: "Authenticate and store a credential",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			rawBase := resolvedBaseURL(command, global.baseURL, deps.getenv, true)
			client, err := deps.newClient(rawBase, global.timeout, global.allowInsecureHTTP)
			if err != nil {
				return err
			}
			store, err := deps.newStore(global.tokenFile)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(command.Context(), global.timeout)
			defer cancel()
			options := litellmauth.AuthenticateOptions{
				TeamID: team,
				OnSession: func(_ context.Context, session litellmauth.Session) error {
					if session.VerificationURL == nil {
						return litellmauth.ErrProtocol
					}
					safeURL, safeCode := safe(session.VerificationURL.String()), safe(session.UserCode)
					fmt.Fprintf(deps.stdout, "Verification URL: %s\nUser code: %s\n", safeURL, safeCode)
					if noBrowser {
						return nil
					}
					if err := deps.openBrowser(session.VerificationURL.String()); err != nil {
						fmt.Fprintln(deps.stderr, "Browser could not be opened; continue manually with the URL above.")
					}
					return nil
				},
			}
			if team == "" && deps.isTerminal() {
				options.SelectTeam = teamSelector(deps)
			}
			if global.verbose {
				options.OnEvent = func(event litellmauth.Event) { printEvent(deps.stderr, event) }
			}
			credential, err := client.Authenticate(ctx, options)
			if err != nil {
				return err
			}
			var output bytes.Buffer
			if err := printCredential(&output, "Authenticated", credential, deps.now()); err != nil {
				return err
			}
			if err := store.Save(ctx, credential); err != nil {
				return err
			}
			_, err = deps.stdout.Write(output.Bytes())
			return err
		},
	}
	command.Flags().BoolVar(&noBrowser, "no-browser", false, "do not open a browser")
	command.Flags().StringVar(&team, "team", "", "LiteLLM team ID")
	return command
}

func newLogoutCommand(global *globalOptions, deps dependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Delete the stored credential",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			store, err := deps.newStore(global.tokenFile)
			if err != nil {
				return err
			}
			if err := store.Delete(command.Context()); err != nil {
				return err
			}
			fmt.Fprintln(deps.stdout, "Logged out.")
			return nil
		},
	}
}

func newWhoamiCommand(global *globalOptions, deps dependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show the stored credential identity",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			store, err := deps.newStore(global.tokenFile)
			if err != nil {
				return err
			}
			issuer, err := explicitIssuer(command, global.baseURL, deps.getenv)
			if err != nil {
				return err
			}
			credential, err := store.Load(command.Context(), issuer)
			if err != nil {
				return err
			}
			return printCredential(deps.stdout, "Authenticated", credential, deps.now())
		},
	}
}

func newPrintTokenCommand(global *globalOptions, deps dependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "print-token",
		Short: "Print the fresh stored token",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			store, err := deps.newStore(global.tokenFile)
			if err != nil {
				return err
			}
			issuer, err := explicitIssuer(command, global.baseURL, deps.getenv)
			if err != nil {
				return err
			}
			credential, err := store.Load(command.Context(), issuer)
			if err != nil {
				return err
			}
			if !credential.Fresh(deps.now()) {
				return litellmauth.ErrCredentialStale
			}
			if credential.AuthorizationHeader() == "" {
				return litellmauth.ErrProtocol
			}
			var output bytes.Buffer
			output.WriteString(credential.Key)
			output.WriteByte('\n')
			_, err = deps.stdout.Write(output.Bytes())
			return err
		},
	}
}

func resolvedBaseURL(command *cobra.Command, flag string, getenv func(string) string, login bool) string {
	if command.Flags().Changed("base-url") {
		return flag
	}
	if env := getenv("LITELLM_PROXY_URL"); env != "" {
		return env
	}
	if login {
		return defaultBaseURL
	}
	return ""
}

func explicitIssuer(command *cobra.Command, flag string, getenv func(string) string) (*url.URL, error) {
	raw := resolvedBaseURL(command, flag, getenv, false)
	if raw == "" {
		return nil, nil
	}
	normalized, err := baseurl.Normalize(raw)
	if err != nil {
		return nil, err
	}
	return normalized, nil
}

func teamSelector(deps dependencies) litellmauth.TeamSelector {
	reader := bufio.NewReader(deps.stdin)
	return func(ctx context.Context, teams []litellmauth.Team) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		fmt.Fprintln(deps.stderr, "Select a team:")
		for index, team := range teams {
			fmt.Fprintf(deps.stderr, "%d) %s\n", index+1, teamLabel(team))
		}
		fmt.Fprint(deps.stderr, "Team: ")
		answer, err := readLine(ctx, reader)
		if err != nil && !errors.Is(err, io.EOF) {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return "", err
			}
			return "", errors.New("read team selection")
		}
		answer = strings.TrimSpace(answer)
		if index, err := strconv.Atoi(answer); err == nil && index > 0 && index <= len(teams) {
			return teams[index-1].ID, nil
		}
		for _, team := range teams {
			if answer == team.ID {
				return team.ID, nil
			}
		}
		return "", errors.New("invalid team selection")
	}
}

func readLine(ctx context.Context, reader *bufio.Reader) (string, error) {
	type result struct {
		line string
		err  error
	}
	resultChannel := make(chan result, 1)
	go func() {
		line, err := reader.ReadString('\n')
		resultChannel <- result{line: line, err: err}
	}()
	select {
	case <-ctx.Done():
		// ponytail: a CLI exit reclaims the blocked read; use cancellable input if embedding.
		return "", ctx.Err()
	case result := <-resultChannel:
		return result.line, result.err
	}
}

func printCredential(output io.Writer, heading string, credential litellmauth.Credential, now time.Time) error {
	if !credentialSafeForOutput(credential) {
		return litellmauth.ErrProtocol
	}
	fmt.Fprintln(output, heading)
	fmt.Fprintf(output, "Base URL: %s\n", safe(credential.BaseURL))
	fmt.Fprintf(output, "User ID: %s\n", safe(credential.UserID))
	if credential.TeamID != "" || credential.TeamAlias != "" {
		fmt.Fprintf(output, "Team: %s\n", teamLabel(litellmauth.Team{ID: credential.TeamID, Alias: credential.TeamAlias}))
	}
	if !credential.IssuedAt.IsZero() {
		fmt.Fprintf(output, "Issued: %s\n", credential.IssuedAt.Format(time.RFC3339))
	}
	status := "stale"
	if credential.Fresh(now) {
		status = "fresh"
	}
	fmt.Fprintf(output, "Status: %s\n", status)
	return nil
}

func credentialSafeForOutput(credential litellmauth.Credential) bool {
	if credential.AuthorizationHeader() == "" {
		return false
	}
	containsKey := func(value string) bool {
		return strings.Contains(value, credential.Key)
	}
	if containsKey(credential.BaseURL) || containsKey(credential.UserID) ||
		containsKey(credential.TeamID) || containsKey(credential.TeamAlias) {
		return false
	}
	for _, team := range credential.Teams {
		if containsKey(team.ID) || containsKey(team.Alias) {
			return false
		}
	}
	for _, value := range credential.AttributionMetadata {
		if text, ok := value.(string); ok && containsKey(text) {
			return false
		}
	}
	return true
}

func teamLabel(team litellmauth.Team) string {
	id, alias := safe(team.ID), safe(team.Alias)
	if alias == "" {
		return id
	}
	if id == "" {
		return alias
	}
	return id + " (" + alias + ")"
}

func printEvent(output io.Writer, event litellmauth.Event) {
	switch event.Kind {
	case litellmauth.EventPending:
		fmt.Fprintf(output, "Waiting for login approval (attempt %d).\n", event.Attempt)
	case litellmauth.EventRetrying:
		if event.StatusCode != 0 {
			fmt.Fprintf(output, "Retrying login (attempt %d, HTTP %d).\n", event.Attempt, event.StatusCode)
		} else {
			fmt.Fprintf(output, "Retrying login (attempt %d).\n", event.Attempt)
		}
	case litellmauth.EventTeamsRequired:
		fmt.Fprintf(output, "Team selection required (%d options, attempt %d).\n", len(event.Teams), event.Attempt)
	}
}

func printError(output io.Writer, err error) {
	var teamErr *litellmauth.TeamRequiredError
	switch {
	case errors.Is(err, litellmauth.ErrNoCredential):
		fmt.Fprintln(output, "Not authenticated: no stored LiteLLM credential.")
	case errors.Is(err, litellmauth.ErrCredentialStale):
		fmt.Fprintln(output, "Stored LiteLLM credential is stale; run litellm-auth login.")
	case errors.As(err, &teamErr):
		available := make([]string, len(teamErr.Teams))
		for index, team := range teamErr.Teams {
			available[index] = teamLabel(team)
		}
		fmt.Fprintf(output, "Team selection required; rerun with --team <team-id>. Available: %s\n", strings.Join(available, ", "))
	case errors.Is(err, litellmauth.ErrOriginMismatch):
		fmt.Fprintln(output, litellmauth.ErrOriginMismatch)
	case errors.Is(err, litellmauth.ErrProtocol):
		fmt.Fprintln(output, litellmauth.ErrProtocol)
	case errors.Is(err, litellmauth.ErrUnsupportedProxy):
		fmt.Fprintln(output, litellmauth.ErrUnsupportedProxy)
	case errors.Is(err, litellmauth.ErrLoginExpired), errors.Is(err, context.DeadlineExceeded):
		fmt.Fprintln(output, "LiteLLM CLI login timed out.")
	default:
		fmt.Fprintln(output, "litellm-auth failed.")
	}
}

func safe(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
}
