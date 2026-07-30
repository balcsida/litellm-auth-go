package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
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
	Discover(context.Context) (*litellmauth.NativeOIDCConfig, error)
	DiscoverProvider(context.Context, litellmauth.NativeOIDCConfig) (litellmauth.OIDCProvider, error)
	AuthenticateBrowser(context.Context, litellmauth.NativeOIDCConfig, litellmauth.OIDCProvider, litellmauth.BrowserLoginOptions) (litellmauth.Credential, error)
	AuthenticateDevice(context.Context, litellmauth.NativeOIDCConfig, litellmauth.OIDCProvider, litellmauth.DeviceLoginOptions) (litellmauth.Credential, error)
	Refresh(context.Context, litellmauth.Credential) (litellmauth.Credential, error)
}

type browserListenerError struct{ cause error }

func (e *browserListenerError) Error() string { return "native OIDC browser listener unavailable" }
func (e *browserListenerError) Unwrap() error { return e.cause }

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
	listen      func(network, address string) (net.Listener, error)
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
		listen:      net.Listen,
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
		newImportTokenCommand(&options, deps),
		newLogoutCommand(&options, deps),
		newWhoamiCommand(&options, deps),
		newPrintTokenCommand(&options, deps),
	)
	return root
}

func newLoginCommand(global *globalOptions, deps dependencies) *cobra.Command {
	var flow string
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
			credential, err := loginCredential(ctx, client, rawBase, flow, noBrowser, team, options, deps)
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
	command.Flags().StringVar(&flow, "flow", "auto", "authentication flow: auto, browser, device, or litellm-sso")
	command.Flags().BoolVar(&noBrowser, "no-browser", false, "do not open a browser")
	command.Flags().StringVar(&team, "team", "", "LiteLLM team ID")
	return command
}

func loginCredential(ctx context.Context, client authClient, rawBase, flow string, noBrowser bool, team string, options litellmauth.AuthenticateOptions, deps dependencies) (litellmauth.Credential, error) {
	if noBrowser && (flow == "browser" || flow == "litellm-sso") {
		return litellmauth.Credential{}, errors.New("--no-browser cannot be used with explicit browser flows")
	}
	if flow == "litellm-sso" {
		return client.Authenticate(ctx, options)
	}
	if flow != "auto" && flow != "browser" && flow != "device" {
		return litellmauth.Credential{}, errors.New("invalid login flow")
	}
	config, err := client.Discover(ctx)
	if err != nil {
		return litellmauth.Credential{}, err
	}
	if config == nil {
		if flow == "auto" {
			return client.Authenticate(ctx, options)
		}
		return litellmauth.Credential{}, errors.New("native OIDC metadata is unavailable")
	}
	if team != "" {
		return litellmauth.Credential{}, errors.New("--team is not supported with native OIDC")
	}
	provider, err := client.DiscoverProvider(ctx, *config)
	if err != nil {
		return litellmauth.Credential{}, err
	}
	browser := func() (litellmauth.Credential, error) {
		return client.AuthenticateBrowser(ctx, *config, provider, litellmauth.BrowserLoginOptions{
			OpenURL: func(_ context.Context, authorization *url.URL) error { return deps.openBrowser(authorization.String()) },
			Listen: func(network, address string) (net.Listener, error) {
				listener, err := deps.listen(network, address)
				if err != nil {
					return nil, &browserListenerError{cause: err}
				}
				return listener, nil
			},
		})
	}
	device := func() (litellmauth.Credential, error) {
		if provider.DeviceAuthorizationEndpoint == "" {
			return litellmauth.Credential{}, errors.New("native OIDC device authorization is unavailable")
		}
		return client.AuthenticateDevice(ctx, *config, provider, litellmauth.DeviceLoginOptions{OnAuthorization: func(_ context.Context, authorization litellmauth.DeviceAuthorization) error {
			verification := authorization.VerificationURIComplete
			if verification == "" {
				verification = authorization.VerificationURI
			}
			fmt.Fprintf(deps.stdout, "Verification URL: %s\nUser code: %s\n", safe(verification), safe(authorization.UserCode))
			if !noBrowser {
				if err := deps.openBrowser(verification); err != nil {
					fmt.Fprintln(deps.stderr, "Browser could not be opened; continue manually with the URL above.")
				}
			}
			return nil
		}})
	}
	var credential litellmauth.Credential
	switch flow {
	case "browser":
		credential, err = browser()
	case "device":
		credential, err = device()
	default:
		if noBrowser {
			credential, err = device()
		} else {
			credential, err = browser()
			var listenerErr *browserListenerError
			if err != nil && errors.As(err, &listenerErr) {
				credential, err = device()
			}
		}
	}
	if err != nil {
		return litellmauth.Credential{}, err
	}
	base, err := baseurl.Normalize(rawBase)
	if err != nil {
		return litellmauth.Credential{}, err
	}
	credential.BaseURL, credential.Issuer = base.String(), provider.Issuer
	return credential, nil
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
	var jsonOutput bool
	command := &cobra.Command{
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
			if jsonOutput {
				return printCredentialJSON(deps.stdout, credential, deps.now())
			}
			return printCredential(deps.stdout, "Authenticated", credential, deps.now())
		},
	}
	command.Flags().BoolVar(&jsonOutput, "json", false, "print identity as JSON")
	return command
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
				if credential.AuthMethod != litellmauth.AuthMethodOIDC || credential.OIDCRefresh == nil {
					return litellmauth.ErrCredentialStale
				}
				rawBase := credential.BaseURL
				if issuer != nil {
					rawBase = issuer.String()
				}
				client, err := deps.newClient(rawBase, global.timeout, global.allowInsecureHTTP)
				if err != nil {
					return err
				}
				credential, err = client.Refresh(command.Context(), credential)
				if err != nil {
					return err
				}
				if err := store.Save(command.Context(), credential); err != nil {
					return err
				}
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
	if credential.AuthMethod != "" {
		fmt.Fprintf(output, "Method: %s\n", safe(string(credential.AuthMethod)))
	}
	fmt.Fprintf(output, "User ID: %s\n", safe(credential.UserID))
	if credential.TeamID != "" || credential.TeamAlias != "" {
		fmt.Fprintf(output, "Team: %s\n", teamLabel(litellmauth.Team{ID: credential.TeamID, Alias: credential.TeamAlias}))
	}
	if !credential.IssuedAt.IsZero() {
		fmt.Fprintf(output, "Issued: %s\n", credential.IssuedAt.Format(time.RFC3339))
	}
	if expiresAt := credential.Expiry(); !expiresAt.IsZero() {
		fmt.Fprintf(output, "Expires: %s\n", expiresAt.Format(time.RFC3339))
	}
	status := "stale"
	if credential.Fresh(now) {
		status = "fresh"
	}
	fmt.Fprintf(output, "Status: %s\n", status)
	return nil
}

func printCredentialJSON(output io.Writer, credential litellmauth.Credential, now time.Time) error {
	if !credentialSafeForOutput(credential) {
		return litellmauth.ErrProtocol
	}
	expiresAt := credential.Expiry()
	identity := struct {
		Authenticated       bool                   `json:"authenticated"`
		BaseURL             string                 `json:"base_url"`
		UserID              string                 `json:"user_id"`
		TeamID              string                 `json:"team_id,omitempty"`
		TeamAlias           string                 `json:"team_alias,omitempty"`
		AuthMethod          litellmauth.AuthMethod `json:"auth_method,omitempty"`
		TokenType           string                 `json:"token_type,omitempty"`
		Issuer              string                 `json:"issuer,omitempty"`
		Subject             string                 `json:"subject,omitempty"`
		Scopes              []string               `json:"scopes,omitempty"`
		NonExpiring         bool                   `json:"non_expiring,omitempty"`
		IssuedAt            string                 `json:"issued_at,omitempty"`
		ExpiresAt           string                 `json:"expires_at,omitempty"`
		Fresh               bool                   `json:"fresh"`
		AttributionMetadata map[string]any         `json:"attribution_metadata,omitempty"`
	}{
		Authenticated:       true,
		BaseURL:             credential.BaseURL,
		UserID:              credential.UserID,
		TeamID:              credential.TeamID,
		TeamAlias:           credential.TeamAlias,
		AuthMethod:          credential.AuthMethod,
		TokenType:           credential.TokenType,
		Issuer:              credential.Issuer,
		Subject:             credential.Subject,
		Scopes:              append([]string(nil), credential.Scopes...),
		NonExpiring:         credential.NonExpiring,
		Fresh:               credential.Fresh(now),
		AttributionMetadata: credential.AttributionMetadata,
	}
	if !credential.IssuedAt.IsZero() {
		identity.IssuedAt = credential.IssuedAt.Format(time.RFC3339)
	}
	if !expiresAt.IsZero() {
		identity.ExpiresAt = expiresAt.Format(time.RFC3339)
	}
	data, err := json.Marshal(identity)
	if err != nil {
		return litellmauth.ErrProtocol
	}
	data = append(data, '\n')
	_, err = output.Write(data)
	return err
}

func credentialSafeForOutput(credential litellmauth.Credential) bool {
	if credential.AuthorizationHeader() == "" {
		return false
	}
	containsKey := func(value string) bool {
		return strings.Contains(value, credential.Key)
	}
	if containsKey(credential.BaseURL) || containsKey(credential.UserID) ||
		containsKey(credential.TeamID) || containsKey(credential.TeamAlias) ||
		containsKey(string(credential.AuthMethod)) || containsKey(credential.TokenType) ||
		containsKey(credential.Issuer) || containsKey(credential.Subject) {
		return false
	}
	for _, scope := range credential.Scopes {
		if containsKey(scope) {
			return false
		}
	}
	for _, team := range credential.Teams {
		if containsKey(team.ID) || containsKey(team.Alias) {
			return false
		}
	}
	for name, value := range credential.AttributionMetadata {
		if containsKey(name) {
			return false
		}
		switch value := value.(type) {
		case string:
			if containsKey(value) {
				return false
			}
		case float64:
			if math.IsNaN(value) || math.IsInf(value, 0) {
				return false
			}
		case bool:
		default:
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
	var httpErr *litellmauth.HTTPError
	var safeErr *safeCLIError
	switch {
	case errors.Is(err, litellmauth.ErrNoCredential):
		fmt.Fprintln(output, "Not authenticated: no stored LiteLLM credential.")
	case errors.Is(err, litellmauth.ErrCredentialStale):
		fmt.Fprintln(output, "Credential is stale; run litellm-auth login or import a fresh token.")
	case errors.As(err, &teamErr):
		available := make([]string, len(teamErr.Teams))
		for index, team := range teamErr.Teams {
			available[index] = teamLabel(team)
		}
		fmt.Fprintf(output, "Team selection required; rerun with --team <team-id>. Available: %s\n", strings.Join(available, ", "))
	case errors.Is(err, litellmauth.ErrOriginMismatch):
		fmt.Fprintln(output, litellmauth.ErrOriginMismatch)
	case errors.Is(err, litellmauth.ErrUnsupportedProxy):
		fmt.Fprintln(output, litellmauth.ErrUnsupportedProxy)
	case errors.As(err, &safeErr):
		fmt.Fprintln(output, safeErr.Error())
	case errors.Is(err, litellmauth.ErrCredentialExpiryUnknown):
		fmt.Fprintln(output, "Credential expiry is unknown; provide --expires-at, --ttl, or --non-expiring.")
	case errors.Is(err, litellmauth.ErrInvalidCredential):
		fmt.Fprintln(output, litellmauth.ErrInvalidCredential)
	case errors.Is(err, litellmauth.ErrSourceUnavailable):
		fmt.Fprintln(output, litellmauth.ErrSourceUnavailable)
	case errors.Is(err, litellmauth.ErrSourceOutput):
		fmt.Fprintln(output, litellmauth.ErrSourceOutput)
	case errors.As(err, &httpErr):
		detail := httpErr.SafeDetail()
		if detail != "" {
			fmt.Fprintf(output, "LiteLLM authentication failed: %s\n", detail)
		} else {
			fmt.Fprintf(output, "LiteLLM authentication failed: HTTP %d.\n", httpErr.StatusCode)
		}
	case errors.Is(err, litellmauth.ErrProtocol):
		fmt.Fprintln(output, litellmauth.ErrProtocol)
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
