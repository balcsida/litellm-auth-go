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
	AuthenticatePKCE(context.Context, litellmauth.PKCEOptions) (litellmauth.Credential, error)
	AuthenticateOIDC(context.Context, litellmauth.OIDCOptions) (litellmauth.Credential, error)
	AuthenticateOIDCDevice(context.Context, litellmauth.OIDCDeviceOptions) (litellmauth.Credential, error)
	Refresh(context.Context, litellmauth.Credential) (litellmauth.Credential, error)
	RevokePKCE(context.Context, litellmauth.Credential) error
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
		newImportTokenCommand(&options, deps),
		newLogoutCommand(&options, deps),
		newWhoamiCommand(&options, deps),
		newPrintTokenCommand(&options, deps),
	)
	return root
}

func newLoginCommand(global *globalOptions, deps dependencies) *cobra.Command {
	var noBrowser bool
	var flow, team string
	var redirectPorts []int
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
			provider := litellmauth.OIDCProvider{
				Issuer:   flagOrEnv(command, "oidc-issuer", "LITELLM_OIDC_ISSUER", deps.getenv),
				ClientID: flagOrEnv(command, "oidc-client-id", "LITELLM_OIDC_CLIENT_ID", deps.getenv),
				Scope:    flagOrEnv(command, "oidc-scope", "LITELLM_OIDC_SCOPE", deps.getenv),
			}
			if provider.Scope == "" {
				provider.Scope = defaultOIDCScope
			}
			credential, err := loginFlow(ctx, client, deps, global.verbose, flow, team, noBrowser, provider, redirectPorts)
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
	command.Flags().StringVar(&flow, "flow", "auto", "login flow: auto, browser, device, pkce, or litellm-sso")
	command.Flags().StringVar(&team, "team", "", "LiteLLM team ID")
	command.Flags().String("oidc-issuer", "", "identity provider issuer URL (or LITELLM_OIDC_ISSUER)")
	command.Flags().String("oidc-client-id", "", "public OIDC client id (or LITELLM_OIDC_CLIENT_ID)")
	command.Flags().String("oidc-scope", "", "OIDC scopes (or LITELLM_OIDC_SCOPE); default "+defaultOIDCScope)
	command.Flags().IntSliceVar(&redirectPorts, "oidc-redirect-port", nil, "loopback callback port to try, for providers that register exact redirect URIs")
	return command
}

const defaultOIDCScope = "openid profile email offline_access"

func flagOrEnv(command *cobra.Command, name, env string, getenv func(string) string) string {
	if command.Flags().Changed(name) {
		value, _ := command.Flags().GetString(name)
		return value
	}
	return getenv(env)
}

// loginFlow runs exactly one login flow; auto only falls back from browser to
// device before any browser session has started.
func loginFlow(ctx context.Context, client authClient, deps dependencies, verbose bool, flow, team string, noBrowser bool, provider litellmauth.OIDCProvider, redirectPorts []int) (litellmauth.Credential, error) {
	errSettings := errors.New("set --oidc-issuer and --oidc-client-id (or LITELLM_OIDC_ISSUER and LITELLM_OIDC_CLIENT_ID) for identity-provider login")
	errTeam := errors.New("--team applies only to the litellm-sso flow")
	haveBoth := provider.Issuer != "" && provider.ClientID != ""
	switch flow {
	case "litellm-sso":
		return ssoLogin(ctx, client, deps, verbose, team, noBrowser)
	case "pkce":
		if team != "" {
			return litellmauth.Credential{}, errTeam
		}
		return client.AuthenticatePKCE(ctx, litellmauth.PKCEOptions{OnSession: openAuthorizeURL(deps, noBrowser)})
	case "browser", "device", "auto":
		if flow == "auto" && provider.Issuer == "" && provider.ClientID == "" {
			return ssoLogin(ctx, client, deps, verbose, team, noBrowser)
		}
		if !haveBoth {
			return litellmauth.Credential{}, errSettings
		}
		if team != "" {
			return litellmauth.Credential{}, errTeam
		}
		device := func() (litellmauth.Credential, error) {
			return client.AuthenticateOIDCDevice(ctx, litellmauth.OIDCDeviceOptions{
				Provider: provider,
				OnAuthorization: func(_ context.Context, authorization litellmauth.DeviceAuthorization) error {
					verificationURL := authorization.VerificationURIComplete
					if verificationURL == "" {
						verificationURL = authorization.VerificationURI
					}
					fmt.Fprintf(deps.stdout, "Verification URL: %s\nUser code: %s\n", safe(verificationURL), safe(authorization.UserCode))
					if !noBrowser {
						openBrowserOrWarn(deps, verificationURL)
					}
					return nil
				},
			})
		}
		if flow == "device" || flow == "auto" && noBrowser {
			return device()
		}
		credential, err := client.AuthenticateOIDC(ctx, litellmauth.OIDCOptions{
			Provider:      provider,
			RedirectPorts: redirectPorts,
			OnSession:     openAuthorizeURL(deps, noBrowser),
		})
		if flow == "auto" && errors.Is(err, litellmauth.ErrLoopbackUnavailable) {
			return device()
		}
		return credential, err
	default:
		return litellmauth.Credential{}, errors.New("invalid login flow: use auto, browser, device, pkce, or litellm-sso")
	}
}

func ssoLogin(ctx context.Context, client authClient, deps dependencies, verbose bool, team string, noBrowser bool) (litellmauth.Credential, error) {
	options := litellmauth.AuthenticateOptions{
		TeamID: team,
		OnSession: func(_ context.Context, session litellmauth.Session) error {
			if session.VerificationURL == nil {
				return litellmauth.ErrProtocol
			}
			safeURL, safeCode := safe(session.VerificationURL.String()), safe(session.UserCode)
			fmt.Fprintf(deps.stdout, "Verification URL: %s\nUser code: %s\n", safeURL, safeCode)
			if !noBrowser {
				openBrowserOrWarn(deps, session.VerificationURL.String())
			}
			return nil
		},
	}
	if team == "" && deps.isTerminal() {
		options.SelectTeam = teamSelector(deps)
	}
	if verbose {
		options.OnEvent = func(event litellmauth.Event) { printEvent(deps.stderr, event) }
	}
	return client.Authenticate(ctx, options)
}

// openAuthorizeURL prints the authorization URL and, unless noBrowser, opens it.
func openAuthorizeURL(deps dependencies, noBrowser bool) func(context.Context, litellmauth.PKCESession) error {
	return func(_ context.Context, session litellmauth.PKCESession) error {
		fmt.Fprintf(deps.stdout, "Open this URL to sign in: %s\n", safe(session.AuthorizeURL.String()))
		if !noBrowser {
			openBrowserOrWarn(deps, session.AuthorizeURL.String())
		}
		return nil
	}
}

func openBrowserOrWarn(deps dependencies, target string) {
	if err := deps.openBrowser(target); err != nil {
		fmt.Fprintln(deps.stderr, "Browser could not be opened; continue manually with the URL above.")
	}
}

func newLogoutCommand(global *globalOptions, deps dependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Revoke PKCE access and delete the stored credential",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			store, err := deps.newStore(global.tokenFile)
			if err != nil {
				return err
			}
			credential, err := store.Load(command.Context(), nil)
			if err == nil && credential.AuthMethod == litellmauth.AuthMethodPKCE {
				client, err := deps.newClient(credential.BaseURL, global.timeout, global.allowInsecureHTTP)
				if err != nil {
					fmt.Fprintln(deps.stderr, "Server-side token was not revoked: client could not be created.")
				} else {
					ctx, cancel := context.WithTimeout(command.Context(), global.timeout)
					defer cancel()
					if err := client.RevokePKCE(ctx, credential); err != nil {
						return err
					}
				}
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
				if credential.RefreshToken == "" {
					return litellmauth.ErrCredentialStale
				}
				base := credential.BaseURL
				if issuer != nil {
					base = issuer.String()
				}
				client, err := deps.newClient(base, global.timeout, global.allowInsecureHTTP)
				if err != nil {
					return err
				}
				if credential, err = client.Refresh(command.Context(), credential); err != nil {
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
		return strings.Contains(value, credential.Key) ||
			(credential.RefreshToken != "" && strings.Contains(value, credential.RefreshToken))
	}
	if containsKey(credential.BaseURL) || containsKey(credential.UserID) ||
		containsKey(credential.TeamID) || containsKey(credential.TeamAlias) ||
		containsKey(string(credential.AuthMethod)) || containsKey(credential.TokenType) ||
		containsKey(credential.Issuer) || containsKey(credential.Subject) ||
		containsKey(credential.ClientID) || containsKey(credential.TokenEndpoint) ||
		containsKey(credential.RevocationEndpoint) || containsKey(credential.Resource) {
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
	case errors.Is(err, litellmauth.ErrRefreshRejected):
		fmt.Fprintln(output, "Refresh token was rejected; run litellm-auth login again.")
	case errors.Is(err, litellmauth.ErrLoopbackUnavailable):
		fmt.Fprintln(output, "Could not open a loopback callback port; use --flow device or --oidc-redirect-port.")
	case errors.Is(err, litellmauth.ErrOIDCDeviceUnsupported):
		fmt.Fprintln(output, litellmauth.ErrOIDCDeviceUnsupported)
	case errors.Is(err, litellmauth.ErrPKCEUnsupported):
		fmt.Fprintln(output, litellmauth.ErrPKCEUnsupported)
	case errors.Is(err, litellmauth.ErrPKCEDenied):
		fmt.Fprintln(output, litellmauth.ErrPKCEDenied)
	case errors.Is(err, litellmauth.ErrProxyUnavailable):
		fmt.Fprintln(output, litellmauth.ErrProxyUnavailable)
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
