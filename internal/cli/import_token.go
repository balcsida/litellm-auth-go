package cli

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	litellmauth "github.com/balcsida/litellm-auth-go"
	"github.com/balcsida/litellm-auth-go/internal/baseurl"
	"github.com/spf13/cobra"
)

const maxStdinTokenBytes = 1 << 20

var cliEnvironmentNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type importTokenOptions struct {
	fromEnv     string
	fromFile    string
	fromStdin   bool
	fromExec    string
	execArgs    []string
	execEnv     []string
	expiresAt   string
	ttl         time.Duration
	ttlSet      bool
	nonExpiring bool
}

type safeCLIError struct {
	message string
}

func newSafeCLIError(message string) error {
	return &safeCLIError{message: message}
}

func (e *safeCLIError) Error() string {
	if e == nil {
		return "invalid CLI input"
	}
	return safe(e.message)
}

func (e *safeCLIError) GoString() string { return e.Error() }

func newImportTokenCommand(global *globalOptions, deps dependencies) *cobra.Command {
	var options importTokenOptions
	command := &cobra.Command{
		Use:   "import-token",
		Short: "Import a token from a safe external source",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return nil
			}
			return newSafeCLIError("import-token does not accept positional arguments")
		},
		RunE: func(command *cobra.Command, _ []string) error {
			rawBase := resolvedBaseURL(command, global.baseURL, deps.getenv, false)
			if rawBase == "" {
				return newSafeCLIError("import-token requires --base-url or LITELLM_PROXY_URL")
			}
			normalized, err := baseurl.Normalize(rawBase)
			if err != nil {
				return newSafeCLIError("invalid LiteLLM base URL")
			}
			if normalized.Scheme == "http" && !global.allowInsecureHTTP &&
				!strings.EqualFold(normalized.Hostname(), "localhost") &&
				!net.ParseIP(normalized.Hostname()).IsLoopback() {
				return newSafeCLIError("invalid LiteLLM base URL")
			}
			options.ttlSet = command.Flags().Changed("ttl")
			credential, err := acquireImportedCredential(command.Context(), normalized, options, deps)
			if err != nil {
				return err
			}
			credential.IssuedAt = deps.now()
			if !credential.Fresh(deps.now()) {
				return litellmauth.ErrCredentialStale
			}
			var output bytes.Buffer
			if err := printCredential(&output, "Imported credential", credential, deps.now()); err != nil {
				return err
			}
			store, err := deps.newStore(global.tokenFile)
			if err != nil {
				return err
			}
			if err := store.Save(command.Context(), credential); err != nil {
				return err
			}
			_, err = deps.stdout.Write(output.Bytes())
			return err
		},
	}
	command.Flags().StringVar(&options.fromEnv, "from-env", "", "read token from an environment variable")
	command.Flags().StringVar(&options.fromFile, "from-file", "", "read the current token from a file")
	command.Flags().BoolVar(&options.fromStdin, "from-stdin", false, "read token from stdin")
	command.Flags().StringVar(&options.fromExec, "from-exec", "", "execute a JSON credential helper")
	command.Flags().StringArrayVar(&options.execArgs, "exec-arg", nil, "credential helper argument; repeatable")
	command.Flags().StringArrayVar(&options.execEnv, "exec-env", nil, "environment variable exposed to helper; repeatable")
	command.Flags().StringVar(&options.expiresAt, "expires-at", "", "credential expiry in RFC3339")
	command.Flags().DurationVar(&options.ttl, "ttl", 0, "credential lifetime from now")
	command.Flags().BoolVar(&options.nonExpiring, "non-expiring", false, "explicitly mark the credential non-expiring")
	return command
}

func acquireImportedCredential(ctx context.Context, base *url.URL, options importTokenOptions, deps dependencies) (litellmauth.Credential, error) {
	sourceCount := 0
	if options.fromEnv != "" {
		sourceCount++
	}
	if options.fromFile != "" {
		sourceCount++
	}
	if options.fromStdin {
		sourceCount++
	}
	if options.fromExec != "" {
		sourceCount++
	}
	if sourceCount != 1 {
		return litellmauth.Credential{}, newSafeCLIError("select exactly one import-token source")
	}
	if options.fromExec == "" && (len(options.execArgs) != 0 || len(options.execEnv) != 0) {
		return litellmauth.Credential{}, newSafeCLIError("exec options require --from-exec")
	}

	if options.fromExec != "" {
		if options.expiresAt != "" || options.ttlSet || options.nonExpiring {
			return litellmauth.Credential{}, newSafeCLIError("exec helper controls credential lifetime")
		}
		source, err := litellmauth.NewExecSource(options.fromExec, options.execArgs, litellmauth.ExecSourceConfig{
			BaseURL:    base.String(),
			AllowedEnv: append([]string(nil), options.execEnv...),
		})
		if err != nil {
			return litellmauth.Credential{}, err
		}
		return source.Credential(ctx)
	}

	config, err := importedSourceConfig(base.String(), options, deps.now())
	if err != nil {
		return litellmauth.Credential{}, err
	}

	switch {
	case options.fromEnv != "":
		if !cliEnvironmentNamePattern.MatchString(options.fromEnv) {
			return litellmauth.Credential{}, newSafeCLIError("invalid environment variable name")
		}
		key := deps.getenv(options.fromEnv)
		if key == "" {
			return litellmauth.Credential{}, litellmauth.ErrSourceUnavailable
		}
		config.AuthMethod = litellmauth.AuthMethodEnvironment
		source, err := litellmauth.NewStaticSource(key, config)
		if err != nil {
			return litellmauth.Credential{}, err
		}
		return source.Credential(ctx)
	case options.fromFile != "":
		source, err := litellmauth.NewTokenFileSource(options.fromFile, config)
		if err != nil {
			return litellmauth.Credential{}, err
		}
		return source.Credential(ctx)
	case options.fromStdin:
		key, err := readTokenFromStdin(ctx, deps.stdin)
		if err != nil {
			return litellmauth.Credential{}, err
		}
		config.AuthMethod = litellmauth.AuthMethodStdin
		source, err := litellmauth.NewStaticSource(key, config)
		if err != nil {
			return litellmauth.Credential{}, err
		}
		return source.Credential(ctx)
	default:
		return litellmauth.Credential{}, newSafeCLIError("select exactly one import-token source")
	}
}

func importedSourceConfig(base string, options importTokenOptions, now time.Time) (litellmauth.SourceConfig, error) {
	lifetimeCount := 0
	if options.expiresAt != "" {
		lifetimeCount++
	}
	if options.ttlSet {
		lifetimeCount++
	}
	if options.nonExpiring {
		lifetimeCount++
	}
	if lifetimeCount > 1 {
		return litellmauth.SourceConfig{}, newSafeCLIError("select at most one credential lifetime")
	}
	if options.ttlSet && options.ttl <= 0 {
		return litellmauth.SourceConfig{}, newSafeCLIError("credential TTL must be positive")
	}

	config := litellmauth.SourceConfig{
		BaseURL:     base,
		NonExpiring: options.nonExpiring,
	}
	if options.expiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, options.expiresAt)
		if err != nil {
			return litellmauth.SourceConfig{}, newSafeCLIError("invalid credential expiry")
		}
		config.ExpiresAt = expiresAt
	}
	if options.ttlSet {
		config.ExpiresAt = now.Add(options.ttl)
	}
	return config, nil
}

func readTokenFromStdin(ctx context.Context, input io.Reader) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if input == nil {
		return "", litellmauth.ErrSourceUnavailable
	}
	type result struct {
		data []byte
		err  error
	}
	results := make(chan result, 1)
	go func() {
		data, err := io.ReadAll(io.LimitReader(input, maxStdinTokenBytes+1))
		results <- result{data: data, err: err}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case result := <-results:
		if result.err != nil || len(result.data) > maxStdinTokenBytes {
			return "", litellmauth.ErrSourceOutput
		}
		key := strings.TrimSuffix(string(result.data), "\n")
		key = strings.TrimSuffix(key, "\r")
		if key == "" {
			return "", litellmauth.ErrSourceUnavailable
		}
		return key, nil
	}
}
