package litellmauth

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

const maxCredentialKeyBytes = 1 << 20

// AuthMethod identifies how a credential was acquired.
type AuthMethod string

const (
	AuthMethodLiteLLMSSO  AuthMethod = "litellm-cli-sso"
	AuthMethodStatic      AuthMethod = "static"
	AuthMethodEnvironment AuthMethod = "env"
	AuthMethodFile        AuthMethod = "file"
	AuthMethodExec        AuthMethod = "exec"
	AuthMethodStdin       AuthMethod = "stdin"
	AuthMethodOIDC        AuthMethod = "oidc"
)

// Client authenticates with one normalized LiteLLM proxy base URL.
type Client struct {
	baseURL           string
	allowInsecureHTTP bool
	httpClient        *http.Client
	maxWait           time.Duration
	pollInterval      time.Duration
	requestTimeout    time.Duration
	now               func() time.Time
	wait              func(context.Context, time.Duration) error
}

// OIDCRefresh contains the secret and public data needed to refresh an OIDC credential.
type OIDCRefresh struct {
	Issuer        string   `json:"issuer"`
	TokenEndpoint string   `json:"token_endpoint"`
	ClientID      string   `json:"client_id"`
	RefreshToken  string   `json:"refresh_token"`
	Scopes        []string `json:"scopes"`
}

func (OIDCRefresh) String() string     { return "OIDC refresh credential" }
func (r OIDCRefresh) GoString() string { return r.String() }

func (r OIDCRefresh) validate() error {
	if len(r.Issuer) > maxCredentialKeyBytes || len(r.TokenEndpoint) > maxCredentialKeyBytes || len(r.ClientID) > maxCredentialKeyBytes || len(r.RefreshToken) > maxCredentialKeyBytes ||
		!validNativeOIDCString(r.ClientID) || r.RefreshToken == "" || containsKeySpaceOrControl(r.RefreshToken) {
		return ErrInvalidCredential
	}
	if !validOIDCIssuer(r.Issuer) {
		return ErrInvalidCredential
	}
	if _, err := normalizeOIDCURL(r.TokenEndpoint); err != nil {
		return ErrInvalidCredential
	}
	for _, scope := range r.Scopes {
		if !validNativeOIDCString(scope) {
			return ErrInvalidCredential
		}
	}
	return nil
}

// Session is a short-lived browser login session. Its polling secret is never
// exported or serialized.
type Session struct {
	// LoginID identifies the session to the proxy.
	LoginID string
	// UserCode is shown to the user while completing browser verification.
	UserCode string
	// VerificationURL is the browser URL for the login session.
	VerificationURL *url.URL
	// ExpiresIn is the maximum duration for completing the login session.
	ExpiresIn time.Duration

	pollSecret string
	expiresAt  time.Time
}

// String returns a secret-free session description.
func (s Session) String() string {
	return "LiteLLM login session"
}

// GoString returns a secret-free session description.
func (s Session) GoString() string { return s.String() }

// Team identifies a LiteLLM team available to a user.
type Team struct {
	// ID is the proxy's team identifier.
	ID string
	// Alias is the optional human-readable team name.
	Alias string
}

// PollStatus describes a single LiteLLM CLI SSO polling result.
type PollStatus string

const (
	// PollPending means browser verification is not complete.
	PollPending PollStatus = "pending"
	// PollReady means a credential is ready.
	PollReady PollStatus = "ready"
	// PollTeamSelection means the caller must choose a team.
	PollTeamSelection PollStatus = "team_selection"
)

// PollResult is the parsed result of one polling request.
type PollResult struct {
	// Status is the polling status.
	Status PollStatus
	// Credential is set when Status is PollReady.
	Credential *Credential
	// Teams is the proxy-provided set of teams.
	Teams []Team
	// RequiresTeamSelection reports whether the proxy requires a team choice.
	RequiresTeamSelection bool
}

// Credential is a LiteLLM API key and its non-secret metadata.
type Credential struct {
	// BaseURL is the normalized proxy URL that issued Key.
	BaseURL string `json:"base_url"`
	// Key is the bearer token returned by LiteLLM.
	Key string `json:"key"`
	// AuthMethod identifies how Key was acquired.
	AuthMethod AuthMethod `json:"auth_method,omitempty"`
	// TokenType is the authorization scheme; empty means Bearer for compatibility.
	TokenType string `json:"token_type,omitempty"`
	// Issuer is optional non-secret identity-provider metadata.
	Issuer string `json:"issuer,omitempty"`
	// Subject is optional non-secret subject metadata.
	Subject string `json:"subject,omitempty"`
	// Scopes contains optional non-secret OAuth scopes.
	Scopes []string `json:"scopes,omitempty"`
	// OIDCRefresh is the refresh material for an OIDC credential. It is never output as metadata.
	OIDCRefresh *OIDCRefresh `json:"oidc_refresh,omitempty"`
	// NonExpiring explicitly marks a credential without a known expiry.
	NonExpiring bool `json:"non_expiring,omitempty"`
	// UserID is the authenticated user's proxy identifier.
	UserID string `json:"user_id"`
	// TeamID is the selected team identifier, when one applies.
	TeamID string `json:"team_id"`
	// TeamAlias is the selected team's optional display name.
	TeamAlias string `json:"team_alias"`
	// Teams is the set of teams available during login.
	Teams []Team `json:"teams"`
	// AttributionMetadata contains scalar metadata supplied by LiteLLM.
	AttributionMetadata map[string]any `json:"attribution_metadata"`
	// IssuedAt is when the credential was received.
	IssuedAt time.Time `json:"issued_at"`
	// ExpiresAt is the credential expiry derived from the key or issue time.
	ExpiresAt time.Time `json:"expires_at"`
}

// String returns a secret-free credential description.
func (Credential) String() string { return "LiteLLM credential" }

// GoString returns a secret-free credential description.
func (c Credential) GoString() string { return c.String() }

// Clone returns an independent credential copy.
func (c Credential) Clone() Credential {
	cloned := c
	cloned.Scopes = append([]string(nil), c.Scopes...)
	if c.OIDCRefresh != nil {
		refresh := *c.OIDCRefresh
		refresh.Scopes = append([]string(nil), c.OIDCRefresh.Scopes...)
		cloned.OIDCRefresh = &refresh
	}
	cloned.Teams = append([]Team(nil), c.Teams...)
	if c.AttributionMetadata != nil {
		cloned.AttributionMetadata = make(map[string]any, len(c.AttributionMetadata))
		for key, value := range c.AttributionMetadata {
			cloned.AttributionMetadata[key] = value
		}
	}
	return cloned
}

// Validate checks token formatting and lifetime semantics without contacting a server.
func (c Credential) Validate() error {
	if len(c.Key) > maxCredentialKeyBytes ||
		c.AuthorizationHeader() == "" ||
		containsControl(c.BaseURL) ||
		containsControl(string(c.AuthMethod)) ||
		containsControl(c.Issuer) ||
		containsControl(c.Subject) ||
		containsControl(c.UserID) ||
		containsControl(c.TeamID) ||
		containsControl(c.TeamAlias) {
		return ErrInvalidCredential
	}
	for _, team := range c.Teams {
		if team.ID == "" || containsControl(team.ID) || containsControl(team.Alias) {
			return ErrInvalidCredential
		}
	}
	for _, scope := range c.Scopes {
		if scope == "" || containsControl(scope) {
			return ErrInvalidCredential
		}
	}
	if c.OIDCRefresh != nil {
		if c.AuthMethod != AuthMethodOIDC || c.OIDCRefresh.validate() != nil {
			return ErrInvalidCredential
		}
	} else if c.AuthMethod == AuthMethodOIDC {
		return ErrInvalidCredential
	}
	for key, value := range c.AttributionMetadata {
		if key == "" || containsControl(key) {
			return ErrInvalidCredential
		}
		switch typed := value.(type) {
		case string:
			if containsControl(typed) {
				return ErrInvalidCredential
			}
		case bool:
		case float64:
			if math.IsNaN(typed) || math.IsInf(typed, 0) {
				return ErrInvalidCredential
			}
		default:
			return ErrInvalidCredential
		}
	}
	if c.NonExpiring {
		if !c.ExpiresAt.IsZero() {
			return ErrInvalidCredential
		}
		if _, ok := jwtExpiry(c.Key); ok {
			return ErrInvalidCredential
		}
		return nil
	}
	if c.Expiry().IsZero() {
		return ErrCredentialExpiryUnknown
	}
	return nil
}

// UnmarshalJSON decodes a credential while rejecting invalid metadata.
func (c *Credential) UnmarshalJSON(data []byte) error {
	var decoded struct {
		BaseURL             string          `json:"base_url"`
		Key                 string          `json:"key"`
		AuthMethod          AuthMethod      `json:"auth_method"`
		TokenType           string          `json:"token_type"`
		Issuer              string          `json:"issuer"`
		Subject             string          `json:"subject"`
		Scopes              []string        `json:"scopes"`
		OIDCRefresh         *OIDCRefresh    `json:"oidc_refresh"`
		NonExpiring         bool            `json:"non_expiring"`
		UserID              string          `json:"user_id"`
		TeamID              string          `json:"team_id"`
		TeamAlias           string          `json:"team_alias"`
		Teams               []Team          `json:"teams"`
		AttributionMetadata json.RawMessage `json:"attribution_metadata"`
		IssuedAt            time.Time       `json:"issued_at"`
		ExpiresAt           time.Time       `json:"expires_at"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	if containsControl(string(decoded.AuthMethod)) ||
		containsControl(decoded.TokenType) ||
		containsControl(decoded.Issuer) ||
		containsControl(decoded.Subject) {
		return fmt.Errorf("%w: credential metadata contains control characters", ErrProtocol)
	}
	for _, scope := range decoded.Scopes {
		if containsControl(scope) {
			return fmt.Errorf("%w: credential scope contains control characters", ErrProtocol)
		}
	}
	var metadata map[string]any
	if decoded.AttributionMetadata != nil {
		if err := json.Unmarshal(decoded.AttributionMetadata, &metadata); err != nil || metadata == nil {
			return fmt.Errorf("%w: attribution metadata must be an object of scalar values", ErrProtocol)
		}
		for _, value := range metadata {
			switch value.(type) {
			case string, float64, bool:
			default:
				return fmt.Errorf("%w: attribution metadata must contain only scalar values", ErrProtocol)
			}
		}
	}
	*c = Credential{
		BaseURL:             decoded.BaseURL,
		Key:                 decoded.Key,
		AuthMethod:          decoded.AuthMethod,
		TokenType:           decoded.TokenType,
		Issuer:              decoded.Issuer,
		Subject:             decoded.Subject,
		Scopes:              append([]string(nil), decoded.Scopes...),
		OIDCRefresh:         decoded.OIDCRefresh,
		NonExpiring:         decoded.NonExpiring,
		UserID:              decoded.UserID,
		TeamID:              decoded.TeamID,
		TeamAlias:           decoded.TeamAlias,
		Teams:               decoded.Teams,
		AttributionMetadata: metadata,
		IssuedAt:            decoded.IssuedAt,
		ExpiresAt:           decoded.ExpiresAt,
	}
	c.ExpiresAt = c.Expiry()
	return nil
}

func containsControl(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}

// TeamSelector chooses one ID from the teams supplied by the proxy.
type TeamSelector func(context.Context, []Team) (string, error)

// EventKind identifies a login progress event.
type EventKind string

const (
	// EventPending reports a pending poll response.
	EventPending EventKind = "pending"
	// EventRetrying reports a retryable polling failure.
	EventRetrying EventKind = "retrying"
	// EventTeamsRequired reports that the proxy requires a team selection.
	EventTeamsRequired EventKind = "teams_required"
)

// Event reports login progress without exposing session secrets.
type Event struct {
	// Kind identifies the event.
	Kind EventKind
	// Attempt is the one-based polling attempt number.
	Attempt int
	// StatusCode is set for HTTP retry events.
	StatusCode int
	// Teams is set when a team selection is required.
	Teams []Team
	// Err is set for retry events.
	Err error
}

// AwaitOptions configures Client.Await.
type AwaitOptions struct {
	// TeamID selects an offered team without calling SelectTeam.
	TeamID string
	// SelectTeam chooses an offered team when TeamID is empty.
	SelectTeam TeamSelector
	// OnEvent receives safe login progress events.
	OnEvent func(Event)
}

// AuthenticateOptions configures Client.Authenticate.
type AuthenticateOptions struct {
	// OnSession receives the session before polling, typically to open its URL.
	OnSession func(context.Context, Session) error
	// TeamID selects an offered team without calling SelectTeam.
	TeamID string
	// SelectTeam chooses an offered team when TeamID is empty.
	SelectTeam TeamSelector
	// OnEvent receives safe login progress events.
	OnEvent func(Event)
}
