package litellmauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
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

// UnmarshalJSON decodes a credential while rejecting invalid metadata.
func (c *Credential) UnmarshalJSON(data []byte) error {
	var decoded struct {
		BaseURL             string          `json:"base_url"`
		Key                 string          `json:"key"`
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
