package litellmauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	baseURL           string
	allowInsecureHTTP bool
	httpClient        *http.Client
	maxWait           time.Duration
	pollInterval      time.Duration
	requestTimeout    time.Duration
}

type Session struct {
	LoginID         string
	UserCode        string
	VerificationURL *url.URL
	ExpiresIn       time.Duration

	pollSecret string
	expiresAt  time.Time
}

func (s Session) String() string {
	return "LiteLLM login session"
}

func (s Session) GoString() string { return s.String() }

type Team struct {
	ID    string
	Alias string
}

type PollStatus string

const (
	PollPending       PollStatus = "pending"
	PollReady         PollStatus = "ready"
	PollTeamSelection PollStatus = "team_selection"
)

type PollResult struct {
	Status                PollStatus
	Credential            *Credential
	Teams                 []Team
	RequiresTeamSelection bool
}

type Credential struct {
	BaseURL             string         `json:"base_url"`
	Key                 string         `json:"key"`
	UserID              string         `json:"user_id"`
	TeamID              string         `json:"team_id"`
	TeamAlias           string         `json:"team_alias"`
	Teams               []Team         `json:"teams"`
	AttributionMetadata map[string]any `json:"attribution_metadata"`
	IssuedAt            time.Time      `json:"issued_at"`
	ExpiresAt           time.Time      `json:"expires_at"`
}

func (c *Credential) UnmarshalJSON(data []byte) error {
	type credential Credential
	var decoded credential
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	for _, value := range decoded.AttributionMetadata {
		switch value.(type) {
		case string, float64, bool:
		default:
			return fmt.Errorf("%w: attribution metadata must contain only scalar values", ErrProtocol)
		}
	}
	*c = Credential(decoded)
	return nil
}

type TeamSelector func(context.Context, []Team) (string, error)

type EventKind string

const (
	EventPending       EventKind = "pending"
	EventRetrying      EventKind = "retrying"
	EventTeamsRequired EventKind = "teams_required"
)

type Event struct {
	Kind       EventKind
	Attempt    int
	StatusCode int
	Teams      []Team
	Err        error
}

type AwaitOptions struct {
	TeamID     string
	SelectTeam TeamSelector
	OnEvent    func(Event)
}

type AuthenticateOptions struct {
	OnSession  func(context.Context, Session) error
	TeamID     string
	SelectTeam TeamSelector
	OnEvent    func(Event)
}
