package litellmauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode"
)

var errPollRedirect = errors.New("LiteLLM CLI SSO poll redirect")

type pollResponse struct {
	Status                string          `json:"status"`
	Key                   string          `json:"key"`
	UserID                string          `json:"user_id"`
	TeamID                string          `json:"team_id"`
	RequiresTeamSelection json.RawMessage `json:"requires_team_selection"`
	TeamDetails           json.RawMessage `json:"team_details"`
	Teams                 json.RawMessage `json:"teams"`
	AttributionMetadata   json.RawMessage `json:"attribution_metadata"`
}

func (c *Client) PollOnce(ctx context.Context, session Session, teamID string) (PollResult, error) {
	if session.LoginID == "" || session.pollSecret == "" {
		return PollResult{}, ErrProtocol
	}
	pollURL := c.pollURL(session.LoginID, teamID)
	requestURL := pollURL.String()
	if containsPollSecret(requestURL, pollURL, session.pollSecret) {
		return PollResult{}, ErrProtocol
	}
	ctx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return PollResult{}, fmt.Errorf("LiteLLM CLI SSO poll request to %s failed", requestURL)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-LiteLLM-CLI-Poll-Secret", session.pollSecret)

	client := *c.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errPollRedirect }
	response, err := client.Do(req)
	if err != nil {
		if errors.Is(err, errPollRedirect) {
			return PollResult{}, errors.New("LiteLLM CLI SSO poll: redirects are not allowed")
		}
		if ctx.Err() != nil {
			return PollResult{}, fmt.Errorf("LiteLLM CLI SSO poll request to %s: %w", requestURL, ctx.Err())
		}
		return PollResult{}, fmt.Errorf("LiteLLM CLI SSO poll request to %s failed", requestURL)
	}
	defer response.Body.Close()

	body, detail, oversized, readErr := readStartResponse(response)
	detail = strings.ReplaceAll(detail, session.pollSecret, "[redacted]")
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return PollResult{}, pollHTTPError(response, body, oversized || readErr != nil, session.pollSecret)
	}
	if readErr != nil {
		return PollResult{}, protocolReadError("poll", readErr)
	}
	if oversized || responseContentType(response) != "application/json" {
		return PollResult{}, protocolError(detail)
	}

	var decoded pollResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return PollResult{}, protocolError(detail)
	}
	switch decoded.Status {
	case string(PollPending):
		return PollResult{Status: PollPending}, nil
	case string(PollReady):
		return c.readyPollResult(decoded)
	default:
		return PollResult{}, protocolError(detail)
	}
}

func pollHTTPError(response *http.Response, body []byte, oversized bool, secret string) error {
	err := &HTTPError{
		Op:           "poll",
		StatusCode:   response.StatusCode,
		Retryable:    response.StatusCode == http.StatusTooManyRequests || (response.StatusCode >= http.StatusInternalServerError && response.StatusCode < 600),
		loginExpired: response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusNotFound,
		retryAfter:   response.Header.Get("Retry-After"),
	}
	if !oversized && responseContentType(response) == "application/json" {
		err.Detail = pollErrorDetail(body, secret)
	}
	return err
}

func pollErrorDetail(body []byte, secret string) string {
	var decoded struct {
		Detail json.RawMessage `json:"detail"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || len(decoded.Detail) == 0 || string(decoded.Detail) == "null" {
		return ""
	}
	var detail string
	if err := json.Unmarshal(decoded.Detail, &detail); err != nil {
		return ""
	}
	detail = strings.ReplaceAll(detail, secret, "[redacted]")
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, detail)
}

func (c *Client) readyPollResult(decoded pollResponse) (PollResult, error) {
	requiresSelection, err := pollRequiresSelection(decoded.RequiresTeamSelection)
	if err != nil || (requiresSelection && decoded.Key != "") || (!requiresSelection && decoded.Key == "") || containsKeySpaceOrControl(decoded.Key) {
		return PollResult{}, ErrProtocol
	}
	teams, err := normalizePollTeams(decoded.TeamDetails, decoded.Teams)
	if err != nil {
		return PollResult{}, ErrProtocol
	}
	if !requiresSelection && decoded.TeamID == "" && len(teams) > 1 {
		return PollResult{}, ErrProtocol
	}
	if requiresSelection {
		if len(teams) == 0 {
			return PollResult{}, ErrProtocol
		}
		return PollResult{Status: PollTeamSelection, Teams: teams, RequiresTeamSelection: true}, nil
	}

	credential, err := pollCredential(decoded)
	if err != nil {
		return PollResult{}, protocolError("credential")
	}
	credential.BaseURL = c.baseURL
	credential.IssuedAt = c.now()
	credential.Teams = teams
	if credential.TeamID == "" && len(teams) == 1 {
		credential.TeamID = teams[0].ID
	}
	for _, team := range teams {
		if team.ID == credential.TeamID {
			credential.TeamAlias = team.Alias
			return PollResult{Status: PollReady, Credential: &credential, Teams: teams}, nil
		}
	}
	if credential.TeamID != "" {
		return PollResult{}, ErrProtocol
	}
	return PollResult{Status: PollReady, Credential: &credential, Teams: teams}, nil
}

func pollRequiresSelection(raw json.RawMessage) (bool, error) {
	if raw == nil {
		return false, nil
	}
	if string(raw) == "null" {
		return false, ErrProtocol
	}
	var requires bool
	if err := json.Unmarshal(raw, &requires); err != nil {
		return false, err
	}
	return requires, nil
}

func containsKeySpaceOrControl(key string) bool {
	return strings.IndexFunc(key, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0
}

func pollCredential(decoded pollResponse) (Credential, error) {
	raw, err := json.Marshal(struct {
		Key                 string          `json:"key"`
		UserID              string          `json:"user_id"`
		TeamID              string          `json:"team_id"`
		AttributionMetadata json.RawMessage `json:"attribution_metadata,omitempty"`
	}{decoded.Key, decoded.UserID, decoded.TeamID, decoded.AttributionMetadata})
	if err != nil {
		return Credential{}, err
	}
	var credential Credential
	if err := json.Unmarshal(raw, &credential); err != nil {
		return Credential{}, err
	}
	return credential, nil
}

type pollTeam struct {
	TeamID    string `json:"team_id"`
	ID        string `json:"id"`
	TeamAlias string `json:"team_alias"`
	Alias     string `json:"alias"`
}

func normalizePollTeams(detailsRaw, teamsRaw json.RawMessage) ([]Team, error) {
	teams := make([]Team, 0)
	byID := make(map[string]int)
	add := func(team Team, detail bool) error {
		if team.ID == "" {
			return ErrProtocol
		}
		if index, ok := byID[team.ID]; ok {
			if detail && teams[index].Alias == "" {
				teams[index].Alias = team.Alias
			}
			return nil
		}
		byID[team.ID] = len(teams)
		teams = append(teams, team)
		return nil
	}
	if err := addPollDetails(detailsRaw, add); err != nil {
		return nil, err
	}
	if err := addPollTeams(teamsRaw, add); err != nil {
		return nil, err
	}
	return teams, nil
}

func addPollDetails(raw json.RawMessage, add func(Team, bool) error) error {
	if raw == nil {
		return nil
	}
	if string(raw) == "null" {
		return ErrProtocol
	}
	var details []pollTeam
	if err := json.Unmarshal(raw, &details); err != nil {
		return err
	}
	for _, detail := range details {
		id := detail.TeamID
		if id == "" {
			id = detail.ID
		}
		alias := detail.TeamAlias
		if alias == "" {
			alias = detail.Alias
		}
		if err := add(Team{ID: id, Alias: alias}, true); err != nil {
			return err
		}
	}
	return nil
}

func addPollTeams(raw json.RawMessage, add func(Team, bool) error) error {
	if raw == nil {
		return nil
	}
	if string(raw) == "null" {
		return ErrProtocol
	}
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil {
		return err
	}
	for _, value := range values {
		var id string
		if err := json.Unmarshal(value, &id); err == nil {
			if err := add(Team{ID: id}, false); err != nil {
				return err
			}
			continue
		}
		var team pollTeam
		if err := json.Unmarshal(value, &team); err != nil {
			return err
		}
		id = team.TeamID
		if id == "" {
			id = team.ID
		}
		alias := team.TeamAlias
		if alias == "" {
			alias = team.Alias
		}
		if err := add(Team{ID: id, Alias: alias}, false); err != nil {
			return err
		}
	}
	return nil
}
