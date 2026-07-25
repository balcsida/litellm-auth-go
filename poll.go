package litellmauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"
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

// PollOnce obtains one polling result for session and an optional team ID.
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
			return PollResult{}, transportError{err: ctx.Err()}
		}
		return PollResult{}, transportError{err: err}
	}
	defer response.Body.Close()

	body, detail, oversized, readErr := readStartResponse(response)
	detail = safeHTTPErrorDetail(detail, session.pollSecret)
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return PollResult{}, pollHTTPError(response, body, oversized || readErr != nil, session.pollSecret)
	}
	if readErr != nil {
		if retryableTransportError(readErr) {
			return PollResult{}, transportError{err: readErr}
		}
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
		return c.readyPollResult(decoded, session.pollSecret)
	default:
		return PollResult{}, protocolError(detail)
	}
}

// Await polls session until it returns a credential or expires.
func (c *Client) Await(ctx context.Context, session Session, options AwaitOptions) (Credential, error) {
	if session.LoginID == "" || session.pollSecret == "" || session.expiresAt.IsZero() {
		return Credential{}, ErrProtocol
	}
	teamID := ""
	teamSelected := false
	for attempt := 1; ; attempt++ {
		now := c.now()
		if err := awaitDeadline(ctx, session, now); err != nil {
			return Credential{}, err
		}
		remaining := session.expiresAt.Sub(now)
		timeout := c.requestTimeout
		if remaining < timeout {
			timeout = remaining
		}
		requestCtx, cancel := context.WithTimeout(ctx, timeout)
		result, err := c.PollOnce(requestCtx, session, teamID)
		cancel()
		if deadlineErr := awaitDeadline(ctx, session, c.now()); deadlineErr != nil {
			return Credential{}, deadlineErr
		}
		if err != nil {
			if !retryablePollError(err) {
				return Credential{}, err
			}
			event := Event{Kind: EventRetrying, Attempt: attempt, Err: safeEventError(err)}
			var httpErr *HTTPError
			if errors.As(err, &httpErr) {
				event.StatusCode = httpErr.StatusCode
			}
			emitEvent(options.OnEvent, event)
			if err := c.awaitWait(ctx, session, retryDelay(err, c.now(), c.pollInterval)); err != nil {
				return Credential{}, err
			}
			continue
		}

		switch result.Status {
		case PollPending:
			emitEvent(options.OnEvent, Event{Kind: EventPending, Attempt: attempt})
			if err := c.awaitWait(ctx, session, c.pollInterval); err != nil {
				return Credential{}, err
			}
		case PollReady:
			if result.Credential == nil || (teamSelected && result.Credential.TeamID != teamID) {
				return Credential{}, ErrProtocol
			}
			return *result.Credential, nil
		case PollTeamSelection:
			if teamSelected {
				return Credential{}, ErrProtocol
			}
			teams := append([]Team(nil), result.Teams...)
			emitEvent(options.OnEvent, Event{Kind: EventTeamsRequired, Attempt: attempt, Teams: teams})
			now := c.now()
			if err := awaitDeadline(ctx, session, now); err != nil {
				return Credential{}, err
			}
			selected := options.TeamID
			if selected == "" {
				if options.SelectTeam == nil {
					return Credential{}, &TeamRequiredError{Teams: append([]Team(nil), teams...)}
				}
				selectorCtx, cancel := context.WithTimeout(ctx, session.expiresAt.Sub(now))
				var selectErr error
				selected, selectErr = options.SelectTeam(selectorCtx, append([]Team(nil), teams...))
				selectorDeadlineErr := selectorCtx.Err()
				cancel()
				if err := awaitDeadline(ctx, session, c.now()); err != nil {
					return Credential{}, err
				}
				if errors.Is(selectorDeadlineErr, context.DeadlineExceeded) {
					return Credential{}, &LoginTimeoutError{}
				}
				if selectErr != nil {
					return Credential{}, selectErr
				}
			}
			if !offeredTeam(selected, teams) {
				return Credential{}, ErrProtocol
			}
			teamID, teamSelected = selected, true
		default:
			return Credential{}, ErrProtocol
		}
	}
}

// Authenticate starts a session, invokes OnSession, then waits for a credential.
func (c *Client) Authenticate(ctx context.Context, options AuthenticateOptions) (Credential, error) {
	session, err := c.Start(ctx)
	if err != nil {
		return Credential{}, err
	}
	if options.OnSession != nil {
		sessionCtx, cancel := context.WithDeadline(ctx, session.expiresAt)
		callbackErr := options.OnSession(sessionCtx, session)
		cancel()
		if callbackErr != nil {
			if deadlineErr := awaitDeadline(ctx, session, c.now()); deadlineErr != nil {
				return Credential{}, deadlineErr
			}
			return Credential{}, callbackErr
		}
	}
	return c.Await(ctx, session, AwaitOptions{
		TeamID:     options.TeamID,
		SelectTeam: options.SelectTeam,
		OnEvent:    options.OnEvent,
	})
}

func (c *Client) awaitWait(ctx context.Context, session Session, delay time.Duration) error {
	now := c.now()
	if err := awaitDeadline(ctx, session, now); err != nil {
		return err
	}
	if remaining := session.expiresAt.Sub(now); delay > remaining {
		delay = remaining
	}
	if err := c.wait(ctx, delay); err != nil {
		if deadlineErr := awaitDeadline(ctx, session, c.now()); deadlineErr != nil {
			return deadlineErr
		}
		return err
	}
	return nil
}

func awaitDeadline(ctx context.Context, session Session, now time.Time) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return context.Canceled
	}
	expired := !now.Before(session.expiresAt)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		if deadline, ok := ctx.Deadline(); expired && ok && !deadline.Before(session.expiresAt) {
			return &LoginTimeoutError{}
		}
		return &LoginTimeoutError{callerDeadline: true}
	}
	if expired {
		return &LoginTimeoutError{}
	}
	return nil
}

func defaultWait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func retryablePollError(err error) bool {
	if errors.Is(err, ErrProtocol) {
		return false
	}
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.Retryable
	}
	if !errors.As(err, new(transportError)) {
		return false
	}
	return retryableTransportError(err)
}

func retryableTransportError(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsTimeout || dnsErr.IsTemporary
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func retryDelay(err error, now time.Time, fallback time.Duration) time.Duration {
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.retryAfter == "" {
		return fallback
	}
	if strings.IndexFunc(httpErr.retryAfter, func(r rune) bool { return r < '0' || r > '9' }) == -1 {
		if seconds, parseErr := strconv.ParseInt(httpErr.retryAfter, 10, 64); parseErr == nil && seconds > 0 {
			if seconds > int64(time.Duration(1<<63-1)/time.Second) {
				return time.Duration(1<<63 - 1)
			}
			return time.Duration(seconds) * time.Second
		}
	}
	if date, parseErr := http.ParseTime(httpErr.retryAfter); parseErr == nil {
		if delay := date.Sub(now); delay > 0 {
			return delay
		}
	}
	return fallback
}

func offeredTeam(selected string, teams []Team) bool {
	if selected == "" {
		return false
	}
	for _, team := range teams {
		if team.ID == selected {
			return true
		}
	}
	return false
}

func emitEvent(callback func(Event), event Event) {
	if callback == nil {
		return
	}
	event.Teams = append([]Team(nil), event.Teams...)
	callback(event)
}

func safeEventError(err error) error {
	return errors.New(err.Error())
}

type transportError struct {
	err error
}

func (transportError) Error() string { return "LiteLLM CLI SSO poll request failed" }

func (e transportError) GoString() string { return e.Error() }

func (e transportError) Unwrap() error { return e.err }

func pollHTTPError(response *http.Response, body []byte, oversized bool, secret string) error {
	err := &HTTPError{
		Op:           "poll",
		StatusCode:   response.StatusCode,
		Retryable:    response.StatusCode == http.StatusTooManyRequests || (response.StatusCode >= http.StatusInternalServerError && response.StatusCode < 600),
		loginExpired: response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusNotFound,
		retryAfter:   response.Header.Get("Retry-After"),
	}
	if !oversized && responseContentType(response) == "application/json" {
		err.Detail = responseErrorDetail(body, secret)
	}
	return err
}

func (c *Client) readyPollResult(decoded pollResponse, pollSecret string) (PollResult, error) {
	requiresSelection, err := pollRequiresSelection(decoded.RequiresTeamSelection)
	if err != nil || (requiresSelection && decoded.Key != "") || (!requiresSelection && decoded.Key == "") || containsKeySpaceOrControl(decoded.Key) {
		return PollResult{}, ErrProtocol
	}
	if stringContainsSecret(decoded.Key, pollSecret) {
		return PollResult{}, ErrProtocol
	}
	teams, err := normalizePollTeams(decoded.TeamDetails, decoded.Teams)
	if err != nil {
		return PollResult{}, ErrProtocol
	}
	if teamsContainSecret(teams, pollSecret, decoded.Key) {
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
	credential.AuthMethod = AuthMethodLiteLLMSSO
	credential.TokenType = "Bearer"
	credential.IssuedAt = c.now()
	credential.ExpiresAt = credential.Expiry()
	credential.Teams = teams
	if credential.TeamID == "" && len(teams) == 1 {
		credential.TeamID = teams[0].ID
	}
	if credentialMetadataContainsSecret(credential, pollSecret, credential.Key) {
		return PollResult{}, ErrProtocol
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

func credentialMetadataContainsSecret(credential Credential, secrets ...string) bool {
	if stringContainsSecret(credential.UserID, secrets...) ||
		stringContainsSecret(credential.TeamID, secrets...) ||
		stringContainsSecret(credential.TeamAlias, secrets...) ||
		teamsContainSecret(credential.Teams, secrets...) {
		return true
	}
	for name, value := range credential.AttributionMetadata {
		if stringContainsSecret(name, secrets...) {
			return true
		}
		if text, ok := value.(string); ok && stringContainsSecret(text, secrets...) {
			return true
		}
	}
	return false
}

func teamsContainSecret(teams []Team, secrets ...string) bool {
	for _, team := range teams {
		if stringContainsSecret(team.ID, secrets...) || stringContainsSecret(team.Alias, secrets...) {
			return true
		}
	}
	return false
}

func stringContainsSecret(value string, secrets ...string) bool {
	for _, secret := range secrets {
		if secret != "" && strings.Contains(value, secret) {
			return true
		}
	}
	return false
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
