package litellmauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/balcsida/litellm-auth-go/internal/testserver"
)

func TestPollOnceSendsOneSafeRequest(t *testing.T) {
	secret := "poll-secret-abc"
	server := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/sso/cli/poll/login-1" || r.URL.Query().Get("team_id") != "team 1" {
			t.Fatalf("request = %s %s", r.Method, r.URL)
		}
		if got := r.Header.Get("X-LiteLLM-CLI-Poll-Secret"); got != secret {
			t.Fatalf("poll secret header = %q", got)
		}
		if strings.Contains(r.URL.String(), secret) || r.Header.Get("Accept") != "application/json" {
			t.Fatalf("unsafe request = %s, Accept=%q", r.URL, r.Header.Get("Accept"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"pending"}`)
	}))
	defer server.Close()

	client := pollClient(t, server.URL)
	result, err := client.PollOnce(context.Background(), pollSession(secret), "team 1")
	if err != nil || result.Status != PollPending || len(server.Requests()) != 1 {
		t.Fatalf("PollOnce() = %#v, %v; requests = %d", result, err, len(server.Requests()))
	}
}

func TestPollOnceRejectsPollSecretInConstructedURL(t *testing.T) {
	secret := "poll-secret-abc"
	for _, test := range []struct {
		name    string
		session Session
		teamID  string
	}{
		{name: "login ID", session: Session{LoginID: "prefix-" + secret, pollSecret: secret}},
		{name: "team ID", session: pollSession(secret), teamID: "prefix-" + secret},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client, err := New("https://gateway.example.com", WithHTTPClient(&http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return nil, errors.New("must not send")
			})}))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			_, err = client.PollOnce(context.Background(), test.session, test.teamID)
			if !errors.Is(err, ErrProtocol) || calls != 0 {
				t.Fatalf("PollOnce() error = %v, calls = %d", err, calls)
			}
			for _, rendered := range []string{err.Error(), fmt.Sprintf("%#v", err)} {
				if strings.Contains(rendered, secret) {
					t.Fatalf("PollOnce() leaked poll secret: %q", rendered)
				}
			}
		})
	}
}

func TestPollOnceParsesReadyCredentialAndTeams(t *testing.T) {
	client := pollClient(t, `{"status":"ready","key":"sk-key","user_id":"user-1","team_id":"team-2","team_details":[{"team_id":"team-1","team_alias":"First"},{"id":"team-2","team_alias":"Second"}],"teams":["team-2","team-3"],"attribution_metadata":{"department":"Engineering","active":true,"score":1}}`)
	clock := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	client.now = func() time.Time { return clock }

	result, err := client.PollOnce(context.Background(), pollSession("secret"), "")
	if err != nil || result.Status != PollReady || result.Credential == nil {
		t.Fatalf("PollOnce() = %#v, %v", result, err)
	}
	credential := result.Credential
	if credential.BaseURL != client.baseURL || credential.Key != "sk-key" || credential.UserID != "user-1" || credential.TeamID != "team-2" || credential.TeamAlias != "Second" || !credential.IssuedAt.Equal(clock) {
		t.Fatalf("credential = %#v", credential)
	}
	if got, want := credential.Teams, []Team{{ID: "team-1", Alias: "First"}, {ID: "team-2", Alias: "Second"}, {ID: "team-3"}}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("teams = %#v, want %#v", got, want)
	}
	if got := credential.AttributionMetadata; got["department"] != "Engineering" || got["active"] != true || got["score"] != float64(1) {
		t.Fatalf("metadata = %#v", got)
	}
}

func TestPollOnceNormalizesTeamsAndSelection(t *testing.T) {
	client := pollClient(t, `{"status":"ready","requires_team_selection":true,"team_details":[{"team_id":"team-1"},{"id":"team-1","team_alias":"Preferred"},{"id":"team-2","alias":"Second"}],"teams":[{"id":"team-2","alias":"Ignored"},"team-3","team-1"]}`)

	result, err := client.PollOnce(context.Background(), pollSession("secret"), "")
	if err != nil || result.Status != PollTeamSelection || !result.RequiresTeamSelection || result.Credential != nil {
		t.Fatalf("PollOnce() = %#v, %v", result, err)
	}
	if got, want := result.Teams, []Team{{ID: "team-1", Alias: "Preferred"}, {ID: "team-2", Alias: "Second"}, {ID: "team-3"}}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("teams = %#v, want %#v", got, want)
	}
}

func TestPollOnceAssignsOnlyTeamAndRejectsInvalidReadyShapes(t *testing.T) {
	for _, test := range []struct {
		name    string
		body    string
		wantID  string
		wantErr bool
	}{
		{name: "only team", body: `{"status":"ready","key":"sk-key","teams":["team-1"]}`, wantID: "team-1"},
		{name: "key and selection", body: `{"status":"ready","key":"sk-key","requires_team_selection":true,"teams":["team-1"]}`, wantErr: true},
		{name: "selection no teams", body: `{"status":"ready","requires_team_selection":true}`, wantErr: true},
		{name: "neither", body: `{"status":"ready"}`, wantErr: true},
		{name: "team mismatch", body: `{"status":"ready","key":"sk-key","team_id":"team-2","teams":["team-1"]}`, wantErr: true},
		{name: "multiple teams without team ID", body: `{"status":"ready","key":"sk-key","teams":["team-1","team-2"]}`, wantErr: true},
		{name: "key unicode whitespace", body: `{"status":"ready","key":"sk-key\u00a0"}`, wantErr: true},
		{name: "key control", body: `{"status":"ready","key":"sk-key\u0000"}`, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := pollClient(t, test.body)
			result, err := client.PollOnce(context.Background(), pollSession("secret"), "")
			if test.wantErr {
				if !errors.Is(err, ErrProtocol) {
					t.Fatalf("PollOnce() error = %v, want ErrProtocol", err)
				}
				return
			}
			if err != nil || result.Credential == nil || result.Credential.TeamID != test.wantID {
				t.Fatalf("PollOnce() = %#v, %v", result, err)
			}
		})
	}
}

func TestPollOnceRejectsInvalidSessionAndMetadata(t *testing.T) {
	client := pollClient(t, `{"status":"ready","key":"sk-key"}`)
	for _, session := range []Session{{pollSecret: "secret"}, {LoginID: "login-1"}} {
		if _, err := client.PollOnce(context.Background(), session, ""); !errors.Is(err, ErrProtocol) {
			t.Fatalf("PollOnce(%#v) error = %v, want ErrProtocol", session, err)
		}
	}
	for _, body := range []string{
		`{"status":"ready","key":"sk-key","attribution_metadata":null}`,
		`{"status":"ready","key":"sk-key","attribution_metadata":{"nested":{"bad":true}}}`,
		`{"status":"ready","key":"sk-key","attribution_metadata":{"list":["bad"]}}`,
	} {
		if _, err := pollClient(t, body).PollOnce(context.Background(), pollSession("secret"), ""); !errors.Is(err, ErrProtocol) {
			t.Fatalf("PollOnce(%s) error = %v, want ErrProtocol", body, err)
		}
	}
}

func TestPollOnceClassifiesHTTPResponsesAndSanitizesDetail(t *testing.T) {
	secret := "poll-secret-abc"
	for _, test := range []struct {
		status    int
		retryable bool
		expired   bool
	}{
		{http.StatusBadRequest, false, true},
		{http.StatusUnauthorized, false, false},
		{http.StatusForbidden, false, false},
		{http.StatusNotFound, false, true},
		{http.StatusConflict, false, false},
		{http.StatusTooManyRequests, true, false},
		{http.StatusInternalServerError, true, false},
		{http.StatusBadGateway, true, false},
		{http.StatusServiceUnavailable, true, false},
		{http.StatusGatewayTimeout, true, false},
	} {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			server := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "7")
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, `{"detail":"cache\n`+secret+`"}`)
			}))
			defer server.Close()
			err := pollError(t, pollClient(t, server.URL), pollSession(secret))
			var httpErr *HTTPError
			if !errors.As(err, &httpErr) || httpErr.StatusCode != test.status || httpErr.Retryable != test.retryable || strings.Contains(httpErr.Detail, secret) || strings.ContainsAny(httpErr.Detail, "\n\r") || httpErr.retryAfter != "7" {
				t.Fatalf("PollOnce() error = %#v", err)
			}
			if errors.Is(err, ErrLoginExpired) != test.expired {
				t.Fatalf("PollOnce() login expiry = %v, want %v", errors.Is(err, ErrLoginExpired), test.expired)
			}
			for _, rendered := range []string{err.Error(), fmt.Sprintf("%#v", err)} {
				if strings.Contains(rendered, secret) || strings.Contains(rendered, "cache") {
					t.Fatalf("rendered error leaked detail: %q", rendered)
				}
			}
		})
	}
}

func TestPollOnceClassifiesHTTPReadFailuresWithoutBodyDetails(t *testing.T) {
	secret := "poll-secret-abc"
	for _, test := range []struct {
		status    int
		retryable bool
		expired   bool
	}{
		{status: http.StatusNotFound, expired: true},
		{status: http.StatusServiceUnavailable, retryable: true},
	} {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			bodyErr := errors.New("partial " + secret)
			client, err := New("https://gateway.example.com", WithHTTPClient(&http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: test.status, Header: http.Header{"Content-Type": {"application/json"}}, Body: &errorBody{body: `{"detail":"` + secret + `"}`, err: bodyErr}, Request: req}, nil
			})}))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			err = pollError(t, client, pollSession(secret))
			var httpErr *HTTPError
			if !errors.As(err, &httpErr) || httpErr.Retryable != test.retryable || errors.Is(err, bodyErr) || errors.Is(err, ErrLoginExpired) != test.expired || httpErr.Detail != "" {
				t.Fatalf("PollOnce() error = %#v", err)
			}
			for _, rendered := range []string{err.Error(), fmt.Sprintf("%#v", err)} {
				if strings.Contains(rendered, secret) || strings.Contains(rendered, "partial") {
					t.Fatalf("PollOnce() leaked partial response: %q", rendered)
				}
			}
		})
	}
}

func TestPollOnceSanitizesProtocolDiagnostics(t *testing.T) {
	secret := "poll-secret-abc"
	server := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/"+secret)
		_, _ = io.WriteString(w, `{"status":"pending"}`)
	}))
	defer server.Close()

	_, err := pollClient(t, server.URL).PollOnce(context.Background(), pollSession(secret), "")
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("PollOnce() error = %v, want ErrProtocol", err)
	}
	for _, rendered := range []string{err.Error(), fmt.Sprintf("%#v", err)} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("PollOnce() leaked protocol diagnostic: %q", rendered)
		}
	}
}

func TestPollOnceRejectsMalformedResponsesAndReadErrorsSafely(t *testing.T) {
	for _, body := range []string{
		`{"status":"unknown"}`,
		`{"status":"pending"} {}`,
		strings.Repeat("x", maxStartResponseBytes+1),
	} {
		if _, err := pollClient(t, body).PollOnce(context.Background(), pollSession("secret"), ""); !errors.Is(err, ErrProtocol) {
			t.Fatalf("PollOnce(%q) error = %v, want ErrProtocol", body[:min(len(body), 20)], err)
		}
	}

	sentinel := errors.New("do-not-leak")
	client, err := New("https://gateway.example.com", WithHTTPClient(&http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: &errorBody{body: `{"status":"pending"}`, err: sentinel}, Request: req}, nil
	})}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := client.PollOnce(context.Background(), pollSession("secret"), ""); !errors.Is(err, ErrProtocol) || !errors.Is(err, sentinel) || strings.Contains(fmt.Sprint(err), "do-not-leak") {
		t.Fatalf("PollOnce() error = %v", err)
	}
}

func TestPollOnceRejectsRedirectAndHonorsContext(t *testing.T) {
	redirect := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/do-not-leak", http.StatusFound)
	}))
	defer redirect.Close()
	if _, err := pollClient(t, redirect.URL).PollOnce(context.Background(), pollSession("secret"), ""); err == nil || !strings.Contains(err.Error(), "redirect") || strings.Contains(err.Error(), "do-not-leak") {
		t.Fatalf("redirect error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := pollClient(t, `{"status":"pending"}`).PollOnce(ctx, pollSession("secret"), ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("PollOnce() context error = %v", err)
	}
}

func pollClient(t *testing.T, response string) *Client {
	t.Helper()
	if strings.HasPrefix(response, "http") {
		client, err := New(response)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		return client
	}
	server := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, response)
	}))
	t.Cleanup(server.Close)
	client, err := New(server.URL)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return client
}

func pollSession(secret string) Session { return Session{LoginID: "login-1", pollSecret: secret} }

func pollError(t *testing.T, client *Client, session Session) error {
	t.Helper()
	_, err := client.PollOnce(context.Background(), session, "")
	if err == nil {
		t.Fatal("PollOnce() error = nil")
	}
	return err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
