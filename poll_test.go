package litellmauth

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
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

func TestAwaitPollsPendingThenReturnsReadyWithoutReusingSession(t *testing.T) {
	clock := newAwaitClock(10 * time.Second)
	attempts := 0
	client := awaitClient(t, clock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		if attempts == 1 {
			_, _ = io.WriteString(w, `{"status":"pending"}`)
			return
		}
		if attempts > 2 {
			t.Fatal("Await reused a completed session")
		}
		_, _ = io.WriteString(w, `{"status":"ready","key":"sk-key"}`)
	}))
	var events []Event

	credential, err := client.Await(context.Background(), awaitSession(clock), AwaitOptions{
		OnEvent: func(event Event) { events = append(events, event) },
	})
	if err != nil || credential.Key != "sk-key" || attempts != 2 {
		t.Fatalf("Await() = %#v, %v; attempts = %d", credential, err, attempts)
	}
	if len(events) != 1 || events[0].Kind != EventPending || events[0].Attempt != 1 {
		t.Fatalf("events = %#v", events)
	}
	if got := clock.waits; len(got) != 1 || got[0] != 2*time.Second {
		t.Fatalf("waits = %v", got)
	}
}

func TestAwaitRetriesTransientTransportErrorWithSafeEvent(t *testing.T) {
	clock := newAwaitClock(10 * time.Second)
	attempts := 0
	secret := "transport-secret"
	client, err := New("https://gateway.example.com", WithHTTPClient(&http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			return nil, &url.Error{Op: "Get", URL: req.URL.String(), Err: fmt.Errorf("%s: %w", secret, syscall.ECONNRESET)}
		}
		return pollResponseFor(req, http.StatusOK, `{"status":"ready","key":"sk-key"}`, nil), nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	client.now, client.wait = clock.Now, clock.Wait
	var event Event

	credential, err := client.Await(context.Background(), awaitSession(clock), AwaitOptions{
		OnEvent: func(got Event) { event = got },
	})
	if err != nil || credential.Key != "sk-key" || attempts != 2 {
		t.Fatalf("Await() = %#v, %v; attempts = %d", credential, err, attempts)
	}
	if event.Kind != EventRetrying || event.Attempt != 1 || event.StatusCode != 0 || event.Err == nil || strings.Contains(fmt.Sprintf("%#v", event.Err), secret) {
		t.Fatalf("event = %#v", event)
	}
}

func TestAwaitUsesRetryAfterSecondsAndHTTPDates(t *testing.T) {
	start := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name       string
		retryAfter string
		want       time.Duration
	}{
		{name: "seconds", retryAfter: "5", want: 5 * time.Second},
		{name: "HTTP date", retryAfter: start.Add(4 * time.Second).Format(http.TimeFormat), want: 4 * time.Second},
		{name: "zero", retryAfter: "0", want: 2 * time.Second},
		{name: "invalid", retryAfter: "later", want: 2 * time.Second},
		{name: "signed", retryAfter: "+5", want: 2 * time.Second},
		{name: "negative", retryAfter: "-1", want: 2 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := &awaitClock{now: start, lifetime: 10 * time.Second}
			attempts := 0
			client := awaitClient(t, clock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts++
				w.Header().Set("Content-Type", "application/json")
				if attempts == 1 {
					w.Header().Set("Retry-After", test.retryAfter)
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}
				_, _ = io.WriteString(w, `{"status":"ready","key":"sk-key"}`)
			}))
			var event Event

			if _, err := client.Await(context.Background(), awaitSession(clock), AwaitOptions{OnEvent: func(got Event) { event = got }}); err != nil {
				t.Fatalf("Await() error = %v", err)
			}
			if len(clock.waits) != 1 || clock.waits[0] != test.want {
				t.Fatalf("waits = %v, want %s", clock.waits, test.want)
			}
			if event.Kind != EventRetrying || event.Attempt != 1 || event.StatusCode != http.StatusTooManyRequests || event.Err == nil {
				t.Fatalf("event = %#v", event)
			}
		})
	}
}

func TestAwaitAvoidsBusyLoopForImmediateRetryAfter(t *testing.T) {
	start := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	for _, retryAfter := range []string{"0", start.Format(http.TimeFormat)} {
		t.Run(retryAfter, func(t *testing.T) {
			clock := &awaitClock{now: start, lifetime: 5 * time.Second}
			attempts := 0
			client := awaitClient(t, clock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts++
				w.Header().Set("Content-Type", "application/json")
				if attempts > 10 {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Retry-After", retryAfter)
				w.WriteHeader(http.StatusTooManyRequests)
			}))

			if _, err := client.Await(context.Background(), awaitSession(clock), AwaitOptions{}); !errors.Is(err, ErrLoginExpired) {
				t.Fatalf("Await() error = %v", err)
			}
			if got := clock.waits; fmt.Sprint(got) != fmt.Sprint([]time.Duration{2 * time.Second, 2 * time.Second, time.Second}) {
				t.Fatalf("waits = %v", got)
			}
			if attempts != 3 || !clock.Now().Equal(start.Add(5*time.Second)) {
				t.Fatalf("attempts = %d; clock = %s", attempts, clock.Now())
			}
		})
	}
}

func TestRetryDelayBoundsHugeSeconds(t *testing.T) {
	delay := retryDelay(&HTTPError{retryAfter: "9223372036854775807"}, time.Time{}, time.Second)
	if delay <= 0 {
		t.Fatalf("retryDelay() = %s", delay)
	}
}

func TestAwaitClampsRetryDelayAndRequestTimeoutToAbsoluteExpiry(t *testing.T) {
	clock := newAwaitClock(3 * time.Second)
	attempts := 0
	client, err := New("https://gateway.example.com", WithRequestTimeout(time.Minute), WithHTTPClient(&http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		attempts++
		if deadline, ok := r.Context().Deadline(); !ok || time.Until(deadline) > 3100*time.Millisecond {
			t.Fatalf("request deadline = %v, %v", deadline, ok)
		}
		return pollResponseFor(r, http.StatusServiceUnavailable, "", http.Header{"Retry-After": {"99"}}), nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	client.now, client.wait = clock.Now, clock.Wait
	session := awaitSession(clock)
	session.ExpiresIn = time.Hour

	_, err = client.Await(context.Background(), session, AwaitOptions{})
	var timeout *LoginTimeoutError
	if !errors.As(err, &timeout) || !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrLoginExpired) || attempts != 1 {
		t.Fatalf("Await() error = %#v; attempts = %d", err, attempts)
	}
	if len(clock.waits) != 1 || clock.waits[0] != 3*time.Second {
		t.Fatalf("waits = %v", clock.waits)
	}
}

func TestAwaitRetries5xxUntilSessionExpires(t *testing.T) {
	clock := newAwaitClock(5 * time.Second)
	attempts := 0
	client := awaitClient(t, clock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
	}))

	_, err := client.Await(context.Background(), awaitSession(clock), AwaitOptions{})
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrLoginExpired) || attempts != 3 {
		t.Fatalf("Await() error = %v; attempts = %d", err, attempts)
	}
	if got := clock.waits; fmt.Sprint(got) != fmt.Sprint([]time.Duration{2 * time.Second, 2 * time.Second, time.Second}) {
		t.Fatalf("waits = %v", got)
	}
}

func TestAwaitStopsOnPermanentHTTPAndProtocolErrors(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "forbidden", status: http.StatusForbidden, body: `{"detail":"denied"}`},
		{name: "malformed JSON", status: http.StatusOK, body: `{`},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := newAwaitClock(10 * time.Second)
			attempts := 0
			client := awaitClient(t, clock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts++
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			_, err := client.Await(context.Background(), awaitSession(clock), AwaitOptions{})
			if err == nil || attempts != 1 || len(clock.waits) != 0 {
				t.Fatalf("Await() error = %v; attempts = %d; waits = %v", err, attempts, clock.waits)
			}
		})
	}
}

func TestAwaitDistinguishesCancellationCallerDeadlineAndSessionExpiry(t *testing.T) {
	clock := newAwaitClock(10 * time.Second)
	client := awaitClient(t, clock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("unexpected request")
	}))

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Await(canceled, awaitSession(clock), AwaitOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Await() error = %v", err)
	}

	deadline, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	_, err := client.Await(deadline, awaitSession(clock), AwaitOptions{})
	var timeout *LoginTimeoutError
	if !errors.As(err, &timeout) || !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrLoginExpired) {
		t.Fatalf("caller deadline Await() error = %#v", err)
	}

	session := awaitSession(clock)
	session.expiresAt = clock.Now()
	_, err = client.Await(context.Background(), session, AwaitOptions{})
	if !errors.As(err, &timeout) || !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrLoginExpired) {
		t.Fatalf("expired Await() error = %#v", err)
	}
}

func TestAwaitRejectsReadyResponseCompletedAtSessionExpiry(t *testing.T) {
	clock := newAwaitClock(3 * time.Second)
	session := awaitSession(clock)
	client, err := New("https://gateway.example.com", WithHTTPClient(&http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		clock.now = session.expiresAt
		return pollResponseFor(req, http.StatusOK, `{"status":"ready","key":"sk-key"}`, nil), nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	client.now, client.wait = clock.Now, clock.Wait

	_, err = client.Await(context.Background(), session, AwaitOptions{})
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrLoginExpired) {
		t.Fatalf("Await() error = %#v", err)
	}
}

func TestAwaitUsesEarliestElapsedDeadlineIdentity(t *testing.T) {
	now := time.Now()
	for _, test := range []struct {
		name          string
		sessionExpiry time.Time
		callerExpiry  time.Time
		wantExpired   bool
	}{
		{name: "session first", sessionExpiry: now.Add(-2 * time.Second), callerExpiry: now.Add(-time.Second), wantExpired: true},
		{name: "caller first", sessionExpiry: now.Add(-time.Second), callerExpiry: now.Add(-2 * time.Second), wantExpired: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := &awaitClock{now: now, lifetime: time.Minute}
			client, err := New("https://gateway.example.com")
			if err != nil {
				t.Fatal(err)
			}
			client.now, client.wait = clock.Now, clock.Wait
			session := awaitSession(clock)
			session.expiresAt = test.sessionExpiry
			ctx, cancel := context.WithDeadline(context.Background(), test.callerExpiry)
			defer cancel()

			_, err = client.Await(ctx, session, AwaitOptions{})
			var timeout *LoginTimeoutError
			if !errors.As(err, &timeout) || !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrLoginExpired) != test.wantExpired {
				t.Fatalf("Await() error = %#v, expired = %v", err, errors.Is(err, ErrLoginExpired))
			}
		})
	}
}

func TestDefaultWaitStopsOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := defaultWait(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("defaultWait() error = %v", err)
	}
}

func TestDefaultWaitInterruptsActiveTimer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	timerActive := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- defaultWait(&signalingContext{Context: ctx, doneCalled: timerActive}, time.Hour)
	}()

	select {
	case <-timerActive:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("defaultWait did not start its timer")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("defaultWait() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("defaultWait did not interrupt its active timer")
	}
}

func TestRetryablePollErrorClassification(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "429", err: &HTTPError{StatusCode: http.StatusTooManyRequests, Retryable: true}, want: true},
		{name: "500", err: &HTTPError{StatusCode: http.StatusInternalServerError, Retryable: true}, want: true},
		{name: "400", err: &HTTPError{StatusCode: http.StatusBadRequest}, want: false},
		{name: "timeout", err: transportError{err: context.DeadlineExceeded}, want: true},
		{name: "temporary DNS", err: transportError{err: &net.DNSError{IsTemporary: true}}, want: true},
		{name: "permanent DNS", err: transportError{err: &net.DNSError{Name: "missing.invalid"}}, want: false},
		{name: "connection reset", err: transportError{err: syscall.ECONNRESET}, want: true},
		{name: "connection refused", err: transportError{err: syscall.ECONNREFUSED}, want: true},
		{name: "EOF", err: transportError{err: io.EOF}, want: true},
		{name: "certificate", err: transportError{err: x509.UnknownAuthorityError{}}, want: false},
		{name: "protocol EOF", err: responseReadError{op: "poll", err: io.EOF}, want: false},
		{name: "other", err: errors.New("permanent"), want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := retryablePollError(test.err); got != test.want {
				t.Fatalf("retryablePollError(%T) = %v, want %v", test.err, got, test.want)
			}
		})
	}
}

func TestAwaitSelectsOnlyOfferedTeamOnce(t *testing.T) {
	for _, useOption := range []bool{false, true} {
		t.Run(fmt.Sprintf("option=%v", useOption), func(t *testing.T) {
			clock := newAwaitClock(10 * time.Second)
			attempts, selectorCalls := 0, 0
			client := awaitClient(t, clock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts++
				w.Header().Set("Content-Type", "application/json")
				if attempts == 1 {
					if r.URL.Query().Get("team_id") != "" {
						t.Fatalf("first poll team_id = %q", r.URL.Query().Get("team_id"))
					}
					_, _ = io.WriteString(w, `{"status":"ready","requires_team_selection":true,"teams":["team-1","team-2"]}`)
					return
				}
				if r.URL.Query().Get("team_id") != "team-2" {
					t.Fatalf("selected team_id = %q", r.URL.Query().Get("team_id"))
				}
				_, _ = io.WriteString(w, `{"status":"ready","key":"sk-key","team_id":"team-2","teams":["team-1","team-2"]}`)
			}))
			options := AwaitOptions{SelectTeam: func(context.Context, []Team) (string, error) {
				selectorCalls++
				return "team-2", nil
			}}
			if useOption {
				options.TeamID = "team-2"
			}

			credential, err := client.Await(context.Background(), awaitSession(clock), options)
			wantSelectorCalls := 1
			if useOption {
				wantSelectorCalls = 0
			}
			if err != nil || credential.TeamID != "team-2" || attempts != 2 || selectorCalls != wantSelectorCalls {
				t.Fatalf("Await() = %#v, %v; attempts = %d; selector = %d", credential, err, attempts, selectorCalls)
			}
		})
	}
}

func TestAwaitRejectsInvalidTeamBeforeRepolling(t *testing.T) {
	for _, teamID := range []string{"", "team-3"} {
		t.Run(fmt.Sprintf("team=%q", teamID), func(t *testing.T) {
			clock := newAwaitClock(10 * time.Second)
			attempts := 0
			client := awaitClient(t, clock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts++
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"status":"ready","requires_team_selection":true,"teams":["team-1","team-2"]}`)
			}))
			_, err := client.Await(context.Background(), awaitSession(clock), AwaitOptions{SelectTeam: func(context.Context, []Team) (string, error) {
				return teamID, nil
			}})
			if !errors.Is(err, ErrProtocol) || attempts != 1 {
				t.Fatalf("Await() error = %v; attempts = %d", err, attempts)
			}
		})
	}
}

func TestAwaitTeamRequiredAndEventsUseIndependentTeamCopies(t *testing.T) {
	clock := newAwaitClock(10 * time.Second)
	client := awaitClient(t, clock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ready","requires_team_selection":true,"teams":[{"id":"team-1","alias":"Engineering"}]}`)
	}))
	eventCalls := 0

	_, err := client.Await(context.Background(), awaitSession(clock), AwaitOptions{OnEvent: func(event Event) {
		eventCalls++
		if event.Kind != EventTeamsRequired || event.Attempt != 1 {
			t.Fatalf("event = %#v", event)
		}
		event.Teams[0].ID = "mutated"
	}})
	var teamErr *TeamRequiredError
	if !errors.As(err, &teamErr) || eventCalls != 1 || len(teamErr.Teams) != 1 || teamErr.Teams[0].ID != "team-1" {
		t.Fatalf("Await() error = %#v; event calls = %d", err, eventCalls)
	}
}

func TestAwaitRechecksDeadlineAfterTeamsEvent(t *testing.T) {
	for _, test := range []struct {
		name        string
		expire      bool
		wantExpired bool
	}{
		{name: "caller cancellation"},
		{name: "session expiry", expire: true, wantExpired: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := newAwaitClock(10 * time.Second)
			session := awaitSession(clock)
			client := awaitClient(t, clock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"status":"ready","requires_team_selection":true,"teams":["team-1"]}`)
			}))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			selectorCalls := 0

			_, err := client.Await(ctx, session, AwaitOptions{
				OnEvent: func(Event) {
					if test.expire {
						clock.now = session.expiresAt
					} else {
						cancel()
					}
				},
				SelectTeam: func(context.Context, []Team) (string, error) {
					selectorCalls++
					return "team-1", nil
				},
			})
			if selectorCalls != 0 || !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) ||
				errors.Is(err, ErrLoginExpired) != test.wantExpired {
				t.Fatalf("Await() error = %#v; selector calls = %d", err, selectorCalls)
			}
		})
	}
}

func TestAwaitBoundsSelectorContextByEarliestDeadline(t *testing.T) {
	for _, test := range []struct {
		name          string
		lifetime      time.Duration
		callerTimeout time.Duration
		wantExpired   bool
	}{
		{name: "session", lifetime: 25 * time.Millisecond, wantExpired: true},
		{name: "caller", lifetime: time.Second, callerTimeout: 100 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := newAwaitClock(test.lifetime)
			client := awaitClient(t, clock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"status":"ready","requires_team_selection":true,"teams":["team-1"]}`)
			}))
			ctx, cancel := context.WithCancel(context.Background())
			if test.callerTimeout > 0 {
				ctx, cancel = context.WithTimeout(context.Background(), test.callerTimeout)
			}
			defer cancel()
			done := make(chan error, 1)
			selectorCalls := 0

			go func() {
				_, err := client.Await(ctx, awaitSession(clock), AwaitOptions{SelectTeam: func(ctx context.Context, _ []Team) (string, error) {
					selectorCalls++
					if _, ok := ctx.Deadline(); !ok {
						return "", errors.New("selector context has no deadline")
					}
					<-ctx.Done()
					return "", ctx.Err()
				}})
				done <- err
			}()

			select {
			case err := <-done:
				var timeout *LoginTimeoutError
				if selectorCalls != 1 || !errors.As(err, &timeout) || !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrLoginExpired) != test.wantExpired {
					t.Fatalf("Await() error = %#v; selector calls = %d", err, selectorCalls)
				}
			case <-time.After(time.Second):
				cancel()
				t.Fatal("Await did not interrupt the selector")
			}
		})
	}
}

func TestAwaitRechecksDeadlineAfterSelectorReturns(t *testing.T) {
	clock := newAwaitClock(10 * time.Second)
	session := awaitSession(clock)
	sentinel := errors.New("selector error")
	client := awaitClient(t, clock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ready","requires_team_selection":true,"teams":["team-1"]}`)
	}))

	_, err := client.Await(context.Background(), session, AwaitOptions{SelectTeam: func(context.Context, []Team) (string, error) {
		clock.now = session.expiresAt
		return "", sentinel
	}})
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrLoginExpired) || errors.Is(err, sentinel) {
		t.Fatalf("Await() error = %#v", err)
	}
}

func TestAwaitPreservesSelectorErrorsAndRejectsRepeatedSelection(t *testing.T) {
	sentinel := errors.New("selector stopped")
	for _, test := range []struct {
		name     string
		selector TeamSelector
		want     error
		wantPoll int
	}{
		{name: "selector error", selector: func(context.Context, []Team) (string, error) { return "", sentinel }, want: sentinel, wantPoll: 1},
		{name: "repeated selection", selector: func(context.Context, []Team) (string, error) { return "team-1", nil }, want: ErrProtocol, wantPoll: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := newAwaitClock(10 * time.Second)
			attempts := 0
			client := awaitClient(t, clock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts++
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"status":"ready","requires_team_selection":true,"teams":["team-1"]}`)
			}))
			_, err := client.Await(context.Background(), awaitSession(clock), AwaitOptions{SelectTeam: test.selector})
			if !errors.Is(err, test.want) || attempts != test.wantPoll {
				t.Fatalf("Await() error = %v; attempts = %d", err, attempts)
			}
		})
	}
}

func TestAwaitSurfacesTeamMembership403Detail(t *testing.T) {
	clock := newAwaitClock(10 * time.Second)
	attempts := 0
	client := awaitClient(t, clock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		if attempts == 1 {
			_, _ = io.WriteString(w, `{"status":"ready","requires_team_selection":true,"teams":["team-1"]}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"detail":"membership denied"}`)
	}))

	_, err := client.Await(context.Background(), awaitSession(clock), AwaitOptions{TeamID: "team-1"})
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusForbidden || httpErr.Detail != "membership denied" || attempts != 2 {
		t.Fatalf("Await() error = %#v; attempts = %d", err, attempts)
	}
}

func TestAwaitRejectsCredentialForDifferentSelectedTeam(t *testing.T) {
	for _, ready := range []string{
		`{"status":"ready","key":"sk-key","team_id":"team-2","teams":["team-1","team-2"]}`,
		`{"status":"ready","key":"sk-key"}`,
	} {
		clock := newAwaitClock(10 * time.Second)
		attempts := 0
		client := awaitClient(t, clock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			w.Header().Set("Content-Type", "application/json")
			if attempts == 1 {
				_, _ = io.WriteString(w, `{"status":"ready","requires_team_selection":true,"teams":["team-1","team-2"]}`)
				return
			}
			_, _ = io.WriteString(w, ready)
		}))

		_, err := client.Await(context.Background(), awaitSession(clock), AwaitOptions{TeamID: "team-1"})
		if !errors.Is(err, ErrProtocol) || attempts != 2 {
			t.Fatalf("Await(%s) error = %v; attempts = %d", ready, err, attempts)
		}
	}
}

func TestAuthenticateStartsCallsBackThenAwaitsSilently(t *testing.T) {
	clock := newAwaitClock(10 * time.Second)
	started, polled := false, false
	client := awaitClient(t, clock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sso/cli/start"):
			started = true
			_, _ = io.WriteString(w, `{"login_id":"login-1","poll_secret":"secret","user_code":"CODE","expires_in":10}`)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/sso/cli/poll/"):
			polled = true
			_, _ = io.WriteString(w, `{"status":"ready","key":"sk-key"}`)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
		}
	}))
	callbacks := 0

	credential, err := client.Authenticate(context.Background(), AuthenticateOptions{OnSession: func(ctx context.Context, session Session) error {
		callbacks++
		if !started || polled || session.LoginID != "login-1" || session.pollSecret != "secret" {
			t.Fatalf("callback session = %#v; started=%v polled=%v", session, started, polled)
		}
		return nil
	}})
	if err != nil || credential.Key != "sk-key" || callbacks != 1 || !polled {
		t.Fatalf("Authenticate() = %#v, %v; callbacks = %d; polled = %v", credential, err, callbacks, polled)
	}
}

func TestAuthenticatePreservesSessionCallbackErrors(t *testing.T) {
	for _, callbackErr := range []error{errors.New("stop"), context.Canceled} {
		clock := newAwaitClock(10 * time.Second)
		polls := 0
		client := awaitClient(t, clock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.Method != http.MethodPost {
				polls++
			}
			_, _ = io.WriteString(w, `{"login_id":"login-1","poll_secret":"secret","user_code":"CODE","expires_in":10}`)
		}))
		_, err := client.Authenticate(context.Background(), AuthenticateOptions{OnSession: func(context.Context, Session) error {
			return callbackErr
		}})
		if !errors.Is(err, callbackErr) || polls != 0 {
			t.Fatalf("Authenticate() error = %v; polls = %d", err, polls)
		}
	}
}

type awaitClock struct {
	now      time.Time
	lifetime time.Duration
	waits    []time.Duration
}

type signalingContext struct {
	context.Context
	doneCalled chan struct{}
	once       sync.Once
}

func (c *signalingContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.doneCalled) })
	return c.Context.Done()
}

func newAwaitClock(lifetime time.Duration) *awaitClock {
	return &awaitClock{now: time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC), lifetime: lifetime}
}

func (c *awaitClock) Now() time.Time { return c.now }

func (c *awaitClock) Wait(ctx context.Context, delay time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		c.waits = append(c.waits, delay)
		c.now = c.now.Add(delay)
		return nil
	}
}

func awaitSession(clock *awaitClock) Session {
	return Session{
		LoginID:    "login-1",
		ExpiresIn:  clock.lifetime,
		pollSecret: "secret",
		expiresAt:  clock.Now().Add(clock.lifetime),
	}
}

func awaitClient(t *testing.T, clock *awaitClock, handler http.HandlerFunc, options ...Option) *Client {
	t.Helper()
	server := testserver.New(handler)
	t.Cleanup(server.Close)
	options = append(options, WithPollInterval(2*time.Second))
	client, err := New(server.URL, options...)
	if err != nil {
		t.Fatal(err)
	}
	client.now, client.wait = clock.Now, clock.Wait
	return client
}

func pollResponseFor(req *http.Request, status int, body string, header http.Header) *http.Response {
	if header == nil {
		header = make(http.Header)
	}
	header.Set("Content-Type", "application/json")
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: req}
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
