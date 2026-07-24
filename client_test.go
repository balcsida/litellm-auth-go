package litellmauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/balcsida/litellm-auth-go/internal/testserver"
)

func TestStartCreatesLegacySession(t *testing.T) {
	server := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/sso/cli/start" {
			t.Fatalf("request = %s %s", r.Method, r.URL)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Fatalf("Accept = %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || len(body) != 0 {
			t.Fatalf("request body = %q, %v", body, err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"login_id":"login-1","poll_secret":"secret","user_code":"CODE-1"}`))
	}))
	defer server.Close()

	client, err := New(server.URL)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	session, err := client.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if session.LoginID != "login-1" || session.UserCode != "CODE-1" || session.ExpiresIn != 5*time.Minute {
		t.Fatalf("session = %#v", session)
	}
	if got, want := session.VerificationURL.String(), server.URL+"/sso/key/generate?key=login-1&source=litellm-cli"; got != want {
		t.Fatalf("VerificationURL = %q, want %q", got, want)
	}
}

func TestStartUsesCurrentResponseFields(t *testing.T) {
	server := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"login_id":"login-1","poll_secret":"secret","user_code":"CODE-1","expires_in":30,"verification_uri_complete":"` + serverURL(r) + `/complete"}`))
	}))
	defer server.Close()

	client, err := New(server.URL)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	session, err := client.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if session.ExpiresIn != 30*time.Second || session.VerificationURL.String() != server.URL+"/complete" {
		t.Fatalf("session = %#v", session)
	}
}

func TestStartFallsBackFromUnsafeVerificationURI(t *testing.T) {
	client := startClient(t, `{"login_id":"login","poll_secret":"secret","user_code":"CODE","verification_uri_complete":"https://other.example/verify?secret=secret"}`)
	session, err := client.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if got, want := session.VerificationURL.String(), client.browserURL("login").String(); got != want {
		t.Fatalf("VerificationURL = %q, want %q", got, want)
	}
}

func TestStartRejectsInvalidRequiredFieldsAndExpiry(t *testing.T) {
	for _, raw := range []string{
		`{"poll_secret":"secret","user_code":"CODE"}`,
		`{"login_id":"","poll_secret":"secret","user_code":"CODE"}`,
		`{"login_id":"login","user_code":"CODE"}`,
		`{"login_id":"login","poll_secret":"","user_code":"CODE"}`,
		`{"login_id":"login","poll_secret":"secret"}`,
		`{"login_id":"login","poll_secret":"secret","user_code":"","expires_in":5}`,
		`{"login_id":"login","poll_secret":"secret","user_code":"CODE","expires_in":0}`,
		`{"login_id":"login","poll_secret":"secret","user_code":"CODE","expires_in":-1}`,
		`{"login_id":"login","poll_secret":"secret","user_code":"CODE","expires_in":1.5}`,
		`{"login_id":"login","poll_secret":"secret","user_code":"CODE","expires_in":"5"}`,
	} {
		t.Run(raw, func(t *testing.T) {
			client := startClient(t, raw)
			if _, err := client.Start(context.Background()); !errors.Is(err, ErrProtocol) {
				t.Fatalf("Start() error = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestStartCapsExpiryAndCapturesAbsoluteDeadline(t *testing.T) {
	client := startClient(t, `{"login_id":"login","poll_secret":"secret","user_code":"CODE","expires_in":3600}`)
	client.maxWait = 20 * time.Second
	clock := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	client.now = func() time.Time { return clock }

	session, err := client.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if session.ExpiresIn != 20*time.Second || !session.expiresAt.Equal(clock.Add(20*time.Second)) {
		t.Fatalf("session expiry = %s / %s", session.ExpiresIn, session.expiresAt)
	}
	clock = clock.Add(time.Hour)
	if !session.expiresAt.Equal(time.Date(2026, 7, 24, 12, 0, 20, 0, time.UTC)) {
		t.Fatalf("session expiry moved to %s", session.expiresAt)
	}
}

func TestStartMapsUnsupportedAndRateLimitResponses(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client := startClient(t, `{"poll_secret":"do-not-leak"}`, withStatus(status))
			_, err := client.Start(context.Background())
			if !errors.Is(err, ErrUnsupportedProxy) || !strings.Contains(err.Error(), "upgrade") || !strings.Contains(err.Error(), "base URL") {
				t.Fatalf("Start() error = %v", err)
			}
		})
	}

	server := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"poll_secret":"do-not-leak"}`))
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = client.Start(context.Background())
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || !httpErr.Retryable || httpErr.StatusCode != http.StatusTooManyRequests || len(server.Requests()) != 1 {
		t.Fatalf("Start() error = %#v, requests = %d", err, len(server.Requests()))
	}
	for _, got := range []string{httpErr.Detail, httpErr.Error(), httpErr.GoString()} {
		if strings.Contains(got, "do-not-leak") {
			t.Fatalf("rate-limit error leaked body: %q", got)
		}
	}
}

func TestStartRejectsInvalidOrOversizedJSONWithoutLeakingBody(t *testing.T) {
	for _, test := range []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "non JSON", contentType: "text/html", body: "do-not-leak"},
		{name: "trailing JSON", contentType: "application/json", body: `{"login_id":"login","poll_secret":"do-not-leak","user_code":"CODE"} {}`},
		{name: "oversized", contentType: "application/json", body: strings.Repeat("x", 1024*1024+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := startClient(t, test.body, withContentType(test.contentType))
			_, err := client.Start(context.Background())
			if !errors.Is(err, ErrProtocol) || !strings.Contains(err.Error(), "content-type") || !strings.Contains(err.Error(), "bytes=") {
				t.Fatalf("Start() error = %v", err)
			}
			if strings.Contains(err.Error(), "do-not-leak") {
				t.Fatalf("Start() leaked body: %q", err)
			}
		})
	}
}

func TestStartRejectsPartialResponseWithoutLeakingBody(t *testing.T) {
	body := `{"login_id":"login","poll_secret":"do-not-leak","user_code":"CODE"}`
	server := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)+1))
		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = client.Start(context.Background())
	if !errors.Is(err, ErrProtocol) || !errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(err.Error(), "do-not-leak") {
		t.Fatalf("Start() error = %v", err)
	}
}

func TestStartRedactsResponseReadErrors(t *testing.T) {
	sentinel := errors.New("do-not-leak")
	client, err := New("https://gateway.example.com", WithHTTPClient(&http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       &errorBody{body: `{"login_id":"login","poll_secret":"secret","user_code":"CODE"}`, err: sentinel},
			Request:    req,
		}, nil
	})}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = client.Start(context.Background())
	if !errors.Is(err, ErrProtocol) || !errors.Is(err, sentinel) {
		t.Fatalf("Start() error = %v", err)
	}
	for _, got := range []string{err.Error(), fmt.Sprintf("%#v", err)} {
		if strings.Contains(got, "do-not-leak") {
			t.Fatalf("Start() leaked response read error: %q", got)
		}
	}
}

func TestStartRejectsRedirectAndKeepsTransportErrorsSafe(t *testing.T) {
	redirect := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/do-not-leak", http.StatusFound)
	}))
	defer redirect.Close()
	client, err := New(redirect.URL)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = client.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "redirect") || strings.Contains(err.Error(), "do-not-leak") {
		t.Fatalf("redirect error = %v", err)
	}

	closed := testserver.New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := closed.URL
	closed.Close()
	client, err = New(closedURL)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = client.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "start") || !strings.Contains(err.Error(), client.startURL().String()) || strings.Contains(err.Error(), "do-not-leak") {
		t.Fatalf("transport error = %v", err)
	}
}

func TestStartDoesNotMutateProvidedHTTPClient(t *testing.T) {
	server := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/", http.StatusFound)
	}))
	defer server.Close()
	originalRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	provided := &http.Client{CheckRedirect: originalRedirect}
	client, err := New(server.URL, WithHTTPClient(provided))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, _ = client.Start(context.Background())
	if reflect.ValueOf(provided.CheckRedirect).Pointer() != reflect.ValueOf(originalRedirect).Pointer() {
		t.Fatal("Start() mutated the caller HTTP client")
	}
}

type startServerOption func(http.ResponseWriter)

func withStatus(status int) startServerOption {
	return func(w http.ResponseWriter) { w.WriteHeader(status) }
}

func withContentType(value string) startServerOption {
	return func(w http.ResponseWriter) { w.Header().Set("Content-Type", value) }
}

func startClient(t *testing.T, body string, opts ...startServerOption) *Client {
	t.Helper()
	server := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for _, option := range opts {
			option(w)
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	client, err := New(server.URL)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return client
}

func serverURL(r *http.Request) string { return "http://" + r.Host }

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type errorBody struct {
	body string
	err  error
	done bool
}

func (b *errorBody) Read(p []byte) (int, error) {
	if b.done {
		return 0, io.EOF
	}
	b.done = true
	return copy(p, b.body), b.err
}

func (*errorBody) Close() error { return nil }
