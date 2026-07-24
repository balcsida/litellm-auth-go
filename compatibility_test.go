package litellmauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLiteLLMTrailingSlashContract(t *testing.T) {
	client, err := New("https://proxy.example.com/root/")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := client.startURL().String(), "https://proxy.example.com/root/sso/cli/start"; got != want {
		t.Fatalf("start URL = %q, want %q", got, want)
	}
	if got, want := client.pollURL("login-1", "").String(), "https://proxy.example.com/root/sso/cli/poll/login-1"; got != want {
		t.Fatalf("poll URL = %q, want %q", got, want)
	}
}

func TestLiteLLMVersionSkewContract(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client := compatibilityClient(t, func(*http.Request) *http.Response {
				return compatibilityResponse(status, "application/json", `{}`)
			})
			_, err := client.Start(context.Background())
			if !errors.Is(err, ErrUnsupportedProxy) || !strings.Contains(err.Error(), "upgrade the LiteLLM proxy") || !strings.Contains(err.Error(), "check the base URL") {
				t.Fatalf("Start() error = %v", err)
			}
		})
	}
}

func TestLiteLLMMissingSharedCacheContract(t *testing.T) {
	client := compatibilityClient(t, func(*http.Request) *http.Response {
		return compatibilityResponse(http.StatusBadRequest, "application/json", `{"detail":"Invalid CLI login session; use a shared cache for multiple replicas"}`)
	})
	_, err := client.PollOnce(context.Background(), pollSession("poll-secret"), "")
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || !errors.Is(err, ErrLoginExpired) {
		t.Fatalf("PollOnce() error = %#v", err)
	}
	if want := "Invalid CLI login session; use a shared cache for multiple replicas"; httpErr.Detail != want {
		t.Fatalf("detail = %q, want %q", httpErr.Detail, want)
	}
	if strings.Contains(err.Error(), httpErr.Detail) {
		t.Fatalf("rendered error leaked response detail: %q", err)
	}
}

func TestLiteLLMPollRetryContract(t *testing.T) {
	t.Run("429 retries", func(t *testing.T) {
		clock := newAwaitClock(10 * time.Second)
		attempts := 0
		client := compatibilityClient(t, func(*http.Request) *http.Response {
			attempts++
			if attempts == 1 {
				return compatibilityResponse(http.StatusTooManyRequests, "application/json", `{}`)
			}
			return compatibilityResponse(http.StatusOK, "application/json", `{"status":"ready","key":"sk-key"}`)
		})
		client.now, client.wait = clock.Now, clock.Wait
		credential, err := client.Await(context.Background(), awaitSession(clock), AwaitOptions{})
		if err != nil || credential.Key != "sk-key" || attempts != 2 {
			t.Fatalf("Await() credential = %#v, error = %v, attempts = %d", credential, err, attempts)
		}
	})

	for status := 400; status < 500; status++ {
		if status == http.StatusTooManyRequests {
			continue
		}
		t.Run(strconv.Itoa(status)+" stops", func(t *testing.T) {
			clock := newAwaitClock(10 * time.Second)
			attempts := 0
			client := compatibilityClient(t, func(*http.Request) *http.Response {
				attempts++
				return compatibilityResponse(status, "application/json", `{}`)
			})
			client.now, client.wait = clock.Now, clock.Wait
			_, err := client.Await(context.Background(), awaitSession(clock), AwaitOptions{})
			var httpErr *HTTPError
			if !errors.As(err, &httpErr) || httpErr.Retryable || attempts != 1 || len(clock.waits) != 0 {
				t.Fatalf("Await() error = %#v, attempts = %d, waits = %v", err, attempts, clock.waits)
			}
		})
	}
}

func TestLiteLLMCorporateGatewayContract(t *testing.T) {
	const body = "<html>corporate-auth-secret</html>"
	client := compatibilityClient(t, func(*http.Request) *http.Response {
		return compatibilityResponse(http.StatusOK, "text/html", body)
	})
	_, err := client.Start(context.Background())
	if !errors.Is(err, ErrProtocol) || !strings.Contains(err.Error(), "content-type=text/html") || strings.Contains(err.Error(), body) || strings.Contains(err.Error(), "corporate-auth-secret") {
		t.Fatalf("Start() error = %v", err)
	}
}

func TestLiteLLMOptionalVerificationURICompleteContract(t *testing.T) {
	client := compatibilityClient(t, func(*http.Request) *http.Response {
		return compatibilityResponse(http.StatusOK, "application/json", `{"login_id":"login-1","poll_secret":"poll-secret","user_code":"CODE"}`)
	})
	session, err := client.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := session.VerificationURL.String(), "https://proxy.example.com/sso/key/generate?key=login-1&source=litellm-cli"; got != want {
		t.Fatalf("verification URL = %q, want %q", got, want)
	}
}

func TestLiteLLMOptionalAttributionMetadataContract(t *testing.T) {
	client := compatibilityClient(t, func(*http.Request) *http.Response {
		return compatibilityResponse(http.StatusOK, "application/json", `{"status":"ready","key":"sk-key"}`)
	})
	result, err := client.PollOnce(context.Background(), pollSession("poll-secret"), "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Credential == nil || result.Credential.Key != "sk-key" || result.Credential.AttributionMetadata != nil {
		t.Fatalf("PollOnce() result = %#v", result)
	}
}

func compatibilityClient(t *testing.T, respond func(*http.Request) *http.Response) *Client {
	t.Helper()
	client, err := New("https://proxy.example.com", WithHTTPClient(&http.Client{
		Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			response := respond(request)
			response.Request = request
			return response, nil
		}),
	}))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func compatibilityResponse(status int, contentType, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {contentType}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
