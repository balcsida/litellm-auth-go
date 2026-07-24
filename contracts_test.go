package litellmauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestSessionFormattingRedactsPollSecret(t *testing.T) {
	secret := "poll-secret-abc"
	session := Session{LoginID: "login-1", UserCode: "CODE-1", pollSecret: secret}

	for _, got := range []string{session.String(), session.GoString()} {
		if strings.Contains(got, secret) {
			t.Fatalf("session formatting leaked poll secret: %q", got)
		}
	}
}

func TestHTTPErrorRedactsDetail(t *testing.T) {
	secret := "eyJhbGciOiJIUzI1NiJ9.payload.signature"
	err := &HTTPError{Op: "poll", StatusCode: http.StatusUnauthorized, Detail: "key=" + secret}

	if got := err.Error(); strings.Contains(got, secret) || strings.Contains(got, "key=") {
		t.Fatalf("HTTP error leaked detail: %q", got)
	}
}

func TestHTTPErrorDetailCapPreservesUTF8(t *testing.T) {
	got := safeHTTPErrorDetail(strings.Repeat("a", maxHTTPErrorDetailBytes-1) + "界")
	if len(got) != maxHTTPErrorDetailBytes-1 || !utf8.ValidString(got) {
		t.Fatalf("safeHTTPErrorDetail() returned %d invalid bytes: %q", len(got), got)
	}
}

func TestPublicFormattingRedactsCredentialAndHTTPSecrets(t *testing.T) {
	key := "sk-credential-secret"
	detail := "poll-secret-abc"
	credential := Credential{Key: key}
	httpErr := HTTPError{Op: "poll", StatusCode: http.StatusUnauthorized, Detail: detail}
	poll := PollResult{Credential: &credential}

	for _, got := range []string{
		fmt.Sprintf("%v", credential),
		fmt.Sprintf("%#v", credential),
		fmt.Sprintf("%v", httpErr),
		fmt.Sprintf("%#v", httpErr),
		fmt.Sprintf("%#v", poll),
	} {
		if strings.Contains(got, key) || strings.Contains(got, detail) {
			t.Fatalf("public formatting leaked a secret: %q", got)
		}
	}
}

func TestTypedErrorsSupportIsAndAs(t *testing.T) {
	teams := []Team{{ID: "team-1", Alias: "Engineering"}}
	teamErr := &TeamRequiredError{Teams: teams}
	if !errors.Is(teamErr, ErrTeamRequired) {
		t.Fatal("team error does not match ErrTeamRequired")
	}
	var gotTeamErr *TeamRequiredError
	if !errors.As(teamErr, &gotTeamErr) || gotTeamErr.Teams[0] != teams[0] {
		t.Fatalf("team error did not unwrap as itself: %#v", gotTeamErr)
	}

	httpErr := &HTTPError{Op: "poll", StatusCode: http.StatusServiceUnavailable, Retryable: true}
	if !errors.Is(httpErr, &HTTPError{Op: "poll", StatusCode: http.StatusServiceUnavailable, Retryable: true}) {
		t.Fatal("HTTP error does not match the same operation and status")
	}
	var gotHTTPErr *HTTPError
	if !errors.As(httpErr, &gotHTTPErr) || gotHTTPErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("HTTP error did not unwrap as itself: %#v", gotHTTPErr)
	}

	timeoutErr := &LoginTimeoutError{}
	if !errors.Is(timeoutErr, context.DeadlineExceeded) || !errors.Is(timeoutErr, ErrLoginExpired) {
		t.Fatal("login timeout does not preserve deadline and expiry sentinels")
	}
	var gotTimeoutErr *LoginTimeoutError
	if !errors.As(timeoutErr, &gotTimeoutErr) {
		t.Fatal("timeout error did not unwrap as itself")
	}
}

func TestOptionsValidateAndUseSafeDefaults(t *testing.T) {
	client, err := New("https://gateway.example.com")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if client.httpClient == nil || client.maxWait != 10*time.Minute || client.pollInterval != 2*time.Second || client.requestTimeout != 10*time.Second {
		t.Fatalf("unsafe defaults: %#v", client)
	}

	if _, err := New("https://gateway.example.com", WithHTTPClient(nil)); err == nil {
		t.Fatal("New() accepted a nil HTTP client")
	}
	for _, option := range []Option{
		WithMaxWait(0),
		WithPollInterval(-time.Second),
		WithRequestTimeout(0),
	} {
		if _, err := New("https://gateway.example.com", option); err == nil {
			t.Fatal("New() accepted an invalid duration")
		}
	}

	if _, err := New("https://gateway.example.com", WithAllowInsecureHTTP()); err != nil {
		t.Fatalf("New() with explicit HTTP allowance error = %v", err)
	}
}

func TestCredentialJSONRejectsNonScalarAttributionMetadata(t *testing.T) {
	var credential Credential
	if err := json.Unmarshal([]byte(`{}`), &credential); err != nil {
		t.Fatalf("json.Unmarshal() without metadata error = %v", err)
	}
	if err := json.Unmarshal([]byte(`{"attribution_metadata":{"department":"Engineering","active":true,"score":1}}`), &credential); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if len(credential.AttributionMetadata) != 3 {
		t.Fatalf("metadata = %#v", credential.AttributionMetadata)
	}

	for _, raw := range []string{
		`{"attribution_metadata":null}`,
		`{"attribution_metadata":[]}`,
		`{"attribution_metadata":"Engineering"}`,
		`{"attribution_metadata":1}`,
		`{"attribution_metadata":true}`,
		`{"attribution_metadata":{"nested":{"team":"Engineering"}}}`,
		`{"attribution_metadata":{"items":["Engineering"]}}`,
		`{"attribution_metadata":{"missing":null}}`,
	} {
		if err := json.Unmarshal([]byte(raw), &credential); !errors.Is(err, ErrProtocol) {
			t.Fatalf("json.Unmarshal(%s) error = %v, want ErrProtocol", raw, err)
		}
	}
}
