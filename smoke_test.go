package litellmauth

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"
)

func TestLiteLLMFullLoginSmoke(t *testing.T) {
	baseURL := os.Getenv("LITELLM_SMOKE_URL")
	if baseURL == "" {
		t.Skip("LITELLM_SMOKE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := New(baseURL, WithAllowInsecureHTTP())
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	response, err := browser.Get(session.VerificationURL.String())
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("verification status = %d, body = %s", response.StatusCode, body)
	}

	match := regexp.MustCompile(`name="browser_complete_token" value="([^"]+)"`).FindSubmatch(body)
	if len(match) != 2 {
		t.Fatal("verification page did not contain completion token")
	}
	completionURL := baseURL + "/sso/cli/complete/" + url.PathEscape(session.LoginID)
	response, err = browser.PostForm(completionURL, url.Values{
		"browser_complete_token": {html.UnescapeString(string(match[1]))},
		"user_code":              {session.UserCode},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("completion status = %d, body = %s", response.StatusCode, body)
	}

	result, err := client.PollOnce(ctx, session, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != PollReady || result.Credential == nil || result.Credential.Key == "" || result.Credential.UserID == "" {
		t.Fatalf("poll result = %#v", result)
	}
}
