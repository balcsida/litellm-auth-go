package litellmauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAuthenticateBrowserExchangesMatchingCallback(t *testing.T) {
	var authorization *url.URL
	var tokenForm url.Values
	tokenServer := loopbackServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("token request method = %s", r.Method)
		}
		var err error
		tokenForm, err = url.ParseQuery(mustReadAll(t, r))
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + oidcJWT(time.Now().Add(time.Hour)) + `","token_type":"Bearer","refresh_token":"rotated"}`))
	}))
	defer tokenServer.Close()

	client, err := New("https://proxy.example.com")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := client.AuthenticateBrowser(context.Background(), NativeOIDCConfig{DiscoveryURL: tokenServer.URL, ClientID: "native-client", Scopes: []string{"openid", "profile"}}, OIDCProvider{Issuer: tokenServer.URL, AuthorizationEndpoint: tokenServer.URL + "/authorize", TokenEndpoint: tokenServer.URL}, BrowserLoginOptions{
		OpenURL: func(_ context.Context, u *url.URL) error {
			authorization = u
			callback(t, u, url.Values{"code": {"authorization-code"}, "state": {u.Query().Get("state")}})
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if credential.OIDCRefresh == nil || credential.OIDCRefresh.RefreshToken != "rotated" {
		t.Fatalf("credential = %#v", credential)
	}
	if authorization == nil || authorization.Query().Get("response_type") != "code" || authorization.Query().Get("client_id") != "native-client" || authorization.Query().Get("scope") != "openid profile" {
		t.Fatalf("authorization URL = %v", authorization)
	}
	redirect, err := url.Parse(authorization.Query().Get("redirect_uri"))
	if err != nil || redirect.Scheme != "http" || redirect.Hostname() != "127.0.0.1" || redirect.Path != "/callback" {
		t.Fatalf("redirect URI = %q", authorization.Query().Get("redirect_uri"))
	}
	state, verifier := authorization.Query().Get("state"), tokenForm.Get("code_verifier")
	if state == "" || verifier == "" || authorization.Query().Get("code_challenge_method") != "S256" || tokenForm.Get("grant_type") != "authorization_code" || tokenForm.Get("client_id") != "native-client" || tokenForm.Get("code") != "authorization-code" || tokenForm.Get("redirect_uri") != redirect.String() {
		t.Fatalf("authorization = %q token form = %q", authorization.Query(), tokenForm)
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if authorization.Query().Get("code_challenge") != challenge {
		t.Fatalf("code challenge = %q, want %q", authorization.Query().Get("code_challenge"), challenge)
	}
}

func TestAuthenticateBrowserRejectsInvalidCallbacks(t *testing.T) {
	for _, test := range []struct {
		name  string
		query url.Values
	}{
		{name: "state mismatch", query: url.Values{"code": {"code"}, "state": {"wrong"}}},
		{name: "provider error", query: url.Values{"error": {"access_denied"}, "error_description": {"browser-secret"}, "state": {"placeholder"}}},
		{name: "missing code", query: url.Values{"state": {"placeholder"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, _ := New("https://proxy.example.com")
			_, err := client.AuthenticateBrowser(context.Background(), browserConfig(), browserProvider(), BrowserLoginOptions{OpenURL: func(_ context.Context, u *url.URL) error {
				query := test.query
				if query.Get("state") == "placeholder" {
					query = url.Values{"state": {u.Query().Get("state")}}
				}
				callback(t, u, query)
				return nil
			}})
			if !errors.Is(err, ErrProtocol) || strings.Contains(err.Error(), "browser-secret") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestAuthenticateBrowserIgnoresProviderErrorWithWrongState(t *testing.T) {
	callbacks := make(chan browserCallback, 1)
	handler := browserCallbackHandler(callbacks, "expected-state")

	wrong := httptest.NewRecorder()
	handler.ServeHTTP(wrong, httptest.NewRequest(http.MethodGet, "/callback?error=access_denied&state=wrong-state", nil))
	if wrong.Code != http.StatusBadRequest {
		t.Fatalf("wrong-state status = %d", wrong.Code)
	}
	select {
	case result := <-callbacks:
		t.Fatalf("wrong-state provider error terminated callback flow: %#v", result)
	default:
	}

	matched := httptest.NewRecorder()
	handler.ServeHTTP(matched, httptest.NewRequest(http.MethodGet, "/callback?code=code&state=expected-state", nil))
	if matched.Code != http.StatusOK {
		t.Fatalf("matching callback status = %d", matched.Code)
	}
	result := <-callbacks
	if result.code != "code" || result.err != nil {
		t.Fatalf("matching callback result = %#v", result)
	}
}

func TestAuthenticateBrowserIgnoresUnrelatedCallbackPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, _ := New("https://proxy.example.com")
	_, err := client.AuthenticateBrowser(ctx, browserConfig(), browserProvider(), BrowserLoginOptions{OpenURL: func(_ context.Context, u *url.URL) error {
		unrelated, err := url.Parse(u.Query().Get("redirect_uri"))
		if err != nil {
			t.Fatal(err)
		}
		unrelated.Path = "/other"
		response, err := http.Get(unrelated.String())
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("unrelated callback status = %d", response.StatusCode)
		}
		cancel()
		return nil
	}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}

func TestAuthenticateBrowserHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client, _ := New("https://proxy.example.com")
	_, err := client.AuthenticateBrowser(ctx, browserConfig(), browserProvider(), BrowserLoginOptions{OpenURL: func(context.Context, *url.URL) error { cancel(); return nil }})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}

func TestAuthenticateBrowserReturnsListenerFailureBeforeOpeningBrowser(t *testing.T) {
	listenerErr := errors.New("listener unavailable")
	opened := false
	client, _ := New("https://proxy.example.com")
	_, err := client.AuthenticateBrowser(context.Background(), browserConfig(), browserProvider(), BrowserLoginOptions{
		Listen:  func(string, string) (net.Listener, error) { return nil, listenerErr },
		OpenURL: func(context.Context, *url.URL) error { opened = true; return nil },
	})
	if !errors.Is(err, listenerErr) || opened {
		t.Fatalf("error = %v opened = %v", err, opened)
	}
}

func TestAuthenticateBrowserDoesNotExposeBrowserSecrets(t *testing.T) {
	client, _ := New("https://proxy.example.com")
	_, err := client.AuthenticateBrowser(context.Background(), browserConfig(), browserProvider(), BrowserLoginOptions{
		OpenURL: func(context.Context, *url.URL) error { return errors.New("browser-secret") },
	})
	if err == nil || strings.Contains(err.Error(), "browser-secret") {
		t.Fatalf("error = %v", err)
	}
}

func browserConfig() NativeOIDCConfig {
	return NativeOIDCConfig{DiscoveryURL: "https://idp.example.com/config", ClientID: "native-client", Scopes: []string{"openid"}}
}

func browserProvider() OIDCProvider {
	return OIDCProvider{Issuer: "https://idp.example.com", AuthorizationEndpoint: "https://idp.example.com/authorize", TokenEndpoint: "https://idp.example.com/token"}
}

func callback(t *testing.T, authorization *url.URL, query url.Values) {
	t.Helper()
	redirect, err := url.Parse(authorization.Query().Get("redirect_uri"))
	if err != nil {
		t.Fatal(err)
	}
	redirect.RawQuery = query.Encode()
	response, err := http.Get(redirect.String())
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusBadRequest {
		t.Fatalf("callback status = %d", response.StatusCode)
	}
}

func mustReadAll(t *testing.T, r *http.Request) string {
	t.Helper()
	var values []string
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	values = append(values, r.PostForm.Encode())
	return strings.Join(values, "")
}

func loopbackServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	return server
}
