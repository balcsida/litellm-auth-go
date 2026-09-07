package litellmauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakePKCEProxy implements the LiteLLM >= 1.99 native CLI auth contract
// (/.well-known/litellm-cli-auth, /register, /authorize, /token, /revoke).
// The browser is played by browse(): it fetches the authorize URL and follows
// the proxy's redirect to the CLI's loopback callback.
type fakePKCEProxy struct {
	t   *testing.T
	srv *httptest.Server

	mu            sync.Mutex
	challenge     string
	registered    string
	codes         map[string]bool
	refreshTokens map[string]bool
	tokenCalls    int
	revoked       []string
	deny          bool
	unavailable   bool
	teamID        string
	// foreignEndpoint, when set, is published as the token_endpoint.
	foreignEndpoint string
}

func newFakePKCEProxy(t *testing.T) *fakePKCEProxy {
	t.Helper()
	proxy := &fakePKCEProxy{t: t, codes: map[string]bool{}, refreshTokens: map[string]bool{}, teamID: "team-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/litellm-cli-auth", proxy.discovery)
	mux.HandleFunc("/register", proxy.register)
	mux.HandleFunc("/authorize", proxy.authorize)
	mux.HandleFunc("/token", proxy.token)
	mux.HandleFunc("/revoke", proxy.revoke)
	proxy.srv = httptest.NewServer(mux)
	t.Cleanup(proxy.srv.Close)
	return proxy
}

func (p *fakePKCEProxy) client(t *testing.T) *Client {
	t.Helper()
	client, err := New(p.srv.URL, WithHTTPClient(p.srv.Client()), WithMaxWait(5*time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func (p *fakePKCEProxy) discovery(w http.ResponseWriter, _ *http.Request) {
	tokenEndpoint := p.srv.URL + "/token"
	if p.foreignEndpoint != "" {
		tokenEndpoint = p.foreignEndpoint
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"contract_version":                           1,
		"issuer":                                     p.srv.URL,
		"authorization_endpoint":                     p.srv.URL + "/authorize",
		"token_endpoint":                             tokenEndpoint,
		"registration_endpoint":                      p.srv.URL + "/register",
		"revocation_endpoint":                        p.srv.URL + "/revoke",
		"resource":                                   p.srv.URL,
		"response_types_supported":                   []string{"code"},
		"grant_types_supported":                      []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":           []string{"S256"},
		"token_endpoint_auth_methods_supported":      []string{"none"},
		"revocation_endpoint_auth_methods_supported": []string{"none"},
	})
}

func (p *fakePKCEProxy) register(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RedirectURIs            []string `json:"redirect_uris"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&body) != nil || body.TokenEndpointAuthMethod != "none" || len(body.RedirectURIs) != 1 {
		http.Error(w, `{"error":"invalid_client_metadata"}`, http.StatusBadRequest)
		return
	}
	if redirect, err := url.Parse(body.RedirectURIs[0]); err != nil || redirect.Hostname() != "127.0.0.1" {
		http.Error(w, `{"error":"invalid_redirect_uri","error_description":"a proxy-API grant may only redirect to a loopback address"}`, http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	p.registered = "llm_dcrc_test"
	p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "llm_dcrc_test", "redirect_uris": body.RedirectURIs, "token_endpoint_auth_method": "none"})
}

// authorize stands in for sign-in + consent: it records the challenge and
// sends the "browser" straight to the loopback callback with a code.
func (p *fakePKCEProxy) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != "llm_dcrc_test" || q.Get("code_challenge_method") != "S256" || q.Get("resource") != p.srv.URL {
		http.Error(w, "bad authorize request", http.StatusBadRequest)
		return
	}
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect", http.StatusBadRequest)
		return
	}
	callback := redirect.Query()
	callback.Set("state", q.Get("state"))
	p.mu.Lock()
	if p.deny {
		callback.Set("error", "access_denied")
	} else {
		p.challenge = q.Get("code_challenge")
		p.codes["code-1"] = true
		callback.Set("code", "code-1")
	}
	p.mu.Unlock()
	redirect.RawQuery = callback.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusSeeOther)
}

func (p *fakePKCEProxy) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenCalls++
	w.Header().Set("Content-Type", "application/json")
	if p.unavailable {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"temporarily_unavailable"}`))
		return
	}
	if r.PostForm.Get("client_secret") != "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"public client must not send a secret"}`))
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		code := r.PostForm.Get("code")
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !p.codes[code] || base64.RawURLEncoding.EncodeToString(sum[:]) != p.challenge || r.PostForm.Get("resource") != p.srv.URL {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"PKCE verification failed"}`))
			return
		}
		delete(p.codes, code) // single use
	case "refresh_token":
		token := r.PostForm.Get("refresh_token")
		if !p.refreshTokens[token] {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"refresh token is not active"}`))
			return
		}
		delete(p.refreshTokens, token) // rotation
	default:
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"unsupported_grant_type"}`))
		return
	}
	refresh := "llm_srefresh_" + strings.Repeat("r", p.tokenCalls)
	p.refreshTokens[refresh] = true
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "sk-access-" + strings.Repeat("a", p.tokenCalls), "token_type": "Bearer", "expires_in": 86400,
		"refresh_token": refresh, "user_id": "NH1", "team_id": p.teamID,
	})
}

func (p *fakePKCEProxy) revoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.unavailable {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	p.revoked = append(p.revoked, r.PostForm.Get("token"))
	delete(p.refreshTokens, r.PostForm.Get("token"))
	w.WriteHeader(http.StatusOK)
}

// browse plays the browser: GET the authorize URL and follow the redirect to
// the loopback callback, exactly as a real browser would.
func (p *fakePKCEProxy) browse(_ context.Context, session PKCESession) error {
	go func() {
		response, err := http.Get(session.AuthorizeURL.String())
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	return nil
}

func TestPKCEAuthenticateRoundTrip(t *testing.T) {
	proxy := newFakePKCEProxy(t)
	client := proxy.client(t)

	var seen PKCESession
	credential, err := client.AuthenticatePKCE(context.Background(), PKCEOptions{
		OnSession: func(ctx context.Context, session PKCESession) error {
			seen = session
			return proxy.browse(ctx, session)
		},
	})
	if err != nil {
		t.Fatalf("AuthenticatePKCE: %v", err)
	}
	if credential.Key != "sk-access-a" || credential.RefreshToken != "llm_srefresh_r" || credential.TeamID != "team-1" || credential.UserID != "NH1" {
		t.Fatalf("credential = %+v", credential)
	}
	if credential.AuthMethod != AuthMethodPKCE || credential.ClientID != "llm_dcrc_test" || credential.TokenEndpoint != proxy.srv.URL+"/token" {
		t.Fatalf("credential metadata = %+v", credential)
	}
	if !credential.Fresh(time.Now()) || credential.Expiry().Before(time.Now().Add(23*time.Hour)) {
		t.Fatalf("expiry = %v; want ~24h", credential.Expiry())
	}
	if err := credential.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	q := seen.AuthorizeURL.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("resource") != proxy.srv.URL || !strings.HasPrefix(seen.RedirectURI, "http://127.0.0.1:") {
		t.Fatalf("authorize URL = %s", seen.AuthorizeURL)
	}
	if strings.Contains(seen.String()+seen.GoString(), "llm_") {
		t.Fatal("session formatting must not leak identifiers")
	}
}

func TestPKCEDeniedConsent(t *testing.T) {
	proxy := newFakePKCEProxy(t)
	proxy.deny = true
	_, err := proxy.client(t).AuthenticatePKCE(context.Background(), PKCEOptions{OnSession: proxy.browse})
	if !errors.Is(err, ErrPKCEDenied) {
		t.Fatalf("err = %v; want ErrPKCEDenied", err)
	}
	if proxy.tokenCalls != 0 {
		t.Fatal("a denied consent must never reach the token endpoint")
	}
}

func TestPKCERejectsForgedState(t *testing.T) {
	proxy := newFakePKCEProxy(t)
	client := proxy.client(t)
	session, err := client.StartPKCE(context.Background(), PKCEOptions{})
	if err != nil {
		t.Fatalf("StartPKCE: %v", err)
	}
	go func() {
		response, err := http.Get(session.RedirectURI + "?code=code-1&state=forged")
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	_, err = client.Wait(context.Background(), session)
	if err == nil || !strings.Contains(err.Error(), "state mismatch") {
		t.Fatalf("err = %v; want state mismatch", err)
	}
	if proxy.tokenCalls != 0 {
		t.Fatal("a forged state must never reach the token endpoint")
	}
}

func TestPKCEDiscoveryFailsClosed(t *testing.T) {
	t.Run("404 is unsupported proxy", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		defer srv.Close()
		client, _ := New(srv.URL, WithHTTPClient(srv.Client()))
		if _, err := client.DiscoverPKCE(context.Background()); !errors.Is(err, ErrPKCEUnsupported) {
			t.Fatalf("err = %v; want ErrPKCEUnsupported", err)
		}
	})
	t.Run("foreign endpoint is refused", func(t *testing.T) {
		proxy := newFakePKCEProxy(t)
		proxy.foreignEndpoint = "https://evil.example/token"
		if _, err := proxy.client(t).DiscoverPKCE(context.Background()); !errors.Is(err, ErrProtocol) {
			t.Fatalf("err = %v; want ErrProtocol for an off-origin endpoint", err)
		}
	})
	t.Run("redirecting discovery is refused", func(t *testing.T) {
		srv := httptest.NewServer(http.RedirectHandler("https://evil.example/", http.StatusFound))
		defer srv.Close()
		client, _ := New(srv.URL, WithHTTPClient(srv.Client()))
		if _, err := client.DiscoverPKCE(context.Background()); err == nil {
			t.Fatal("a redirecting discovery document must be refused")
		}
	})
}

func TestPKCERefreshRotatesAndRejectsReplay(t *testing.T) {
	proxy := newFakePKCEProxy(t)
	client := proxy.client(t)
	credential, err := client.AuthenticatePKCE(context.Background(), PKCEOptions{OnSession: proxy.browse})
	if err != nil {
		t.Fatalf("AuthenticatePKCE: %v", err)
	}

	renewed, err := client.RefreshPKCE(context.Background(), credential)
	if err != nil {
		t.Fatalf("RefreshPKCE: %v", err)
	}
	if renewed.Key == credential.Key || renewed.RefreshToken == credential.RefreshToken {
		t.Fatal("refresh must rotate both the key and the refresh token")
	}
	if renewed.ClientID != credential.ClientID || renewed.TokenEndpoint != credential.TokenEndpoint || renewed.TeamID != "team-1" {
		t.Fatalf("renewed metadata lost: %+v", renewed)
	}

	// Replaying the burned refresh token is the "signed in elsewhere / revoked"
	// case: callers must fall back to a browser login.
	if _, err := client.RefreshPKCE(context.Background(), credential); !errors.Is(err, ErrRefreshRejected) {
		t.Fatalf("replay err = %v; want ErrRefreshRejected", err)
	}
}

func TestPKCERefreshRefusesForeignTokenEndpoint(t *testing.T) {
	proxy := newFakePKCEProxy(t)
	credential := Credential{AuthMethod: AuthMethodPKCE, RefreshToken: "rt", ClientID: "c", TokenEndpoint: "https://evil.example/token"}
	if _, err := proxy.client(t).RefreshPKCE(context.Background(), credential); !errors.Is(err, ErrOriginMismatch) {
		t.Fatalf("err = %v; want ErrOriginMismatch", err)
	}
}

func TestPKCERevoke(t *testing.T) {
	proxy := newFakePKCEProxy(t)
	client := proxy.client(t)
	credential, err := client.AuthenticatePKCE(context.Background(), PKCEOptions{OnSession: proxy.browse})
	if err != nil {
		t.Fatalf("AuthenticatePKCE: %v", err)
	}
	if err := client.RevokePKCE(context.Background(), credential); err != nil {
		t.Fatalf("RevokePKCE: %v", err)
	}
	if len(proxy.revoked) != 1 || proxy.revoked[0] != credential.RefreshToken {
		t.Fatalf("revoked = %v", proxy.revoked)
	}
	if _, err := client.RefreshPKCE(context.Background(), credential); !errors.Is(err, ErrRefreshRejected) {
		t.Fatalf("refresh after revoke err = %v; want ErrRefreshRejected", err)
	}
	// A non-PKCE credential has nothing to revoke server-side.
	if err := client.RevokePKCE(context.Background(), Credential{Key: "sk-plain"}); err != nil {
		t.Fatalf("RevokePKCE on a plain key = %v; want nil", err)
	}
}

func TestPKCEProxyUnavailableIsNotInvalidGrant(t *testing.T) {
	proxy := newFakePKCEProxy(t)
	client := proxy.client(t)
	credential, err := client.AuthenticatePKCE(context.Background(), PKCEOptions{OnSession: proxy.browse})
	if err != nil {
		t.Fatalf("AuthenticatePKCE: %v", err)
	}
	proxy.unavailable = true
	if _, err := client.RefreshPKCE(context.Background(), credential); !errors.Is(err, ErrProxyUnavailable) {
		t.Fatalf("refresh err = %v; want ErrProxyUnavailable", err)
	}
	if err := client.RevokePKCE(context.Background(), credential); !errors.Is(err, ErrProxyUnavailable) {
		t.Fatalf("revoke err = %v; want ErrProxyUnavailable", err)
	}
}

func TestPKCEWaitHonoursCancellation(t *testing.T) {
	proxy := newFakePKCEProxy(t)
	client := proxy.client(t)
	session, err := client.StartPKCE(context.Background(), PKCEOptions{})
	if err != nil {
		t.Fatalf("StartPKCE: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Wait(ctx, session); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want context.Canceled", err)
	}
}

func TestPKCERedirectPortsAreHonoured(t *testing.T) {
	proxy := newFakePKCEProxy(t)
	// Port 1 needs root and fails; the flow must move on to the OS-assigned 0.
	session, err := proxy.client(t).StartPKCE(context.Background(), PKCEOptions{RedirectPorts: []int{1, 0}})
	if err != nil {
		t.Fatalf("StartPKCE: %v", err)
	}
	defer session.Close()
	if !strings.HasPrefix(session.RedirectURI, "http://127.0.0.1:") || strings.HasPrefix(session.RedirectURI, "http://127.0.0.1:1/") {
		t.Fatalf("RedirectURI = %s", session.RedirectURI)
	}
}

func TestPKCECredentialJSONRoundTripKeepsRefreshMetadata(t *testing.T) {
	original := Credential{
		BaseURL: "https://proxy.example.com", Key: "sk-k", AuthMethod: AuthMethodPKCE, TokenType: "Bearer",
		IssuedAt: time.Now().UTC().Truncate(time.Second), ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		RefreshToken: "llm_srefresh_x", ClientID: "llm_dcrc_x", TokenEndpoint: "https://proxy.example.com/token",
		RevocationEndpoint: "https://proxy.example.com/revoke", Resource: "https://proxy.example.com",
		AttributionMetadata: map[string]any{},
	}
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Credential
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.RefreshToken != original.RefreshToken || decoded.ClientID != original.ClientID ||
		decoded.TokenEndpoint != original.TokenEndpoint || decoded.RevocationEndpoint != original.RevocationEndpoint || decoded.Resource != original.Resource {
		t.Fatalf("round trip lost PKCE metadata: %+v", decoded)
	}
	if strings.Contains(original.String()+original.GoString(), "llm_srefresh") {
		t.Fatal("credential formatting must not leak the refresh token")
	}
	if err := json.Unmarshal([]byte(`{"key":"sk","refresh_token":"bad\ntoken"}`), &decoded); !errors.Is(err, ErrProtocol) {
		t.Fatalf("control characters in refresh_token must be rejected, got %v", err)
	}
}
