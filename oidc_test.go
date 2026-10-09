package litellmauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeIdP is an OIDC provider with a public PKCE client: /oidc/2/auth "signs
// the user in" by redirecting straight to the loopback callback, /oidc/2/token
// verifies the PKCE challenge and issues an id_token echoing the nonce, and
// the refresh grant rotates or revokes on demand.
type fakeIdP struct {
	t   *testing.T
	srv *httptest.Server

	mu            sync.Mutex
	challenge     string
	nonce         string
	codes         map[string]bool
	refreshTokens map[string]bool
	tokenCalls    int
	deny          bool
	rotateRefresh bool
	disabledUser  bool
	subject       string
	issuer        string
	audience      any
	azp           string
	expiresAt     time.Time

	discoveryCalls  int
	discoveryIssuer string
	dropToken       bool
	omitS256        bool
	discoveryStatus int
	discoveryRedir  bool
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	idp := &fakeIdP{t: t, codes: map[string]bool{}, refreshTokens: map[string]bool{}, rotateRefresh: true, subject: "NH10000001"}
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/2/auth", idp.authorize)
	mux.HandleFunc("/oidc/2/token", idp.token)
	mux.HandleFunc("/oidc/2/.well-known/openid-configuration", idp.discovery)
	idp.srv = httptest.NewTLSServer(mux)
	idp.issuer = idp.srv.URL + "/oidc/2"
	idp.audience = "example-client"
	idp.expiresAt = time.Now().Add(time.Hour).Truncate(time.Second)
	t.Cleanup(idp.srv.Close)
	return idp
}

func (idp *fakeIdP) provider() OIDCProvider {
	return OIDCProvider{Issuer: idp.srv.URL + "/oidc/2", ClientID: "example-client", Scope: "openid params"}
}

// fullProvider names every endpoint, so it must never trigger discovery.
func (idp *fakeIdP) fullProvider() OIDCProvider {
	provider := idp.provider()
	provider.AuthorizeURL = idp.srv.URL + "/oidc/2/auth"
	provider.TokenURL = idp.srv.URL + "/oidc/2/token"
	return provider
}

func (idp *fakeIdP) discovery(w http.ResponseWriter, r *http.Request) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.discoveryCalls++
	if idp.discoveryRedir {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
		return
	}
	if idp.discoveryStatus != 0 {
		http.Error(w, "no", idp.discoveryStatus)
		return
	}
	document := map[string]any{
		"issuer": idp.srv.URL + "/oidc/2", "authorization_endpoint": idp.srv.URL + "/oidc/2/auth",
		"token_endpoint":                   idp.srv.URL + "/oidc/2/token",
		"device_authorization_endpoint":    idp.srv.URL + "/oidc/2/device",
		"code_challenge_methods_supported": []string{"S256"},
		"jwks_uri":                         idp.srv.URL + "/oidc/2/jwks", "response_types_supported": []string{"code"},
	}
	if idp.discoveryIssuer != "" {
		document["issuer"] = idp.discoveryIssuer
	}
	if idp.dropToken {
		delete(document, "token_endpoint")
	}
	if idp.omitS256 {
		document["code_challenge_methods_supported"] = []string{"plain"}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(document)
}

func (idp *fakeIdP) client(t *testing.T) *Client {
	t.Helper()
	client, err := New("https://proxy.example.com", WithHTTPClient(idp.srv.Client()), WithMaxWait(5*time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func (idp *fakeIdP) idToken(nonce string, exp time.Time) string {
	claims := map[string]any{
		"iss": idp.issuer, "aud": idp.audience, "sub": idp.subject,
		"exp": exp.Unix(), "iat": time.Now().Unix(), "nonce": nonce,
	}
	if idp.azp != "" {
		claims["azp"] = idp.azp
	}
	payload, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k1"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func (idp *fakeIdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != "example-client" || q.Get("code_challenge_method") != "S256" || !strings.Contains(q.Get("scope"), "openid") || q.Get("nonce") == "" {
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
	idp.mu.Lock()
	if idp.deny {
		callback.Set("error", "access_denied")
	} else {
		idp.challenge = q.Get("code_challenge")
		idp.nonce = q.Get("nonce")
		idp.codes["code-1"] = true
		callback.Set("code", "code-1")
	}
	idp.mu.Unlock()
	redirect.RawQuery = callback.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (idp *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.tokenCalls++
	w.Header().Set("Content-Type", "application/json")
	if r.PostForm.Get("client_secret") != "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"Sending credentials in both Authorization header and payload body will cause an error"}`))
		return
	}
	if idp.disabledUser {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"User is suspended. Access is unauthorized"}`))
		return
	}
	nonce := ""
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !idp.codes[r.PostForm.Get("code")] || base64.RawURLEncoding.EncodeToString(sum[:]) != idp.challenge || r.PostForm.Get("client_id") != "example-client" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"PKCE verification failed"}`))
			return
		}
		delete(idp.codes, r.PostForm.Get("code"))
		nonce = idp.nonce
	case "refresh_token":
		if !idp.refreshTokens[r.PostForm.Get("refresh_token")] {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"refresh token is not active"}`))
			return
		}
		if idp.rotateRefresh {
			delete(idp.refreshTokens, r.PostForm.Get("refresh_token"))
		}
	default:
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"unsupported_grant_type"}`))
		return
	}
	body := map[string]any{
		"access_token": "opaque-access-" + strings.Repeat("a", idp.tokenCalls), "token_type": "Bearer", "expires_in": 3600,
		"id_token": idp.idToken(nonce, idp.expiresAt),
	}
	if r.PostForm.Get("grant_type") == "authorization_code" || idp.rotateRefresh {
		refresh := "rt-" + strings.Repeat("r", idp.tokenCalls)
		idp.refreshTokens[refresh] = true
		body["refresh_token"] = refresh
	}
	_ = json.NewEncoder(w).Encode(body)
}

// browse plays the browser: GET the authorize URL (TLS to the fake IdP) and
// follow the redirect to the loopback callback.
func (idp *fakeIdP) browse(_ context.Context, session PKCESession) error {
	go func() {
		response, err := idp.srv.Client().Get(session.AuthorizeURL.String())
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	return nil
}

func TestOIDCAuthenticateRoundTrip(t *testing.T) {
	idp := newFakeIdP(t)
	client := idp.client(t)

	var seen PKCESession
	credential, err := client.AuthenticateOIDC(context.Background(), OIDCOptions{
		Provider: idp.provider(),
		OnSession: func(ctx context.Context, session PKCESession) error {
			seen = session
			return idp.browse(ctx, session)
		},
	})
	if err != nil {
		t.Fatalf("AuthenticateOIDC: %v", err)
	}
	if credential.AuthMethod != AuthMethodOIDC || credential.Subject != "NH10000001" || credential.UserID != "NH10000001" || credential.RefreshToken != "rt-r" {
		t.Fatalf("credential = %+v", credential)
	}
	if credential.BaseURL != "https://proxy.example.com" || credential.Issuer != idp.srv.URL+"/oidc/2" || credential.ClientID != "example-client" {
		t.Fatalf("credential binding = %+v", credential)
	}
	// The bearer is the id_token, and freshness follows its exp claim.
	if !strings.HasPrefix(credential.AuthorizationHeader(), "Bearer eyJ") || !credential.Fresh(time.Now()) {
		t.Fatalf("header = %.20s fresh=%v", credential.AuthorizationHeader(), credential.Fresh(time.Now()))
	}
	if err := credential.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	q := seen.AuthorizeURL.Query()
	if q.Get("nonce") == "" || q.Get("client_secret") != "" || !strings.HasPrefix(seen.RedirectURI, "http://127.0.0.1:") {
		t.Fatalf("authorize URL = %s", seen.AuthorizeURL)
	}
}

func TestOIDCRejectsNonceMismatch(t *testing.T) {
	idp := newFakeIdP(t)
	client := idp.client(t)
	session, err := client.StartOIDC(context.Background(), OIDCOptions{Provider: idp.provider()})
	if err != nil {
		t.Fatalf("StartOIDC: %v", err)
	}
	// Drive the authorize hop by hand so the IdP records a nonce OTHER than
	// the one this session sent (a substituted token).
	go func() {
		authorize := session.AuthorizeURL
		q := authorize.Query()
		q.Set("nonce", "someone-elses-nonce")
		authorize.RawQuery = q.Encode()
		response, err := idp.srv.Client().Get(authorize.String())
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	_, err = client.Wait(context.Background(), session)
	if err == nil || !strings.Contains(err.Error(), "nonce mismatch") {
		t.Fatalf("err = %v; want nonce mismatch", err)
	}
}

func TestOIDCDeniedAndForgedState(t *testing.T) {
	t.Run("denied", func(t *testing.T) {
		idp := newFakeIdP(t)
		idp.deny = true
		_, err := idp.client(t).AuthenticateOIDC(context.Background(), OIDCOptions{Provider: idp.provider(), OnSession: idp.browse})
		if !errors.Is(err, ErrPKCEDenied) || idp.tokenCalls != 0 {
			t.Fatalf("err = %v tokenCalls = %d; want ErrPKCEDenied and no exchange", err, idp.tokenCalls)
		}
	})
	t.Run("forged state", func(t *testing.T) {
		idp := newFakeIdP(t)
		client := idp.client(t)
		session, err := client.StartOIDC(context.Background(), OIDCOptions{Provider: idp.provider()})
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			response, err := http.Get(session.RedirectURI + "?code=code-1&state=forged")
			if err == nil {
				_ = response.Body.Close()
			}
		}()
		if _, err := client.Wait(context.Background(), session); err == nil || !strings.Contains(err.Error(), "state mismatch") {
			t.Fatalf("err = %v; want state mismatch", err)
		}
	})
}

func TestOIDCProviderValidation(t *testing.T) {
	client, _ := New("https://proxy.example.com")
	for name, provider := range map[string]OIDCProvider{
		"http issuer":     {Issuer: "http://idp.example/oidc/2", ClientID: "c", Scope: "openid"},
		"http endpoint":   {Issuer: "https://idp.example/oidc/2", ClientID: "c", Scope: "openid", TokenURL: "http://idp.example/token"},
		"issuer query":    {Issuer: "https://idp.example/oidc/2?x=1", ClientID: "c", Scope: "openid"},
		"missing openid":  {Issuer: "https://idp.example/oidc/2", ClientID: "c", Scope: "params"},
		"missing client":  {Issuer: "https://idp.example/oidc/2", Scope: "openid"},
		"userinfo in URL": {Issuer: "https://user@idp.example/oidc/2", ClientID: "c", Scope: "openid"},
	} {
		if _, err := client.StartOIDC(context.Background(), OIDCOptions{Provider: provider}); err == nil {
			t.Errorf("%s: StartOIDC accepted an invalid provider", name)
		}
	}
}

func TestOIDCAuthorizePreservesProviderQuery(t *testing.T) {
	idp := newFakeIdP(t)
	provider := idp.provider()
	query := url.Values{"tenant": {"example"}, "resource": {"one", "two"}}
	for _, key := range []string{"response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method"} {
		query[key] = []string{"stale", "duplicate"}
	}
	provider.AuthorizeURL = idp.srv.URL + "/oidc/2/auth?" + query.Encode()
	session, err := idp.client(t).StartOIDC(context.Background(), OIDCOptions{Provider: provider})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	got := session.AuthorizeURL.Query()
	if got.Get("tenant") != "example" || strings.Join(got["resource"], ",") != "one,two" {
		t.Fatalf("provider query was lost: %v", got)
	}
	for key := range query {
		if key == "tenant" || key == "resource" {
			continue
		}
		if len(got[key]) != 1 || got.Get(key) == "" || got.Get(key) == "stale" || got.Get(key) == "duplicate" {
			t.Errorf("protocol parameter %s = %v; want one generated value", key, got[key])
		}
	}
}

func TestOIDCRefreshKeepsSubjectAndHandlesRotation(t *testing.T) {
	idp := newFakeIdP(t)
	client := idp.client(t)
	credential, err := client.AuthenticateOIDC(context.Background(), OIDCOptions{Provider: idp.provider(), OnSession: idp.browse})
	if err != nil {
		t.Fatalf("AuthenticateOIDC: %v", err)
	}

	renewed, err := client.RefreshOIDC(context.Background(), idp.provider(), credential)
	if err != nil {
		t.Fatalf("RefreshOIDC: %v", err)
	}
	if renewed.Key == credential.Key || renewed.RefreshToken == credential.RefreshToken || renewed.Subject != credential.Subject || renewed.BaseURL != credential.BaseURL {
		t.Fatalf("renewed = %+v", renewed)
	}
	// Rotation burned the old refresh token.
	if _, err := client.RefreshOIDC(context.Background(), idp.provider(), credential); !errors.Is(err, ErrRefreshRejected) {
		t.Fatalf("replay err = %v; want ErrRefreshRejected", err)
	}

	// An IdP that does not rotate omits refresh_token: the previous one is kept.
	idp.rotateRefresh = false
	again, err := client.RefreshOIDC(context.Background(), idp.provider(), renewed)
	if err != nil {
		t.Fatalf("RefreshOIDC (no rotation): %v", err)
	}
	if again.RefreshToken != renewed.RefreshToken {
		t.Fatalf("refresh token = %q; want the previous token kept", again.RefreshToken)
	}
}

func TestOIDCRefreshReportsDisabledUserAsRejected(t *testing.T) {
	idp := newFakeIdP(t)
	client := idp.client(t)
	credential, err := client.AuthenticateOIDC(context.Background(), OIDCOptions{Provider: idp.provider(), OnSession: idp.browse})
	if err != nil {
		t.Fatal(err)
	}
	idp.disabledUser = true // OneLogin: invalid_request + "User is suspended. Access is unauthorized"
	if _, err := client.RefreshOIDC(context.Background(), idp.provider(), credential); !errors.Is(err, ErrRefreshRejected) {
		t.Fatalf("err = %v; want ErrRefreshRejected for a disabled user", err)
	}
}

func TestOIDCTokenErrorsDistinguishLoginFromRefresh(t *testing.T) {
	for _, code := range []string{"invalid_grant", "invalid_token", "access_denied", "invalid_request"} {
		t.Run(code, func(t *testing.T) {
			description := "provider rejected request"
			if code == "invalid_request" {
				description = "User is suspended. Access is unauthorized"
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
			}))
			defer server.Close()
			client, err := New("https://proxy.example.com", WithHTTPClient(server.Client()))
			if err != nil {
				t.Fatal(err)
			}
			provider := OIDCProvider{Issuer: server.URL, ClientID: "client", Scope: "openid", TokenURL: server.URL}
			_, err = client.redeemOIDCCode(context.Background(), &PKCESession{provider: &provider}, "code")
			var httpErr *HTTPError
			if errors.Is(err, ErrRefreshRejected) || !errors.As(err, &httpErr) {
				t.Errorf("login err = %v; want HTTPError without ErrRefreshRejected", err)
			} else if httpErr.StatusCode != http.StatusBadRequest || httpErr.Detail != description {
				t.Errorf("login HTTPError status=%d detail=%q", httpErr.StatusCode, httpErr.Detail)
			}
			_, err = client.RefreshOIDC(context.Background(), provider, Credential{AuthMethod: AuthMethodOIDC, RefreshToken: "refresh"})
			if !errors.Is(err, ErrRefreshRejected) {
				t.Errorf("refresh err = %v; want ErrRefreshRejected", err)
			}
		})
	}
}

func TestOIDCRefreshValidatesTokenIdentity(t *testing.T) {
	for _, claim := range []string{"issuer", "audience", "subject"} {
		t.Run(claim, func(t *testing.T) {
			idp := newFakeIdP(t)
			client := idp.client(t)
			credential, err := client.AuthenticateOIDC(context.Background(), OIDCOptions{Provider: idp.provider(), OnSession: idp.browse})
			if err != nil {
				t.Fatal(err)
			}
			idp.mu.Lock()
			switch claim {
			case "issuer":
				idp.issuer = "https://other-idp.example/oidc/2"
			case "audience":
				idp.audience = "another-client"
			case "subject":
				idp.subject = "another-user"
			}
			idp.mu.Unlock()
			if _, err := client.RefreshOIDC(context.Background(), idp.provider(), credential); !errors.Is(err, ErrProtocol) || !strings.Contains(err.Error(), claim) {
				t.Fatalf("err = %v; want protocol error for changed %s", err, claim)
			}
		})
	}
}

func TestOIDCRefreshRefusesForeignIssuer(t *testing.T) {
	idp := newFakeIdP(t)
	credential := Credential{AuthMethod: AuthMethodOIDC, RefreshToken: "rt", Issuer: "https://other-idp.example/oidc/2", Subject: "NH1"}
	if _, err := idp.client(t).RefreshOIDC(context.Background(), idp.provider(), credential); !errors.Is(err, ErrOriginMismatch) {
		t.Fatalf("err = %v; want ErrOriginMismatch", err)
	}
}

func TestOIDCRejectsExpiredIDTokens(t *testing.T) {
	for _, operation := range []string{"login", "refresh"} {
		for _, offset := range []time.Duration{-time.Second, 0, time.Second} {
			t.Run(operation+"/"+offset.String(), func(t *testing.T) {
				idp := newFakeIdP(t)
				client := idp.client(t)
				options := OIDCOptions{Provider: idp.provider(), OnSession: idp.browse}
				var credential Credential
				var err error
				if operation == "refresh" {
					credential, err = client.AuthenticateOIDC(context.Background(), options)
					if err != nil {
						t.Fatal(err)
					}
				}
				client.now = func() time.Time { return idp.expiresAt.Add(offset) }
				if operation == "refresh" {
					_, err = client.RefreshOIDC(context.Background(), idp.provider(), credential)
				} else {
					_, err = client.AuthenticateOIDC(context.Background(), options)
				}
				if offset < 0 {
					if err != nil {
						t.Fatalf("unexpired token rejected: %v", err)
					}
				} else if !errors.Is(err, ErrProtocol) || !strings.Contains(err.Error(), "expired") {
					t.Fatalf("err = %v; want expired token protocol error", err)
				}
			})
		}
	}
}

func TestOIDCCredentialFormattingHidesTokens(t *testing.T) {
	credential := Credential{AuthMethod: AuthMethodOIDC, Key: "eyJ.secret.sig", RefreshToken: "rt-secret"}
	if s := credential.String() + credential.GoString(); strings.Contains(s, "secret") {
		t.Fatalf("%q leaks a token", s)
	}
}

func TestOIDCComparesIssuersExactly(t *testing.T) {
	t.Run("trailing slash is kept", func(t *testing.T) {
		idp := newFakeIdP(t)
		idp.issuer += "/"
		idp.discoveryIssuer = idp.issuer
		provider := idp.provider()
		provider.Issuer += "/"
		client := idp.client(t)
		credential, err := client.AuthenticateOIDC(context.Background(), OIDCOptions{Provider: provider, OnSession: idp.browse})
		if err != nil {
			t.Fatalf("AuthenticateOIDC: %v", err)
		}
		if credential.Issuer != provider.Issuer {
			t.Fatalf("credential issuer = %q; want %q", credential.Issuer, provider.Issuer)
		}
		if _, err := client.RefreshOIDC(context.Background(), provider, credential); err != nil {
			t.Fatalf("RefreshOIDC: %v", err)
		}
	})
	t.Run("trailing slash difference is rejected", func(t *testing.T) {
		idp := newFakeIdP(t)
		provider := idp.provider()
		provider.Issuer += "/"
		client := idp.client(t)
		_, err := client.AuthenticateOIDC(context.Background(), OIDCOptions{Provider: provider, OnSession: idp.browse})
		if !errors.Is(err, ErrProtocol) || !strings.Contains(err.Error(), "issuer mismatch") {
			t.Fatalf("AuthenticateOIDC err = %v; want issuer mismatch", err)
		}
		credential, err := client.AuthenticateOIDC(context.Background(), OIDCOptions{Provider: idp.provider(), OnSession: idp.browse})
		if err != nil {
			t.Fatal(err)
		}
		idp.mu.Lock()
		idp.issuer += "/"
		idp.mu.Unlock()
		_, err = client.RefreshOIDC(context.Background(), idp.provider(), credential)
		if !errors.Is(err, ErrProtocol) || !strings.Contains(err.Error(), "issuer mismatch") {
			t.Fatalf("RefreshOIDC err = %v; want issuer mismatch", err)
		}
	})
}

func TestOIDCValidatesAuthorizedParty(t *testing.T) {
	const client = "example-client"
	for _, test := range []struct {
		name     string
		audience any
		azp      string
		accept   bool
	}{
		{"multiple audiences without azp", []string{client, "other-api"}, "", false},
		{"azp names another client", client, "another-client", false},
		{"multiple audiences with azp", []string{client, "other-api"}, client, true},
		{"single audience with azp", client, client, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			idp := newFakeIdP(t)
			idp.audience, idp.azp = test.audience, test.azp
			c := idp.client(t)
			credential, err := c.AuthenticateOIDC(context.Background(), OIDCOptions{Provider: idp.provider(), OnSession: idp.browse})
			if test.accept {
				if err != nil {
					t.Fatalf("AuthenticateOIDC: %v", err)
				}
				if _, err := c.RefreshOIDC(context.Background(), idp.provider(), credential); err != nil {
					t.Fatalf("RefreshOIDC: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrProtocol) || !strings.Contains(err.Error(), "audience mismatch") {
				t.Fatalf("err = %v; want audience mismatch", err)
			}
		})
	}
}

func TestOIDCValidateAcceptsLoopbackHTTP(t *testing.T) {
	provider := OIDCProvider{Issuer: "http://127.0.0.1:9000/oidc", ClientID: "c", Scope: "openid", TokenURL: "http://127.0.0.1:9000/token"}
	if err := provider.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestOIDCDiscoveryFillsEmptyEndpointsAndKeepsOverrides(t *testing.T) {
	idp := newFakeIdP(t)
	provider := idp.provider()
	provider.TokenURL = idp.srv.URL + "/custom/token"
	got, err := idp.client(t).DiscoverOIDC(context.Background(), provider)
	if err != nil {
		t.Fatalf("DiscoverOIDC: %v", err)
	}
	base := idp.srv.URL + "/oidc/2"
	if got.AuthorizeURL != base+"/auth" || got.TokenURL != idp.srv.URL+"/custom/token" || got.DeviceAuthorizationURL != base+"/device" {
		t.Fatalf("provider = %+v", got)
	}
}

func TestOIDCFullyConfiguredProviderSkipsDiscovery(t *testing.T) {
	idp := newFakeIdP(t)
	client := idp.client(t)
	credential, err := client.AuthenticateOIDC(context.Background(), OIDCOptions{Provider: idp.fullProvider(), OnSession: idp.browse})
	if err != nil {
		t.Fatalf("AuthenticateOIDC: %v", err)
	}
	if _, err := client.RefreshOIDC(context.Background(), idp.fullProvider(), credential); err != nil {
		t.Fatalf("RefreshOIDC: %v", err)
	}
	if idp.discoveryCalls != 0 {
		t.Fatalf("discovery calls = %d; want 0", idp.discoveryCalls)
	}
}

func TestOIDCRefreshUsesStoredTokenEndpointWithoutDiscovery(t *testing.T) {
	idp := newFakeIdP(t)
	client := idp.client(t)
	credential, err := client.AuthenticateOIDC(context.Background(), OIDCOptions{Provider: idp.provider(), OnSession: idp.browse})
	if err != nil {
		t.Fatalf("AuthenticateOIDC: %v", err)
	}
	if credential.TokenEndpoint == "" || idp.discoveryCalls != 1 {
		t.Fatalf("TokenEndpoint = %q, discovery calls = %d", credential.TokenEndpoint, idp.discoveryCalls)
	}
	if _, err := client.RefreshOIDC(context.Background(), idp.provider(), credential); err != nil {
		t.Fatalf("RefreshOIDC: %v", err)
	}
	if idp.discoveryCalls != 1 {
		t.Fatalf("discovery calls = %d; want no new request on refresh", idp.discoveryCalls)
	}
}

func TestOIDCDiscoveryRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		set  func(*fakeIdP)
		http bool
	}{
		"issuer mismatch": {set: func(idp *fakeIdP) { idp.discoveryIssuer = idp.srv.URL + "/oidc/2/" }},
		"redirect":        {set: func(idp *fakeIdP) { idp.discoveryRedir = true }},
		"non-200":         {set: func(idp *fakeIdP) { idp.discoveryStatus = http.StatusNotFound }, http: true},
		"no token":        {set: func(idp *fakeIdP) { idp.dropToken = true }},
		"no S256":         {set: func(idp *fakeIdP) { idp.omitS256 = true }},
	} {
		t.Run(name, func(t *testing.T) {
			idp := newFakeIdP(t)
			tc.set(idp)
			_, err := idp.client(t).DiscoverOIDC(context.Background(), idp.provider())
			var httpErr *HTTPError
			switch {
			case err == nil:
				t.Fatal("DiscoverOIDC accepted the document")
			case tc.http && (!errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusNotFound):
				t.Fatalf("err = %v; want HTTPError 404", err)
			case !tc.http && !errors.Is(err, ErrProtocol):
				t.Fatalf("err = %v; want ErrProtocol", err)
			}
		})
	}
}

func TestOIDCStartReportsLoopbackUnavailable(t *testing.T) {
	idp := newFakeIdP(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	port := busy.Addr().(*net.TCPAddr).Port
	_, err = idp.client(t).StartOIDC(context.Background(), OIDCOptions{Provider: idp.fullProvider(), RedirectPorts: []int{port}})
	if !errors.Is(err, ErrLoopbackUnavailable) {
		t.Fatalf("err = %v; want ErrLoopbackUnavailable", err)
	}
}
