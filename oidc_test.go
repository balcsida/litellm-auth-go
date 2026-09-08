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
	expiresAt     time.Time
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	idp := &fakeIdP{t: t, codes: map[string]bool{}, refreshTokens: map[string]bool{}, rotateRefresh: true, subject: "NH10000001"}
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/2/auth", idp.authorize)
	mux.HandleFunc("/oidc/2/token", idp.token)
	idp.srv = httptest.NewTLSServer(mux)
	idp.issuer = idp.srv.URL + "/oidc/2"
	idp.audience = "tescode-client"
	idp.expiresAt = time.Now().Add(time.Hour).Truncate(time.Second)
	t.Cleanup(idp.srv.Close)
	return idp
}

func (idp *fakeIdP) provider() OIDCProvider {
	return OIDCProvider{Issuer: idp.srv.URL + "/oidc/2", ClientID: "tescode-client", Scope: "openid params"}
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
	payload, _ := json.Marshal(map[string]any{
		"iss": idp.issuer, "aud": idp.audience, "sub": idp.subject,
		"exp": exp.Unix(), "iat": time.Now().Unix(), "nonce": nonce,
	})
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k1"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func (idp *fakeIdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != "tescode-client" || q.Get("code_challenge_method") != "S256" || !strings.Contains(q.Get("scope"), "openid") || q.Get("nonce") == "" {
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
		if !idp.codes[r.PostForm.Get("code")] || base64.RawURLEncoding.EncodeToString(sum[:]) != idp.challenge || r.PostForm.Get("client_id") != "tescode-client" {
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
	if credential.BaseURL != "https://proxy.example.com" || credential.Issuer != idp.srv.URL+"/oidc/2" || credential.ClientID != "tescode-client" {
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
	provider.AuthorizeURL = provider.authorizeURL() + "?" + query.Encode()
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
