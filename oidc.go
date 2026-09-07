package litellmauth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AuthMethodOIDC marks a credential obtained straight from the identity
// provider with the OAuth 2.0 authorization code + PKCE flow (RFC 7636, RFC
// 8252). The bearer presented to LiteLLM is the IdP's id_token, verified by
// the proxy's `enable_jwt_auth` path; the IdP stays the session authority via
// its refresh token.
const AuthMethodOIDC AuthMethod = "oidc-pkce"

// OIDCProvider describes a pre-registered public OIDC client at an identity
// provider. There is no client secret: PKCE replaces it.
type OIDCProvider struct {
	// Issuer is the OIDC issuer, e.g. https://login.example.com/oidc/2.
	// AuthorizeURL and TokenURL default to <Issuer>/auth and <Issuer>/token.
	Issuer string
	// ClientID is the public client's id (a public identifier, not a secret).
	ClientID string
	// Scope is the space-separated scope list; "openid" is required.
	Scope string
	// AuthorizeURL and TokenURL override the issuer-relative defaults.
	AuthorizeURL string
	TokenURL     string
}

func (p OIDCProvider) authorizeURL() string {
	if p.AuthorizeURL != "" {
		return p.AuthorizeURL
	}
	return strings.TrimRight(p.Issuer, "/") + "/auth"
}

func (p OIDCProvider) tokenURL() string {
	if p.TokenURL != "" {
		return p.TokenURL
	}
	return strings.TrimRight(p.Issuer, "/") + "/token"
}

func (p OIDCProvider) validate() error {
	if p.Issuer == "" || p.ClientID == "" {
		return errors.New("OIDC provider issuer and client id are required")
	}
	for _, raw := range []string{p.Issuer, p.authorizeURL(), p.tokenURL()} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return errors.New("OIDC provider endpoints must be absolute https URLs")
		}
	}
	if !containsString(strings.Fields(p.Scope), "openid") {
		return errors.New("OIDC provider scope must include openid")
	}
	return nil
}

// OIDCOptions configures Client.AuthenticateOIDC.
type OIDCOptions struct {
	// Provider is the identity provider and public client to sign in with.
	Provider OIDCProvider
	// OnSession receives the session before waiting, typically to open its URL.
	OnSession func(context.Context, PKCESession) error
	// RedirectPorts lists loopback ports to try in order. Empty means an
	// OS-assigned port; set it when the IdP registers exact redirect URIs.
	RedirectPorts []int
}

// StartOIDC binds the loopback listener and returns the session whose
// AuthorizeURL the user must open. The session carries a nonce that the
// returned id_token must echo.
func (c *Client) StartOIDC(ctx context.Context, options OIDCOptions) (*PKCESession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := options.Provider.validate(); err != nil {
		return nil, err
	}
	listener, err := listenLoopback(options.RedirectPorts)
	if err != nil {
		return nil, err
	}
	redirectURI := "http://" + listener.Addr().String() + "/callback"
	verifier, err := randomURLSafe(32)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	state, err := randomURLSafe(32)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	nonce, err := randomURLSafe(32)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}

	authorize, _ := url.Parse(options.Provider.authorizeURL())
	query := url.Values{}
	query.Set("response_type", "code")
	query.Set("client_id", options.Provider.ClientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("scope", options.Provider.Scope)
	query.Set("state", state)
	query.Set("nonce", nonce)
	query.Set("code_challenge", challengeS256(verifier))
	query.Set("code_challenge_method", "S256")
	authorize.RawQuery = query.Encode()

	return &PKCESession{
		AuthorizeURL: authorize,
		RedirectURI:  redirectURI,
		clientID:     options.Provider.ClientID,
		verifier:     verifier,
		state:        state,
		nonce:        nonce,
		provider:     &options.Provider,
		listener:     listener,
	}, nil
}

// AuthenticateOIDC runs the whole IdP browser flow: bind the listener, open
// the browser via OnSession, wait for the callback, redeem the code, and
// verify the id_token nonce.
func (c *Client) AuthenticateOIDC(ctx context.Context, options OIDCOptions) (Credential, error) {
	session, err := c.StartOIDC(ctx, options)
	if err != nil {
		return Credential{}, err
	}
	if options.OnSession != nil {
		if err := options.OnSession(ctx, *session); err != nil {
			_ = session.Close()
			return Credential{}, err
		}
	}
	return c.Wait(ctx, session)
}

// RefreshOIDC renews an IdP credential with its refresh token (public client:
// client_id only). The IdP may or may not rotate the refresh token; when it
// does not return one, the previous token is kept. ErrRefreshRejected means
// the IdP no longer honours the session (revoked, expired, user disabled).
func (c *Client) RefreshOIDC(ctx context.Context, provider OIDCProvider, credential Credential) (Credential, error) {
	if credential.AuthMethod != AuthMethodOIDC || credential.RefreshToken == "" {
		return Credential{}, fmt.Errorf("%w: credential has no refresh token", ErrRefreshRejected)
	}
	if err := provider.validate(); err != nil {
		return Credential{}, err
	}
	if credential.Issuer != "" && credential.Issuer != strings.TrimRight(provider.Issuer, "/") {
		return Credential{}, ErrOriginMismatch
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", credential.RefreshToken)
	form.Set("client_id", provider.ClientID)
	token, err := c.postOIDCToken(ctx, provider.tokenURL(), form, "refresh")
	if err != nil {
		return Credential{}, err
	}
	// An IdP refresh does not repeat the login nonce; only the code exchange
	// is nonce-checked. The subject must not change across a refresh, though.
	claims, err := oidcClaims(token.IDToken)
	if err != nil {
		return Credential{}, err
	}
	if credential.Subject != "" && claims.Subject != credential.Subject {
		return Credential{}, protocolError("refresh: id_token subject changed")
	}
	renewed := c.oidcCredential(token, claims, provider)
	if renewed.RefreshToken == "" {
		renewed.RefreshToken = credential.RefreshToken
	}
	renewed.BaseURL = credential.BaseURL
	return renewed, nil
}

func (c *Client) redeemOIDCCode(ctx context.Context, session *PKCESession, code string) (Credential, error) {
	provider := *session.provider
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", session.RedirectURI)
	form.Set("client_id", provider.ClientID)
	form.Set("code_verifier", session.verifier)
	token, err := c.postOIDCToken(ctx, provider.tokenURL(), form, "token")
	if err != nil {
		return Credential{}, err
	}
	claims, err := oidcClaims(token.IDToken)
	if err != nil {
		return Credential{}, err
	}
	// OIDC Core 3.1.3.7 (11): the id_token must echo the request nonce, which
	// binds it to this login and defeats token substitution.
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(session.nonce)) != 1 {
		return Credential{}, protocolError("token: id_token nonce mismatch")
	}
	if claims.Issuer != strings.TrimRight(provider.Issuer, "/") {
		return Credential{}, protocolError("token: id_token issuer mismatch")
	}
	if !claims.hasAudience(provider.ClientID) {
		return Credential{}, protocolError("token: id_token audience mismatch")
	}
	return c.oidcCredential(token, claims, provider), nil
}

type oidcTokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

func (c *Client) postOIDCToken(ctx context.Context, endpoint string, form url.Values, op string) (oidcTokenResponse, error) {
	response, err := c.postForm(ctx, endpoint, form)
	if err != nil {
		return oidcTokenResponse{}, fmt.Errorf("OIDC %s: %w", op, err)
	}
	defer response.Body.Close()
	body, err := readPKCEBody(response, op)
	if err != nil && response.StatusCode == http.StatusOK {
		return oidcTokenResponse{}, err
	}
	if response.StatusCode != http.StatusOK {
		switch oauthErrorCode(body) {
		case "invalid_grant", "invalid_token", "access_denied":
			return oidcTokenResponse{}, ErrRefreshRejected
		}
		// OneLogin reports a disabled or locked user as invalid_request with
		// an "Access is unauthorized" description; that is a dead session too.
		if strings.Contains(strings.ToLower(oauthErrorDescription(body)), "unauthorized") {
			return oidcTokenResponse{}, ErrRefreshRejected
		}
		return oidcTokenResponse{}, pkceHTTPError(op, response, body)
	}
	var token oidcTokenResponse
	if err := json.Unmarshal(body, &token); err != nil || token.IDToken == "" ||
		containsKeySpaceOrControl(token.IDToken) || containsKeySpaceOrControl(token.RefreshToken) {
		return oidcTokenResponse{}, protocolError(op + ": malformed token response")
	}
	return token, nil
}

// oidcIDTokenClaims is the subset of id_token claims the client reads. The
// signature is NOT verified here: LiteLLM is the verifier (JWKS, iss, aud);
// the client needs exp for freshness and sub/nonce/iss/aud for sanity.
type oidcIDTokenClaims struct {
	Issuer   string          `json:"iss"`
	Subject  string          `json:"sub"`
	Audience json.RawMessage `json:"aud"`
	Nonce    string          `json:"nonce"`
	Exp      json.Number     `json:"exp"`
}

func (claims oidcIDTokenClaims) hasAudience(clientID string) bool {
	var single string
	if json.Unmarshal(claims.Audience, &single) == nil {
		return single == clientID
	}
	var many []string
	if json.Unmarshal(claims.Audience, &many) == nil {
		return containsString(many, clientID)
	}
	return false
}

func (claims oidcIDTokenClaims) expiry() time.Time {
	seconds, err := claims.Exp.Int64()
	if err != nil || seconds <= 0 {
		return time.Time{}
	}
	return time.Unix(seconds, 0)
}

func oidcClaims(idToken string) (oidcIDTokenClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return oidcIDTokenClaims{}, protocolError("id_token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return oidcIDTokenClaims{}, protocolError("id_token payload is not base64url")
	}
	var claims oidcIDTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return oidcIDTokenClaims{}, protocolError("id_token claims are not JSON")
	}
	if claims.Subject == "" || containsControl(claims.Subject) || claims.expiry().IsZero() {
		return oidcIDTokenClaims{}, protocolError("id_token lacks sub or exp")
	}
	return claims, nil
}

func (c *Client) oidcCredential(token oidcTokenResponse, claims oidcIDTokenClaims, provider OIDCProvider) Credential {
	return Credential{
		BaseURL:       c.baseURL,
		Key:           token.IDToken,
		AuthMethod:    AuthMethodOIDC,
		TokenType:     "Bearer",
		Issuer:        strings.TrimRight(provider.Issuer, "/"),
		Subject:       claims.Subject,
		Scopes:        strings.Fields(provider.Scope),
		UserID:        claims.Subject,
		IssuedAt:      c.now(),
		ExpiresAt:     claims.expiry(),
		RefreshToken:  token.RefreshToken,
		ClientID:      provider.ClientID,
		TokenEndpoint: provider.tokenURL(),
	}
}

func oauthErrorDescription(body []byte) string {
	var decoded struct {
		ErrorDescription string `json:"error_description"`
	}
	if json.Unmarshal(body, &decoded) != nil {
		return ""
	}
	return decoded.ErrorDescription
}
