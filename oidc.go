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
	// Endpoints left empty come from OIDC discovery of the issuer.
	Issuer string
	// ClientID is the public client's id (a public identifier, not a secret).
	ClientID string
	// Scope is the space-separated scope list; "openid" is required.
	Scope string
	// AuthorizeURL, TokenURL and DeviceAuthorizationURL override the endpoints
	// that discovery would supply.
	AuthorizeURL           string
	TokenURL               string
	DeviceAuthorizationURL string
}

func (p OIDCProvider) validate() error {
	if p.Issuer == "" || p.ClientID == "" {
		return errors.New("OIDC provider issuer and client id are required")
	}
	for _, raw := range []string{p.Issuer, p.AuthorizeURL, p.TokenURL, p.DeviceAuthorizationURL} {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || u.User != nil ||
			(u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname()))) {
			return errors.New("OIDC provider endpoints must be absolute https URLs")
		}
	}
	if u, _ := url.Parse(p.Issuer); u.RawQuery != "" || u.Fragment != "" {
		return errors.New("OIDC provider issuer must not have a query or fragment")
	}
	if !containsString(strings.Fields(p.Scope), "openid") {
		return errors.New("OIDC provider scope must include openid")
	}
	return nil
}

// DiscoverOIDC fetches <Issuer>/.well-known/openid-configuration and fills the
// provider's empty endpoints from it. The document's issuer must equal
// provider.Issuer exactly (OpenID Connect Discovery 1.0 section 4.3); that
// equality is the trust anchor, so endpoints may live on another origin.
func (c *Client) DiscoverOIDC(ctx context.Context, provider OIDCProvider) (OIDCProvider, error) {
	if err := provider.validate(); err != nil {
		return OIDCProvider{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(provider.Issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return OIDCProvider{}, errors.New("OIDC discovery request failed")
	}
	req.Header.Set("Accept", "application/json")
	response, err := c.doNoRedirect(req)
	if err != nil {
		if errors.Is(err, errPKCERedirect) {
			return OIDCProvider{}, protocolError("discovery: unexpected redirect")
		}
		return OIDCProvider{}, fmt.Errorf("OIDC discovery: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return OIDCProvider{}, &HTTPError{Op: "discovery", StatusCode: response.StatusCode}
	}
	body, err := readPKCEBody(response, "discovery")
	if err != nil {
		return OIDCProvider{}, err
	}
	var document struct {
		Issuer                      string   `json:"issuer"`
		AuthorizationEndpoint       string   `json:"authorization_endpoint"`
		TokenEndpoint               string   `json:"token_endpoint"`
		DeviceAuthorizationEndpoint string   `json:"device_authorization_endpoint"`
		CodeChallengeMethods        []string `json:"code_challenge_methods_supported"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return OIDCProvider{}, protocolError("discovery: not a JSON document")
	}
	if document.Issuer != provider.Issuer {
		return OIDCProvider{}, protocolError("discovery: issuer mismatch")
	}
	if document.AuthorizationEndpoint == "" || document.TokenEndpoint == "" {
		return OIDCProvider{}, protocolError("discovery: authorization or token endpoint missing")
	}
	if len(document.CodeChallengeMethods) > 0 && !containsString(document.CodeChallengeMethods, "S256") {
		return OIDCProvider{}, protocolError("discovery: provider does not support PKCE S256")
	}
	if provider.AuthorizeURL == "" {
		provider.AuthorizeURL = document.AuthorizationEndpoint
	}
	if provider.TokenURL == "" {
		provider.TokenURL = document.TokenEndpoint
	}
	if provider.DeviceAuthorizationURL == "" {
		provider.DeviceAuthorizationURL = document.DeviceAuthorizationEndpoint
	}
	if err := provider.validate(); err != nil {
		return OIDCProvider{}, protocolError("discovery: " + err.Error())
	}
	return provider, nil
}

// resolveOIDCProvider validates the provider and runs discovery only when an
// endpoint the flow needs is empty: the token endpoint plus the authorization
// endpoint, or the device endpoint with needDevice. The caller checks the
// device endpoint afterwards, since not every provider advertises one.
func (c *Client) resolveOIDCProvider(ctx context.Context, provider OIDCProvider, needDevice bool) (OIDCProvider, error) {
	if err := provider.validate(); err != nil {
		return OIDCProvider{}, err
	}
	entry := provider.AuthorizeURL
	if needDevice {
		entry = provider.DeviceAuthorizationURL
	}
	if entry == "" || provider.TokenURL == "" {
		return c.DiscoverOIDC(ctx, provider)
	}
	return provider, nil
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
	provider, err := c.resolveOIDCProvider(ctx, options.Provider, false)
	if err != nil {
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

	authorize, _ := url.Parse(provider.AuthorizeURL)
	query := authorize.Query()
	query.Set("response_type", "code")
	query.Set("client_id", provider.ClientID)
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
		clientID:     provider.ClientID,
		verifier:     verifier,
		state:        state,
		nonce:        nonce,
		provider:     &provider,
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
	if provider.TokenURL == "" {
		provider.TokenURL = credential.TokenEndpoint
	}
	// Refresh needs only the token endpoint, so a provider that has one skips
	// discovery even when AuthorizeURL is empty.
	if provider.TokenURL != "" {
		if err := provider.validate(); err != nil {
			return Credential{}, err
		}
	} else {
		var err error
		if provider, err = c.resolveOIDCProvider(ctx, provider, false); err != nil {
			return Credential{}, err
		}
	}
	if credential.Issuer != "" && credential.Issuer != provider.Issuer {
		return Credential{}, ErrOriginMismatch
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", credential.RefreshToken)
	form.Set("client_id", provider.ClientID)
	token, err := c.postOIDCToken(ctx, provider.TokenURL, form, "refresh")
	if err != nil {
		return Credential{}, err
	}
	// An IdP refresh does not repeat the login nonce; only the code exchange
	// is nonce-checked. The subject must not change across a refresh, though.
	claims, err := c.oidcClaims(token.IDToken)
	if err != nil {
		return Credential{}, err
	}
	if claims.Issuer != provider.Issuer {
		return Credential{}, protocolError("refresh: id_token issuer mismatch")
	}
	if !claims.validAudience(provider.ClientID) {
		return Credential{}, protocolError("refresh: id_token audience mismatch")
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
	token, err := c.postOIDCToken(ctx, provider.TokenURL, form, "token")
	if err != nil {
		return Credential{}, err
	}
	claims, err := c.oidcClaims(token.IDToken)
	if err != nil {
		return Credential{}, err
	}
	// OIDC Core 3.1.3.7 (11): the id_token must echo the request nonce, which
	// binds it to this login and defeats token substitution.
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(session.nonce)) != 1 {
		return Credential{}, protocolError("token: id_token nonce mismatch")
	}
	if claims.Issuer != provider.Issuer {
		return Credential{}, protocolError("token: id_token issuer mismatch")
	}
	if !claims.validAudience(provider.ClientID) {
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
		if op == "refresh" {
			switch oauthErrorCode(body) {
			case "invalid_grant", "invalid_token", "access_denied":
				return oidcTokenResponse{}, ErrRefreshRejected
			}
			// OneLogin reports a disabled or locked user as invalid_request with
			// an "Access is unauthorized" description; that is a dead session too.
			if strings.Contains(strings.ToLower(oauthErrorDescription(body)), "unauthorized") {
				return oidcTokenResponse{}, ErrRefreshRejected
			}
		}
		if op == "device" {
			switch code := oauthErrorCode(body); code {
			case "authorization_pending", "slow_down":
				return oidcTokenResponse{}, &devicePollError{code: code}
			case "expired_token":
				return oidcTokenResponse{}, &LoginTimeoutError{}
			case "access_denied":
				return oidcTokenResponse{}, ErrPKCEDenied
			}
		}
		return oidcTokenResponse{}, pkceHTTPError(op, response, body, form.Get("code"), form.Get("code_verifier"), form.Get("refresh_token"), form.Get("device_code"))
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
	Issuer          string          `json:"iss"`
	Subject         string          `json:"sub"`
	Audience        json.RawMessage `json:"aud"`
	AuthorizedParty string          `json:"azp"`
	Nonce           string          `json:"nonce"`
	Exp             json.Number     `json:"exp"`
}

// validAudience implements OIDC Core 3.1.3.7 (3)-(5): aud must contain the
// client ID, a multi-valued aud requires azp, and azp must be the client ID.
func (claims oidcIDTokenClaims) validAudience(clientID string) bool {
	var audiences []string
	var single string
	if json.Unmarshal(claims.Audience, &single) == nil {
		audiences = []string{single}
	} else if json.Unmarshal(claims.Audience, &audiences) != nil {
		return false
	}
	if !containsString(audiences, clientID) {
		return false
	}
	if len(audiences) > 1 && claims.AuthorizedParty == "" {
		return false
	}
	return claims.AuthorizedParty == "" || claims.AuthorizedParty == clientID
}

func (claims oidcIDTokenClaims) expiry() time.Time {
	seconds, err := claims.Exp.Int64()
	if err != nil || seconds <= 0 {
		return time.Time{}
	}
	return time.Unix(seconds, 0)
}

func (c *Client) oidcClaims(idToken string) (oidcIDTokenClaims, error) {
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
	if !claims.expiry().After(c.now()) {
		return oidcIDTokenClaims{}, protocolError("id_token is expired")
	}
	return claims, nil
}

func (c *Client) oidcCredential(token oidcTokenResponse, claims oidcIDTokenClaims, provider OIDCProvider) Credential {
	return Credential{
		BaseURL:       c.baseURL,
		Key:           token.IDToken,
		AuthMethod:    AuthMethodOIDC,
		TokenType:     "Bearer",
		Issuer:        provider.Issuer,
		Subject:       claims.Subject,
		Scopes:        strings.Fields(provider.Scope),
		UserID:        claims.Subject,
		IssuedAt:      c.now(),
		ExpiresAt:     claims.expiry(),
		RefreshToken:  token.RefreshToken,
		ClientID:      provider.ClientID,
		TokenEndpoint: provider.TokenURL,
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
