package litellmauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AuthMethodPKCE marks a credential minted by the proxy's OAuth 2.1
// authorization-code + PKCE flow (LiteLLM >= 1.99, `lite login --pkce`).
const AuthMethodPKCE AuthMethod = "litellm-pkce"

// pkceDiscoveryPath is the versioned discovery document a proxy publishes when
// it supports native CLI clients.
const pkceDiscoveryPath = "/.well-known/litellm-cli-auth"

// pkceClientName is the client_name sent at dynamic client registration.
const pkceClientName = "litellm-auth-go"

// maxPKCEResponseBytes caps every discovery, registration, and token body.
const maxPKCEResponseBytes = 256 * 1024

// ErrPKCEUnsupported reports a proxy without the native CLI auth contract.
var ErrPKCEUnsupported = errors.New("proxy does not support LiteLLM native CLI login")

// ErrPKCEDenied reports that the user denied the sign-in on the consent page.
var ErrPKCEDenied = errors.New("LiteLLM login was denied in the browser")

// ErrRefreshRejected reports a refresh token the proxy will no longer honour
// (`invalid_grant`): revoked, replaced by a newer login, or expired. The only
// remedy is a fresh login.
var ErrRefreshRejected = errors.New("LiteLLM refresh token was rejected; sign in again")

// ErrProxyUnavailable reports a 503 from the proxy's token or revocation
// endpoint: the proxy could not reach its shared cache. Retry shortly; the
// stored credential is still valid as far as the proxy knows.
var ErrProxyUnavailable = errors.New("LiteLLM proxy is temporarily unavailable")

// PKCEContract is the proxy's native CLI auth discovery document. Every
// endpoint has been verified to share the proxy's origin before a contract is
// returned, so credentials can never be posted elsewhere.
type PKCEContract struct {
	ContractVersion       int    `json:"contract_version"`
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	Resource              string `json:"resource"`

	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

// PKCESession is one in-progress browser sign-in. The verifier and state are
// never exported or serialized; the loopback listener is bound before the
// authorize URL is built, so the redirect URI is exact.
type PKCESession struct {
	// AuthorizeURL is the proxy URL the user opens in a browser.
	AuthorizeURL *url.URL
	// RedirectURI is the loopback callback, e.g. http://127.0.0.1:54321/callback.
	RedirectURI string

	contract PKCEContract
	clientID string
	verifier string
	state    string
	listener net.Listener
}

// String returns a secret-free session description.
func (PKCESession) String() string { return "LiteLLM PKCE login session" }

// GoString returns a secret-free session description.
func (s PKCESession) GoString() string { return s.String() }

// Close releases the loopback listener. It is safe after Wait has returned.
func (s *PKCESession) Close() error {
	if s.listener == nil {
		return nil
	}
	return s.listener.Close()
}

// PKCEOptions configures Client.AuthenticatePKCE.
type PKCEOptions struct {
	// OnSession receives the session before waiting, typically to open its URL.
	OnSession func(context.Context, PKCESession) error
	// RedirectPorts lists loopback ports to try in order for the callback
	// listener. Empty means an OS-assigned port (RFC 8252 default).
	RedirectPorts []int
}

// DiscoverPKCE fetches and validates the proxy's native CLI auth contract.
// It fails closed: a 404, a non-JSON body, an unsupported contract version, a
// missing S256, or any endpoint outside the proxy's origin is an error.
func (c *Client) DiscoverPKCE(ctx context.Context) (PKCEContract, error) {
	target := c.endpoint(".well-known", "litellm-cli-auth")
	ctx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return PKCEContract{}, fmt.Errorf("LiteLLM PKCE discovery request failed")
	}
	req.Header.Set("Accept", "application/json")
	response, err := c.doNoRedirect(req)
	if err != nil {
		return PKCEContract{}, fmt.Errorf("LiteLLM PKCE discovery: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return PKCEContract{}, fmt.Errorf("%w: upgrade the LiteLLM proxy to 1.99 or later", ErrPKCEUnsupported)
	}
	body, err := readPKCEBody(response, "discovery")
	if err != nil {
		return PKCEContract{}, err
	}
	var contract PKCEContract
	if err := json.Unmarshal(body, &contract); err != nil {
		return PKCEContract{}, protocolError("discovery: not a JSON contract")
	}
	if contract.ContractVersion != 1 {
		return PKCEContract{}, fmt.Errorf("%w: contract version %d", ErrPKCEUnsupported, contract.ContractVersion)
	}
	if !containsString(contract.CodeChallengeMethodsSupported, "S256") {
		return PKCEContract{}, fmt.Errorf("%w: S256 not offered", ErrPKCEUnsupported)
	}
	// RFC 8414 §3.3: the document must be issued for the proxy it came from,
	// and every endpoint must stay on that origin.
	for name, endpoint := range map[string]string{
		"issuer":                 contract.Issuer,
		"authorization_endpoint": contract.AuthorizationEndpoint,
		"token_endpoint":         contract.TokenEndpoint,
		"registration_endpoint":  contract.RegistrationEndpoint,
		"revocation_endpoint":    contract.RevocationEndpoint,
		"resource":               contract.Resource,
	} {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.User != nil || !sameOrigin(c.baseURL, parsed) {
			return PKCEContract{}, protocolError("discovery: " + name + " is outside the proxy origin")
		}
	}
	return contract, nil
}

// StartPKCE registers a public client, binds the loopback listener, and
// returns the session whose AuthorizeURL the user must open. Callers must
// Close the session (Wait does so when it returns).
func (c *Client) StartPKCE(ctx context.Context, options PKCEOptions) (*PKCESession, error) {
	contract, err := c.DiscoverPKCE(ctx)
	if err != nil {
		return nil, err
	}
	listener, err := listenLoopback(options.RedirectPorts)
	if err != nil {
		return nil, err
	}
	redirectURI := "http://" + listener.Addr().String() + "/callback"

	clientID, err := c.registerPKCEClient(ctx, contract, redirectURI)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
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

	authorize, _ := url.Parse(contract.AuthorizationEndpoint)
	query := url.Values{}
	query.Set("response_type", "code")
	query.Set("client_id", clientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("state", state)
	query.Set("code_challenge", challengeS256(verifier))
	query.Set("code_challenge_method", "S256")
	query.Set("resource", contract.Resource)
	authorize.RawQuery = query.Encode()

	return &PKCESession{
		AuthorizeURL: authorize,
		RedirectURI:  redirectURI,
		contract:     contract,
		clientID:     clientID,
		verifier:     verifier,
		state:        state,
		listener:     listener,
	}, nil
}

// Wait serves the loopback callback until the browser returns or ctx ends,
// then redeems the code. The listener is closed on every path.
func (c *Client) Wait(ctx context.Context, session *PKCESession) (Credential, error) {
	defer func() { _ = session.Close() }()
	if session.listener == nil {
		return Credential{}, errors.New("LiteLLM PKCE session is not started")
	}
	ctx, cancel := context.WithTimeout(ctx, c.maxWait)
	defer cancel()

	type outcome struct {
		code string
		err  error
	}
	outcomes := make(chan outcome, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code, err := session.parseCallback(r.URL.Query())
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, pkceFailureHTML)
		} else {
			_, _ = io.WriteString(w, pkceSuccessHTML)
		}
		select {
		case outcomes <- outcome{code, err}:
		default: // only the first callback counts
		}
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server.Serve(session.listener) }()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()

	select {
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			// The browser never reached the loopback callback: the sign-in was
			// abandoned, or the authorize URL was altered (a wrapped copy-paste
			// makes the proxy answer 400 instead of redirecting here).
			return Credential{}, LoginTimeoutError{}
		}
		return Credential{}, ctx.Err()
	case result := <-outcomes:
		if result.err != nil {
			return Credential{}, result.err
		}
		return c.redeemPKCECode(ctx, session, result.code)
	}
}

// AuthenticatePKCE runs the whole browser flow: discover, register, open the
// browser via OnSession, wait for the callback, and redeem the code.
func (c *Client) AuthenticatePKCE(ctx context.Context, options PKCEOptions) (Credential, error) {
	session, err := c.StartPKCE(ctx, options)
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

// RefreshPKCE renews a PKCE credential with its refresh token. The proxy
// rotates the pair: callers must persist the returned credential before using
// it, since the previous refresh token is dead once this returns.
func (c *Client) RefreshPKCE(ctx context.Context, credential Credential) (Credential, error) {
	if credential.AuthMethod != AuthMethodPKCE || credential.RefreshToken == "" || credential.TokenEndpoint == "" {
		return Credential{}, fmt.Errorf("%w: credential has no refresh token", ErrRefreshRejected)
	}
	tokenEndpoint, err := url.Parse(credential.TokenEndpoint)
	if err != nil || !sameOrigin(c.baseURL, tokenEndpoint) {
		return Credential{}, ErrOriginMismatch
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", credential.RefreshToken)
	form.Set("client_id", credential.ClientID)
	form.Set("resource", credential.Resource)
	renewed, err := c.postPKCEToken(ctx, credential.TokenEndpoint, form, "refresh")
	if err != nil {
		return Credential{}, err
	}
	return c.pkceCredential(renewed, credential.ClientID, credential.TokenEndpoint, credential.RevocationEndpoint, credential.Resource), nil
}

// RevokePKCE tells the proxy to revoke the credential's refresh token (RFC
// 7009), so a logout is more than deleting a local file. ErrProxyUnavailable
// means the proxy could not reach its cache: keep the credential and retry.
func (c *Client) RevokePKCE(ctx context.Context, credential Credential) error {
	if credential.AuthMethod != AuthMethodPKCE || credential.RefreshToken == "" || credential.RevocationEndpoint == "" {
		return nil
	}
	revocation, err := url.Parse(credential.RevocationEndpoint)
	if err != nil || !sameOrigin(c.baseURL, revocation) {
		return ErrOriginMismatch
	}
	form := url.Values{}
	form.Set("token", credential.RefreshToken)
	form.Set("token_type_hint", "refresh_token")
	form.Set("client_id", credential.ClientID)
	response, err := c.postForm(ctx, credential.RevocationEndpoint, form)
	if err != nil {
		return fmt.Errorf("LiteLLM PKCE revoke: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxPKCEResponseBytes))
	switch {
	case response.StatusCode == http.StatusServiceUnavailable:
		return ErrProxyUnavailable
	case response.StatusCode != http.StatusOK:
		return &HTTPError{Op: "revoke", StatusCode: response.StatusCode}
	}
	return nil
}

func (s *PKCESession) parseCallback(query url.Values) (string, error) {
	if subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(s.state)) != 1 {
		return "", errors.New("LiteLLM PKCE callback state mismatch")
	}
	if oauthError := query.Get("error"); oauthError != "" {
		if oauthError == "access_denied" {
			return "", ErrPKCEDenied
		}
		return "", fmt.Errorf("LiteLLM PKCE callback error: %s", safeHTTPErrorDetail(oauthError))
	}
	code := query.Get("code")
	if code == "" {
		return "", errors.New("LiteLLM PKCE callback has no authorization code")
	}
	return code, nil
}

func (c *Client) registerPKCEClient(ctx context.Context, contract PKCEContract, redirectURI string) (string, error) {
	payload, _ := json.Marshal(map[string]any{
		"client_name":                pkceClientName,
		"redirect_uris":              []string{redirectURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
	requestCtx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, contract.RegistrationEndpoint, strings.NewReader(string(payload)))
	if err != nil {
		return "", errors.New("LiteLLM PKCE registration request failed")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	response, err := c.doNoRedirect(req)
	if err != nil {
		return "", fmt.Errorf("LiteLLM PKCE registration: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		return "", pkceHTTPError("register", response)
	}
	body, err := readPKCEBody(response, "register")
	if err != nil {
		return "", err
	}
	var registered struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(body, &registered); err != nil || registered.ClientID == "" || containsControl(registered.ClientID) {
		return "", protocolError("register: no client_id")
	}
	return registered.ClientID, nil
}

func (c *Client) redeemPKCECode(ctx context.Context, session *PKCESession, code string) (Credential, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", session.RedirectURI)
	form.Set("client_id", session.clientID)
	form.Set("code_verifier", session.verifier)
	form.Set("resource", session.contract.Resource)
	token, err := c.postPKCEToken(ctx, session.contract.TokenEndpoint, form, "token")
	if err != nil {
		return Credential{}, err
	}
	return c.pkceCredential(token, session.clientID, session.contract.TokenEndpoint, session.contract.RevocationEndpoint, session.contract.Resource), nil
}

type pkceTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	UserID       string `json:"user_id"`
	TeamID       string `json:"team_id"`
}

func (c *Client) postPKCEToken(ctx context.Context, endpoint string, form url.Values, op string) (pkceTokenResponse, error) {
	response, err := c.postForm(ctx, endpoint, form)
	if err != nil {
		return pkceTokenResponse{}, fmt.Errorf("LiteLLM PKCE %s: %w", op, err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusServiceUnavailable {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxPKCEResponseBytes))
		return pkceTokenResponse{}, ErrProxyUnavailable
	}
	body, err := readPKCEBody(response, op)
	if err != nil && response.StatusCode == http.StatusOK {
		return pkceTokenResponse{}, err
	}
	if response.StatusCode != http.StatusOK {
		if oauthErrorCode(body) == "invalid_grant" {
			return pkceTokenResponse{}, ErrRefreshRejected
		}
		return pkceTokenResponse{}, pkceHTTPError(op, response, body)
	}
	var token pkceTokenResponse
	if err := json.Unmarshal(body, &token); err != nil ||
		token.AccessToken == "" || token.RefreshToken == "" || token.ExpiresIn <= 0 ||
		containsKeySpaceOrControl(token.AccessToken) || containsControl(token.UserID) || containsControl(token.TeamID) {
		return pkceTokenResponse{}, protocolError(op + ": malformed token response")
	}
	return token, nil
}

func (c *Client) pkceCredential(token pkceTokenResponse, clientID, tokenEndpoint, revocationEndpoint, resource string) Credential {
	now := c.now()
	tokenType := token.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	return Credential{
		BaseURL:            c.baseURL,
		Key:                token.AccessToken,
		AuthMethod:         AuthMethodPKCE,
		TokenType:          tokenType,
		Issuer:             c.baseURL,
		UserID:             token.UserID,
		TeamID:             token.TeamID,
		IssuedAt:           now,
		ExpiresAt:          now.Add(time.Duration(token.ExpiresIn) * time.Second),
		RefreshToken:       token.RefreshToken,
		ClientID:           clientID,
		TokenEndpoint:      tokenEndpoint,
		RevocationEndpoint: revocationEndpoint,
		Resource:           resource,
	}
}

// postForm posts a URL-encoded form without following redirects: a 307/308
// would replay the code, verifier, or refresh token wherever Location points.
func (c *Client) postForm(ctx context.Context, endpoint string, form url.Values) (*http.Response, error) {
	requestCtx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	response, err := func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, errors.New("request build failed")
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		return c.doNoRedirect(req)
	}()
	if err != nil {
		cancel()
		return nil, err
	}
	// Tie the body's lifetime to the context: closing the body releases it.
	response.Body = &cancelOnClose{ReadCloser: response.Body, cancel: cancel}
	return response, nil
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelOnClose) Close() error {
	b.cancel()
	return b.ReadCloser.Close()
}

var errPKCERedirect = errors.New("redirects are not allowed")

func (c *Client) doNoRedirect(req *http.Request) (*http.Response, error) {
	client := *c.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errPKCERedirect }
	response, err := client.Do(req)
	if err != nil {
		if errors.Is(err, errPKCERedirect) {
			return nil, errPKCERedirect
		}
		if req.Context().Err() != nil {
			return nil, req.Context().Err()
		}
		return nil, errors.New("request failed")
	}
	return response, nil
}

func readPKCEBody(response *http.Response, op string) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(response.Body, maxPKCEResponseBytes+1))
	if err != nil {
		return nil, protocolReadError(op, err)
	}
	if len(body) > maxPKCEResponseBytes {
		return nil, protocolError(op + ": response too large")
	}
	return body, nil
}

func oauthErrorCode(body []byte) string {
	var decoded struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &decoded) != nil {
		return ""
	}
	return decoded.Error
}

func pkceHTTPError(op string, response *http.Response, body ...[]byte) error {
	detail := ""
	if len(body) > 0 {
		var decoded struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
			Detail           string `json:"detail"`
		}
		if json.Unmarshal(body[0], &decoded) == nil {
			detail = strings.TrimSpace(decoded.ErrorDescription)
			if detail == "" {
				detail = decoded.Error
			}
			if detail == "" {
				detail = decoded.Detail
			}
		}
	}
	return &HTTPError{
		Op:         op,
		StatusCode: response.StatusCode,
		Detail:     safeHTTPErrorDetail(detail),
		Retryable:  response.StatusCode == http.StatusTooManyRequests,
	}
}

// listenLoopback binds a literal 127.0.0.1 address (never "localhost", whose
// resolution an attacker could influence) on the first free port listed, or an
// OS-assigned port when ports is empty.
func listenLoopback(ports []int) (net.Listener, error) {
	if len(ports) == 0 {
		ports = []int{0}
	}
	var lastErr error
	for _, port := range ports {
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			return listener, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("LiteLLM PKCE loopback listener: %w", lastErr)
}

func randomURLSafe(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", errors.New("LiteLLM PKCE random generation failed")
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func challengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

const pkceSuccessHTML = `<!DOCTYPE html><html><head><title>LiteLLM login</title></head><body><h1>Signed in to LiteLLM.</h1><p>You can close this window and return to the terminal.</p></body></html>`

// pkceFailureHTML never reflects callback parameters, so a crafted redirect
// cannot inject markup.
const pkceFailureHTML = `<!DOCTYPE html><html><head><title>LiteLLM login</title></head><body><h1>Login failed</h1><p>Return to the terminal for details.</p></body></html>`
