package litellmauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const browserCallbackPath = "/callback"

// BrowserLoginOptions configures the local browser callback flow.
type BrowserLoginOptions struct {
	OpenURL func(context.Context, *url.URL) error
	Listen  func(network, address string) (net.Listener, error)
}

type browserCallback struct {
	code string
	err  error
}

// AuthenticateBrowser obtains an OIDC credential through a local browser callback.
func (c *Client) AuthenticateBrowser(ctx context.Context, config NativeOIDCConfig, provider OIDCProvider, options BrowserLoginOptions) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	config, err := validatedNativeOIDCConfig(config)
	if err != nil {
		return Credential{}, err
	}
	if err := provider.validate(); err != nil {
		return Credential{}, err
	}
	if options.OpenURL == nil {
		return Credential{}, errors.New("native OIDC browser opener is required")
	}
	if options.Listen == nil {
		options.Listen = net.Listen
	}

	listener, err := options.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return Credential{}, err
	}
	defer listener.Close()

	state, err := randomBrowserValue()
	if err != nil {
		return Credential{}, errors.New("native OIDC browser setup failed")
	}
	verifier, err := randomBrowserValue()
	if err != nil {
		return Credential{}, errors.New("native OIDC browser setup failed")
	}
	redirect := &url.URL{Scheme: "http", Host: listener.Addr().String(), Path: browserCallbackPath}
	callback := make(chan browserCallback, 1)
	server := &http.Server{Handler: browserCallbackHandler(callback, state)}
	served := make(chan struct{})
	go func() { _ = server.Serve(listener); close(served) }()
	defer func() {
		_ = server.Close()
		<-served
	}()

	authorization, _ := normalizeOIDCURL(provider.AuthorizationEndpoint)
	query := authorization.Query()
	query.Set("response_type", "code")
	query.Set("client_id", config.ClientID)
	query.Set("redirect_uri", redirect.String())
	query.Set("scope", strings.Join(config.Scopes, " "))
	query.Set("state", state)
	sum := sha256.Sum256([]byte(verifier))
	query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	query.Set("code_challenge_method", "S256")
	authorization.RawQuery = query.Encode()
	if err := options.OpenURL(ctx, authorization); err != nil {
		return Credential{}, errors.New("native OIDC browser launch failed")
	}

	select {
	case result := <-callback:
		if result.err != nil {
			return Credential{}, result.err
		}
		refresh := OIDCRefresh{DiscoveryURL: config.DiscoveryURL, TokenEndpoint: provider.TokenEndpoint, ClientID: config.ClientID, Scopes: config.Scopes}
		return c.exchangeToken(ctx, provider.TokenEndpoint, url.Values{"grant_type": {"authorization_code"}, "client_id": {config.ClientID}, "code": {result.code}, "code_verifier": {verifier}, "redirect_uri": {redirect.String()}}, refresh)
	case <-ctx.Done():
		return Credential{}, ctx.Err()
	}
}

func browserCallbackHandler(callback chan<- browserCallback, state string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != browserCallbackPath {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		query := r.URL.Query()
		stateMatches := subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(state)) == 1
		if !stateMatches {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if query.Get("error") != "" {
			callback <- browserCallback{err: browserCallbackProtocolError()}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if query.Get("code") == "" {
			callback <- browserCallback{err: browserCallbackProtocolError()}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		callback <- browserCallback{code: query.Get("code")}
		w.WriteHeader(http.StatusOK)
	})
}

func browserCallbackProtocolError() error {
	return fmt.Errorf("%w: native OIDC browser callback", ErrProtocol)
}

func randomBrowserValue() (string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
