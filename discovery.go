package litellmauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const maxDiscoveryResponseBytes = 1 << 20

// NativeOIDCConfig is the public-client configuration advertised by a LiteLLM proxy.
type NativeOIDCConfig struct {
	DiscoveryURL string
	ClientID     string
	Scopes       []string
}

// OIDCProvider contains the endpoints advertised by an OpenID Connect provider.
type OIDCProvider struct {
	Issuer                      string
	AuthorizationEndpoint       string
	TokenEndpoint               string
	DeviceAuthorizationEndpoint string
}

type proxyDiscoveryDocument struct {
	NativeOIDC *nativeOIDCConfig `json:"native_oidc"`
}

type nativeOIDCConfig struct {
	DiscoveryURL string   `json:"discovery_url"`
	ClientID     string   `json:"client_id"`
	Scopes       []string `json:"scopes"`
}

type providerDiscoveryDocument struct {
	Issuer                      string `json:"issuer"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

// Discover reads native OIDC configuration advertised by the LiteLLM proxy.
func (c *Client) Discover(ctx context.Context) (*NativeOIDCConfig, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var document proxyDiscoveryDocument
	if err := c.discoverJSON(ctx, c.endpoint(".well-known", "litellm-ui-config").String(), "proxy discovery", &document); err != nil {
		return nil, err
	}
	if document.NativeOIDC == nil {
		return nil, nil
	}
	config, err := nativeOIDCConfigFrom(document.NativeOIDC)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// DiscoverProvider reads the OpenID Connect provider document advertised by config.
func (c *Client) DiscoverProvider(ctx context.Context, config NativeOIDCConfig) (OIDCProvider, error) {
	if err := ctx.Err(); err != nil {
		return OIDCProvider{}, err
	}
	if _, err := validatedNativeOIDCConfig(config); err != nil {
		return OIDCProvider{}, err
	}
	var document providerDiscoveryDocument
	if err := c.discoverJSON(ctx, config.DiscoveryURL, "provider discovery", &document); err != nil {
		return OIDCProvider{}, err
	}
	provider := OIDCProvider{
		Issuer:                      document.Issuer,
		AuthorizationEndpoint:       document.AuthorizationEndpoint,
		TokenEndpoint:               document.TokenEndpoint,
		DeviceAuthorizationEndpoint: document.DeviceAuthorizationEndpoint,
	}
	if err := provider.validate(); err != nil {
		return OIDCProvider{}, err
	}
	return provider, nil
}

func (c *Client) discoverJSON(ctx context.Context, rawURL, op string, target any) error {
	ctx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nativeOIDCProtocolError()
	}
	req.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("native OIDC " + op + " request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return HTTPError{Op: op, StatusCode: response.StatusCode}
	}
	if responseContentType(response) != "application/json" {
		return nativeOIDCProtocolError()
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxDiscoveryResponseBytes+1))
	if err != nil || len(data) > maxDiscoveryResponseBytes {
		return nativeOIDCProtocolError()
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return nativeOIDCProtocolError()
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nativeOIDCProtocolError()
	}
	return nil
}

func nativeOIDCConfigFrom(raw *nativeOIDCConfig) (NativeOIDCConfig, error) {
	if raw == nil {
		return NativeOIDCConfig{}, nativeOIDCProtocolError()
	}
	return validatedNativeOIDCConfig(NativeOIDCConfig{DiscoveryURL: raw.DiscoveryURL, ClientID: raw.ClientID, Scopes: raw.Scopes})
}

func validatedNativeOIDCConfig(config NativeOIDCConfig) (NativeOIDCConfig, error) {
	if !validNativeOIDCString(config.ClientID) || len(config.Scopes) == 0 {
		return NativeOIDCConfig{}, nativeOIDCProtocolError()
	}
	if _, err := normalizeOIDCURL(config.DiscoveryURL); err != nil {
		return NativeOIDCConfig{}, nativeOIDCProtocolError()
	}
	for _, scope := range config.Scopes {
		if !validNativeOIDCString(scope) {
			return NativeOIDCConfig{}, nativeOIDCProtocolError()
		}
	}
	config.Scopes = append([]string(nil), config.Scopes...)
	return config, nil
}

func (provider OIDCProvider) validate() error {
	for _, rawURL := range []string{provider.Issuer, provider.AuthorizationEndpoint, provider.TokenEndpoint} {
		if _, err := normalizeOIDCURL(rawURL); err != nil {
			return nativeOIDCProtocolError()
		}
	}
	if provider.DeviceAuthorizationEndpoint != "" {
		if _, err := normalizeOIDCURL(provider.DeviceAuthorizationEndpoint); err != nil {
			return nativeOIDCProtocolError()
		}
	}
	return nil
}

func validNativeOIDCString(value string) bool {
	return strings.TrimSpace(value) != "" && !containsControl(value)
}
