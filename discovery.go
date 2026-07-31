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

// providerConfigurationPath is appended to the issuer to locate the OpenID
// Provider Configuration document, per OpenID Connect Discovery 1.0.
const providerConfigurationPath = "/.well-known/openid-configuration"

var errDiscoveryRedirect = errors.New("native OIDC discovery redirect")

// NativeOIDCConfig is the public-client configuration advertised by a LiteLLM proxy.
type NativeOIDCConfig struct {
	// Issuer is the OIDC issuer identifier and the trust anchor. It is kept
	// byte-for-byte as advertised: it is compared by exact string equality
	// against the provider document, so it must never be normalized.
	Issuer   string
	ClientID string
	Scopes   []string
}

// OIDCProvider contains the endpoints advertised by an OpenID Connect provider.
type OIDCProvider struct {
	Issuer                      string
	AuthorizationEndpoint       string
	TokenEndpoint               string
	DeviceAuthorizationEndpoint string
}

type proxyDiscoveryDocument struct {
	NativeOIDC json.RawMessage `json:"native_oidc"`
}

type nativeOIDCConfig struct {
	Issuer   string   `json:"issuer"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
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
	if err := c.discoverJSON(ctx, c.endpoint(".well-known", "litellm-ui-config").String(), "proxy discovery", &document, false); err != nil {
		return nil, err
	}
	if document.NativeOIDC == nil {
		return nil, nil
	}
	var native nativeOIDCConfig
	if err := decodeNativeOIDCConfig(document.NativeOIDC, &native); err != nil {
		return nil, err
	}
	config, err := nativeOIDCConfigFrom(&native)
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
	if err := c.discoverJSON(ctx, providerConfigurationURL(config.Issuer), "provider discovery", &document, true); err != nil {
		return OIDCProvider{}, err
	}
	// The issuer is the trust anchor: a provider document that names a
	// different issuer than the one the proxy advertised is rejected outright
	// rather than followed. Compared byte-for-byte, per OpenID Connect
	// Discovery 1.0 section 4.3.
	if document.Issuer != config.Issuer {
		return OIDCProvider{}, nativeOIDCProtocolError()
	}
	provider := OIDCProvider(document)
	if err := provider.validate(); err != nil {
		return OIDCProvider{}, err
	}
	return provider, nil
}

// providerConfigurationURL derives the OpenID Provider Configuration URL from an
// issuer identifier by removing a single trailing slash and appending the
// well-known path. No other normalization is applied.
func providerConfigurationURL(issuer string) string {
	return strings.TrimSuffix(issuer, "/") + providerConfigurationPath
}

func (c *Client) discoverJSON(ctx context.Context, rawURL, op string, target any, strict bool) error {
	ctx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nativeOIDCProtocolError()
	}
	req.Header.Set("Accept", "application/json")
	client := *c.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errDiscoveryRedirect }
	response, err := client.Do(req)
	if err != nil {
		if errors.Is(err, errDiscoveryRedirect) {
			return nativeOIDCProtocolError()
		}
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
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(target); err != nil {
		return nativeOIDCProtocolError()
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nativeOIDCProtocolError()
	}
	return nil
}

func decodeNativeOIDCConfig(data json.RawMessage, target *nativeOIDCConfig) error {
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
	return validatedNativeOIDCConfig(NativeOIDCConfig{Issuer: raw.Issuer, ClientID: raw.ClientID, Scopes: raw.Scopes})
}

func validatedNativeOIDCConfig(config NativeOIDCConfig) (NativeOIDCConfig, error) {
	if !validNativeOIDCString(config.ClientID) || len(config.Scopes) == 0 {
		return NativeOIDCConfig{}, nativeOIDCProtocolError()
	}
	if !validOIDCIssuer(config.Issuer) {
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

// validOIDCIssuer reports whether value is usable as an issuer identifier.
// Stricter than a plain endpoint URL: an issuer carries no query component.
func validOIDCIssuer(value string) bool {
	parsed, err := normalizeOIDCURL(value)
	if err != nil {
		return false
	}
	return parsed.RawQuery == ""
}
