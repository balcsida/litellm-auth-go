package litellmauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const maxOIDCTokenResponseBytes = 1 << 20

type oidcTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// Refresh exchanges credential's OIDC refresh token for a fresh access token.
func (c *Client) Refresh(ctx context.Context, credential Credential) (Credential, error) {
	if credential.AuthMethod != AuthMethodOIDC || credential.OIDCRefresh == nil || credential.OIDCRefresh.validate() != nil {
		return Credential{}, ErrInvalidCredential
	}
	refresh := credential.OIDCRefresh.Clone()
	fresh, err := c.exchangeToken(ctx, refresh.TokenEndpoint, url.Values{"grant_type": {"refresh_token"}, "client_id": {refresh.ClientID}, "refresh_token": {refresh.RefreshToken}}, refresh)
	if err != nil {
		return Credential{}, err
	}
	result := credential.Clone()
	result.Key, result.TokenType, result.AuthMethod = fresh.Key, fresh.TokenType, AuthMethodOIDC
	result.Scopes, result.OIDCRefresh = fresh.Scopes, fresh.OIDCRefresh
	result.IssuedAt, result.ExpiresAt, result.NonExpiring = fresh.IssuedAt, fresh.ExpiresAt, false
	return result, nil
}

// exchangeToken performs one public-client OAuth token exchange.
func (c *Client) exchangeToken(ctx context.Context, endpoint string, form url.Values, refresh OIDCRefresh) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	if _, err := normalizeOIDCURL(endpoint); err != nil || refresh.validate() != nil {
		return Credential{}, ErrInvalidCredential
	}
	ctx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Credential{}, ErrInvalidCredential
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := *c.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errDiscoveryRedirect }
	response, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return Credential{}, ctx.Err()
		}
		return Credential{}, errors.New("native OIDC token request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return Credential{}, &HTTPError{Op: "OIDC token", StatusCode: response.StatusCode}
	}
	if responseContentType(response) != "application/json" {
		return Credential{}, nativeOIDCProtocolError()
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxOIDCTokenResponseBytes+1))
	if err != nil || len(data) > maxOIDCTokenResponseBytes {
		return Credential{}, nativeOIDCProtocolError()
	}
	var decoded oidcTokenResponse
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&decoded); err != nil {
		return Credential{}, nativeOIDCProtocolError()
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Credential{}, nativeOIDCProtocolError()
	}
	if decoded.TokenType != "Bearer" || decoded.AccessToken == "" {
		return Credential{}, nativeOIDCProtocolError()
	}
	expiresAt, ok := jwtExpiry(decoded.AccessToken)
	if !ok || !expiresAt.After(c.now()) {
		return Credential{}, nativeOIDCProtocolError()
	}
	if decoded.RefreshToken != "" {
		refresh.RefreshToken = decoded.RefreshToken
	}
	if refresh.validate() != nil {
		return Credential{}, nativeOIDCProtocolError()
	}
	scopes := append([]string(nil), refresh.Scopes...)
	if decoded.Scope != "" {
		scopes = strings.Fields(decoded.Scope)
	}
	credential := Credential{Key: decoded.AccessToken, AuthMethod: AuthMethodOIDC, TokenType: "Bearer", Scopes: scopes, OIDCRefresh: &refresh, IssuedAt: c.now(), ExpiresAt: expiresAt}
	if err := credential.Validate(); err != nil {
		return Credential{}, nativeOIDCProtocolError()
	}
	return credential, nil
}

func (r OIDCRefresh) Clone() OIDCRefresh { r.Scopes = append([]string(nil), r.Scopes...); return r }
