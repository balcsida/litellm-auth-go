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
	"time"
)

const (
	deviceGrantType       = "urn:ietf:params:oauth:grant-type:device_code"
	defaultDeviceInterval = 5 * time.Second
)

// DeviceAuthorization is the user-facing result of a device authorization request.
type DeviceAuthorization struct {
	DeviceCode, UserCode, VerificationURI, VerificationURIComplete string
	ExpiresIn, Interval                                            time.Duration
}

// String returns a secret-free device authorization description.
func (DeviceAuthorization) String() string { return "OIDC device authorization" }

// GoString returns a secret-free device authorization description.
func (a DeviceAuthorization) GoString() string { return a.String() }

// DeviceLoginOptions configures the device authorization flow.
type DeviceLoginOptions struct {
	OnAuthorization func(context.Context, DeviceAuthorization) error
}

type deviceAuthorizationResponse struct {
	DeviceCode              string      `json:"device_code"`
	UserCode                string      `json:"user_code"`
	VerificationURI         string      `json:"verification_uri"`
	VerificationURIComplete string      `json:"verification_uri_complete"`
	ExpiresIn               json.Number `json:"expires_in"`
	Interval                json.Number `json:"interval"`
}

// AuthenticateDevice obtains an OIDC credential through the device authorization flow.
func (c *Client) AuthenticateDevice(ctx context.Context, config NativeOIDCConfig, provider OIDCProvider, options DeviceLoginOptions) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	config, err := validatedNativeOIDCConfig(config)
	if err != nil {
		return Credential{}, err
	}
	if err := provider.validate(); err != nil || provider.DeviceAuthorizationEndpoint == "" {
		return Credential{}, nativeOIDCProtocolError()
	}
	authorization, err := c.deviceAuthorization(ctx, provider.DeviceAuthorizationEndpoint, config)
	if err != nil {
		return Credential{}, err
	}
	deadline := c.now().Add(authorization.ExpiresIn)
	if maximum := c.now().Add(c.maxWait); maximum.Before(deadline) {
		deadline = maximum
	}
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	if options.OnAuthorization != nil {
		callbackCtx, cancel := context.WithDeadline(ctx, deadline)
		err := options.OnAuthorization(callbackCtx, authorization)
		cancel()
		if deadlineErr := deviceDeadline(ctx, deadline, c.now()); deadlineErr != nil {
			return Credential{}, deadlineErr
		}
		if err != nil {
			return Credential{}, err
		}
	}

	refresh := OIDCRefresh{DiscoveryURL: config.DiscoveryURL, TokenEndpoint: provider.TokenEndpoint, ClientID: config.ClientID, Scopes: config.Scopes}
	interval := authorization.Interval
	for {
		if err := deviceDeadline(ctx, deadline, c.now()); err != nil {
			return Credential{}, err
		}
		requestTimeout := c.requestTimeout
		if remaining := deadline.Sub(c.now()); remaining < requestTimeout {
			requestTimeout = remaining
		}
		requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		credential, err := c.exchangeToken(requestCtx, provider.TokenEndpoint, url.Values{"grant_type": {deviceGrantType}, "client_id": {config.ClientID}, "device_code": {authorization.DeviceCode}}, refresh)
		cancel()
		if err == nil {
			return credential, nil
		}
		if deadlineErr := deviceDeadline(ctx, deadline, c.now()); deadlineErr != nil {
			return Credential{}, deadlineErr
		}
		var tokenErr oidcTokenError
		if !errors.As(err, &tokenErr) {
			return Credential{}, err
		}
		switch tokenErr.code {
		case "authorization_pending":
		case "slow_down":
			interval += 5 * time.Second
		default:
			return Credential{}, nativeOIDCProtocolError()
		}
		if remaining := deadline.Sub(c.now()); interval > remaining {
			interval = remaining
		}
		if err := c.wait(ctx, interval); err != nil {
			if deadlineErr := deviceDeadline(ctx, deadline, c.now()); deadlineErr != nil {
				return Credential{}, deadlineErr
			}
			return Credential{}, err
		}
	}
}

func (c *Client) deviceAuthorization(ctx context.Context, endpoint string, config NativeOIDCConfig) (DeviceAuthorization, error) {
	ctx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(url.Values{"client_id": {config.ClientID}, "scope": {strings.Join(config.Scopes, " ")}}.Encode()))
	if err != nil {
		return DeviceAuthorization{}, nativeOIDCProtocolError()
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := *c.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errDiscoveryRedirect }
	response, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return DeviceAuthorization{}, ctx.Err()
		}
		return DeviceAuthorization{}, errors.New("native OIDC device authorization request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices || responseContentType(response) != "application/json" {
		return DeviceAuthorization{}, nativeOIDCProtocolError()
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxOIDCTokenResponseBytes+1))
	if err != nil || len(data) > maxOIDCTokenResponseBytes {
		return DeviceAuthorization{}, nativeOIDCProtocolError()
	}
	var decoded deviceAuthorizationResponse
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return DeviceAuthorization{}, nativeOIDCProtocolError()
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return DeviceAuthorization{}, nativeOIDCProtocolError()
	}
	return validDeviceAuthorization(decoded)
}

func validDeviceAuthorization(decoded deviceAuthorizationResponse) (DeviceAuthorization, error) {
	expires, err := decoded.ExpiresIn.Int64()
	if err != nil || expires <= 0 || expires > int64(time.Duration(1<<63-1)/time.Second) || !validNativeOIDCString(decoded.DeviceCode) || !validNativeOIDCString(decoded.UserCode) {
		return DeviceAuthorization{}, nativeOIDCProtocolError()
	}
	if _, err := normalizeOIDCURL(decoded.VerificationURI); err != nil {
		return DeviceAuthorization{}, nativeOIDCProtocolError()
	}
	if decoded.VerificationURIComplete != "" {
		if _, err := normalizeOIDCURL(decoded.VerificationURIComplete); err != nil {
			return DeviceAuthorization{}, nativeOIDCProtocolError()
		}
	}
	interval := defaultDeviceInterval
	if decoded.Interval != "" {
		seconds, err := decoded.Interval.Int64()
		if err != nil || seconds <= 0 || seconds > int64(time.Duration(1<<63-1)/time.Second) {
			return DeviceAuthorization{}, nativeOIDCProtocolError()
		}
		interval = time.Duration(seconds) * time.Second
	}
	return DeviceAuthorization{DeviceCode: decoded.DeviceCode, UserCode: decoded.UserCode, VerificationURI: decoded.VerificationURI, VerificationURIComplete: decoded.VerificationURIComplete, ExpiresIn: time.Duration(expires) * time.Second, Interval: interval}, nil
}

func deviceDeadline(ctx context.Context, deadline, now time.Time) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return context.Canceled
	}
	if !now.Before(deadline) {
		return &LoginTimeoutError{}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &LoginTimeoutError{callerDeadline: true}
	}
	return nil
}
