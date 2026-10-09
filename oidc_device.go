package litellmauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"time"
)

// ErrOIDCDeviceUnsupported reports an identity provider without a device authorization endpoint.
var ErrOIDCDeviceUnsupported = errors.New("identity provider does not offer device authorization")

// defaultDeviceInterval is the polling interval of RFC 8628 section 3.2 when
// the provider names none; slowDownStep is added on every slow_down answer.
const (
	defaultDeviceInterval = 5 * time.Second
	slowDownStep          = 5 * time.Second
)

// DeviceAuthorization is what the user needs to approve the login on another
// device. The device code stays private to the client.
type DeviceAuthorization struct {
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresIn               time.Duration
	Interval                time.Duration
	deviceCode              string
}

// String hides the device code from fmt.
func (DeviceAuthorization) String() string { return "OIDC device authorization" }

// GoString hides the device code from %#v.
func (DeviceAuthorization) GoString() string { return "OIDC device authorization" }

// OIDCDeviceOptions configures Client.AuthenticateOIDCDevice.
type OIDCDeviceOptions struct {
	// Provider is the identity provider and public client to sign in with.
	Provider OIDCProvider
	// OnAuthorization receives the user code and verification URIs before
	// polling, typically to print them. An error aborts the login.
	OnAuthorization func(context.Context, DeviceAuthorization) error
}

// devicePollError carries authorization_pending or slow_down from the token endpoint.
type devicePollError struct{ code string }

func (e *devicePollError) Error() string { return "OIDC device: " + e.code }

// nextDeviceInterval returns the polling interval after a token endpoint answer.
func nextDeviceInterval(interval time.Duration, code string) time.Duration {
	if code == "slow_down" {
		return interval + slowDownStep
	}
	return interval
}

func validVerificationURI(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http" && isLoopbackHost(u.Hostname())) && u.Host != "" && u.User == nil
}

// AuthenticateOIDCDevice runs the OAuth 2.0 device authorization grant (RFC
// 8628) for hosts without a browser. The id_token becomes the bearer exactly
// as in AuthenticateOIDC; RFC 8628 has no nonce, so none is checked.
func (c *Client) AuthenticateOIDCDevice(ctx context.Context, options OIDCDeviceOptions) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	provider, err := c.resolveOIDCProvider(ctx, options.Provider, true)
	if err != nil {
		return Credential{}, err
	}
	if provider.DeviceAuthorizationURL == "" {
		return Credential{}, ErrOIDCDeviceUnsupported
	}
	authorization, err := c.requestDeviceAuthorization(ctx, provider, options.Provider.Scope)
	if err != nil {
		return Credential{}, err
	}
	expiresIn := authorization.ExpiresIn
	if expiresIn > c.maxWait {
		expiresIn = c.maxWait
	}
	deadline := c.now().Add(expiresIn)
	if options.OnAuthorization != nil {
		if err := options.OnAuthorization(ctx, authorization); err != nil {
			return Credential{}, err
		}
	}

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("device_code", authorization.deviceCode)
	form.Set("client_id", provider.ClientID)
	interval := authorization.Interval
	for {
		if err := deviceDeadline(ctx, deadline, c.now()); err != nil {
			return Credential{}, err
		}
		token, err := c.postOIDCToken(ctx, provider.TokenURL, form, "device")
		if err == nil {
			claims, err := c.oidcClaims(token.IDToken)
			if err != nil {
				return Credential{}, err
			}
			if claims.Issuer != provider.Issuer {
				return Credential{}, protocolError("device: id_token issuer mismatch")
			}
			if !claims.validAudience(provider.ClientID) {
				return Credential{}, protocolError("device: id_token audience mismatch")
			}
			return c.oidcCredential(token, claims, provider), nil
		}
		var pending *devicePollError
		if !errors.As(err, &pending) {
			if deadlineErr := deviceDeadline(ctx, deadline, c.now()); deadlineErr != nil {
				return Credential{}, deadlineErr
			}
			return Credential{}, err
		}
		interval = nextDeviceInterval(interval, pending.code)
		now := c.now()
		delay := interval
		if remaining := deadline.Sub(now); delay > remaining {
			delay = remaining
		}
		if err := c.wait(ctx, delay); err != nil {
			if deadlineErr := deviceDeadline(ctx, deadline, c.now()); deadlineErr != nil {
				return Credential{}, deadlineErr
			}
			return Credential{}, err
		}
	}
}

func (c *Client) requestDeviceAuthorization(ctx context.Context, provider OIDCProvider, scope string) (DeviceAuthorization, error) {
	form := url.Values{}
	form.Set("client_id", provider.ClientID)
	form.Set("scope", scope)
	response, err := c.postForm(ctx, provider.DeviceAuthorizationURL, form)
	if err != nil {
		return DeviceAuthorization{}, fmt.Errorf("OIDC device: %w", err)
	}
	defer response.Body.Close()
	body, err := readPKCEBody(response, "device")
	if err != nil && response.StatusCode == http.StatusOK {
		return DeviceAuthorization{}, err
	}
	if response.StatusCode != http.StatusOK {
		return DeviceAuthorization{}, pkceHTTPError("device", response, body)
	}
	var decoded struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int64  `json:"expires_in"`
		Interval                int64  `json:"interval"`
	}
	const maxSeconds = math.MaxInt64 / int64(time.Second)
	if err := json.Unmarshal(body, &decoded); err != nil ||
		decoded.DeviceCode == "" || containsKeySpaceOrControl(decoded.DeviceCode) ||
		decoded.UserCode == "" || containsKeySpaceOrControl(decoded.UserCode) ||
		decoded.ExpiresIn <= 0 || decoded.ExpiresIn > maxSeconds ||
		decoded.Interval < 0 || decoded.Interval > maxSeconds ||
		!validVerificationURI(decoded.VerificationURI) ||
		(decoded.VerificationURIComplete != "" && !validVerificationURI(decoded.VerificationURIComplete)) {
		return DeviceAuthorization{}, protocolError("device: malformed authorization response")
	}
	interval := time.Duration(decoded.Interval) * time.Second
	if interval == 0 {
		interval = defaultDeviceInterval
	}
	return DeviceAuthorization{
		UserCode:                decoded.UserCode,
		VerificationURI:         decoded.VerificationURI,
		VerificationURIComplete: decoded.VerificationURIComplete,
		ExpiresIn:               time.Duration(decoded.ExpiresIn) * time.Second,
		Interval:                interval,
		deviceCode:              decoded.DeviceCode,
	}, nil
}

// deviceDeadline maps cancellation and expiry to the login errors, like awaitDeadline.
func deviceDeadline(ctx context.Context, deadline, now time.Time) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return context.Canceled
	}
	expired := !now.Before(deadline)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		if callerDeadline, ok := ctx.Deadline(); expired && ok && !callerDeadline.Before(deadline) {
			return &LoginTimeoutError{}
		}
		return &LoginTimeoutError{callerDeadline: true}
	}
	if expired {
		return &LoginTimeoutError{}
	}
	return nil
}
