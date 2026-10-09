package litellmauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestOIDCDeviceRoundTrip(t *testing.T) {
	idp := newFakeIdP(t)
	idp.pendingRounds = 1
	client := idp.client(t)

	var seen DeviceAuthorization
	credential, err := client.AuthenticateOIDCDevice(context.Background(), OIDCDeviceOptions{
		Provider: idp.provider(),
		OnAuthorization: func(_ context.Context, authorization DeviceAuthorization) error {
			seen = authorization
			return nil
		},
	})
	if err != nil {
		t.Fatalf("AuthenticateOIDCDevice: %v", err)
	}
	if credential.AuthMethod != AuthMethodOIDC || credential.Subject != "NH10000001" ||
		credential.TokenEndpoint != idp.srv.URL+"/oidc/2/token" || !strings.HasPrefix(credential.Key, "eyJ") {
		t.Fatalf("credential = %+v", credential)
	}
	if err := credential.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if seen.UserCode != "WDJB-MJHT" || seen.VerificationURI != idp.srv.URL+"/oidc/2/activate" ||
		seen.VerificationURIComplete != seen.VerificationURI+"?user_code=WDJB-MJHT" || seen.Interval != time.Second {
		t.Fatalf("authorization = %+v", seen)
	}
	if polls := idp.devicePollCount(); polls != 2 {
		t.Fatalf("polls = %d, want 2", polls)
	}
}

func TestOIDCDeviceExplicitEndpointsSkipDiscovery(t *testing.T) {
	idp := newFakeIdP(t)
	client := idp.client(t)
	// Device login needs only the device and token endpoints; an explicit
	// AuthorizeURL is not required to skip discovery.
	provider := idp.provider()
	provider.DeviceAuthorizationURL = idp.srv.URL + "/oidc/2/device"
	provider.TokenURL = idp.srv.URL + "/oidc/2/token"
	if _, err := client.AuthenticateOIDCDevice(context.Background(), OIDCDeviceOptions{Provider: provider}); err != nil {
		t.Fatalf("AuthenticateOIDCDevice: %v", err)
	}
	if calls := idp.discoveryCallCount(); calls != 0 {
		t.Fatalf("discovery calls = %d", calls)
	}
}

func TestOIDCDeviceUnsupported(t *testing.T) {
	idp := newFakeIdP(t)
	idp.omitDeviceEndpoint = true
	_, err := idp.client(t).AuthenticateOIDCDevice(context.Background(), OIDCDeviceOptions{Provider: idp.provider()})
	if !errors.Is(err, ErrOIDCDeviceUnsupported) {
		t.Fatalf("err = %v", err)
	}
}

func TestOIDCDeviceOnAuthorizationErrorAborts(t *testing.T) {
	idp := newFakeIdP(t)
	sentinel := errors.New("stop")
	_, err := idp.client(t).AuthenticateOIDCDevice(context.Background(), OIDCDeviceOptions{
		Provider:        idp.provider(),
		OnAuthorization: func(context.Context, DeviceAuthorization) error { return sentinel },
	})
	if polls := idp.devicePollCount(); err != sentinel || polls != 0 {
		t.Fatalf("err = %v polls = %d", err, polls)
	}
}

func TestOIDCDeviceDenied(t *testing.T) {
	idp := newFakeIdP(t)
	idp.denyDevice = true
	_, err := idp.client(t).AuthenticateOIDCDevice(context.Background(), OIDCDeviceOptions{Provider: idp.provider()})
	if !errors.Is(err, ErrPKCEDenied) {
		t.Fatalf("err = %v", err)
	}
}

func TestOIDCDeviceExpiredToken(t *testing.T) {
	idp := newFakeIdP(t)
	idp.expireDevice = true
	_, err := idp.client(t).AuthenticateOIDCDevice(context.Background(), OIDCDeviceOptions{Provider: idp.provider()})
	var timeout *LoginTimeoutError
	if !errors.As(err, &timeout) {
		t.Fatalf("err = %v", err)
	}
}

func TestOIDCDeviceCallerDeadline(t *testing.T) {
	idp := newFakeIdP(t)
	idp.pendingRounds = 10
	idp.deviceInterval = 30
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := idp.client(t).AuthenticateOIDCDevice(ctx, OIDCDeviceOptions{Provider: idp.provider()})
	var timeout *LoginTimeoutError
	if !errors.As(err, &timeout) || !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrLoginExpired) {
		t.Fatalf("err = %v", err)
	}
}

func TestOIDCDeviceExpiresIn(t *testing.T) {
	idp := newFakeIdP(t)
	idp.pendingRounds = 10
	idp.deviceExpiresIn = 1
	start := time.Now()
	_, err := idp.client(t).AuthenticateOIDCDevice(context.Background(), OIDCDeviceOptions{Provider: idp.provider()})
	var timeout *LoginTimeoutError
	if !errors.As(err, &timeout) || !errors.Is(err, ErrLoginExpired) {
		t.Fatalf("err = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("took %v", elapsed)
	}
}

func TestOIDCDeviceMalformedAuthorization(t *testing.T) {
	for name, mutate := range map[string]func(*fakeIdP){
		"missing device_code": func(idp *fakeIdP) { idp.omitDeviceCode = true },
		"negative interval":   func(idp *fakeIdP) { idp.deviceInterval = -1 },
		"zero expires_in":     func(idp *fakeIdP) { idp.deviceExpiresIn = 0 },
		"bad verification":    func(idp *fakeIdP) { idp.deviceVerificationURI = "not a url" },
		"http verification":   func(idp *fakeIdP) { idp.deviceVerificationURI = "http://example.com/activate" },
	} {
		t.Run(name, func(t *testing.T) {
			idp := newFakeIdP(t)
			mutate(idp)
			_, err := idp.client(t).AuthenticateOIDCDevice(context.Background(), OIDCDeviceOptions{Provider: idp.provider()})
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestOIDCDeviceRejectsForeignIDToken(t *testing.T) {
	for name, mutate := range map[string]func(*fakeIdP){
		"issuer":   func(idp *fakeIdP) { idp.issuer = "https://evil.example.com" },
		"audience": func(idp *fakeIdP) { idp.audience = "other-client" },
	} {
		t.Run(name, func(t *testing.T) {
			idp := newFakeIdP(t)
			provider := idp.provider()
			mutate(idp)
			_, err := idp.client(t).AuthenticateOIDCDevice(context.Background(), OIDCDeviceOptions{Provider: provider})
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestNextDeviceInterval(t *testing.T) {
	if got := nextDeviceInterval(5*time.Second, "slow_down"); got != 10*time.Second {
		t.Fatalf("slow_down = %v", got)
	}
	if got := nextDeviceInterval(5*time.Second, "authorization_pending"); got != 5*time.Second {
		t.Fatalf("pending = %v", got)
	}
}

func TestDeviceAuthorizationHidesDeviceCode(t *testing.T) {
	authorization := DeviceAuthorization{UserCode: "ABCD", deviceCode: "secret-device-code"}
	for _, text := range []string{
		authorization.String(), authorization.GoString(),
		fmt.Sprintf("%v", authorization), fmt.Sprintf("%+v", authorization), fmt.Sprintf("%#v", authorization),
	} {
		if strings.Contains(text, "secret-device-code") {
			t.Fatalf("leaked device code in %q", text)
		}
	}
}
