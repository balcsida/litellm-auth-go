package litellmauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAuthenticateDeviceAuthorizesAndPolls(t *testing.T) {
	var authorization DeviceAuthorization
	var deviceForm, tokenForm url.Values
	tokenCalls := 0
	server := loopbackServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		switch r.URL.Path {
		case "/device":
			deviceForm = form
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"device_code":"device-code","user_code":"USER-CODE","verification_uri":"https://verify.example.com","verification_uri_complete":"https://verify.example.com/?user_code=USER-CODE","expires_in":60,"interval":3}`))
		case "/token":
			tokenCalls++
			tokenForm = form
			w.Header().Set("Content-Type", "application/json")
			if tokenCalls == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"` + oidcJWT(time.Now().Add(time.Hour)) + `","token_type":"Bearer","refresh_token":"refresh"}`))
		default:
			t.Fatalf("path = %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client, _ := New(server.URL)
	var waits []time.Duration
	client.wait = func(_ context.Context, delay time.Duration) error { waits = append(waits, delay); return nil }
	credential, err := client.AuthenticateDevice(context.Background(), deviceConfig(server.URL), deviceProvider(server.URL), DeviceLoginOptions{OnAuthorization: func(_ context.Context, got DeviceAuthorization) error { authorization = got; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if credential.AuthMethod != AuthMethodOIDC || credential.OIDCRefresh == nil || credential.OIDCRefresh.RefreshToken != "refresh" {
		t.Fatalf("credential = %#v", credential)
	}
	if authorization.DeviceCode != "device-code" || authorization.UserCode != "USER-CODE" || authorization.VerificationURIComplete == "" || authorization.Interval != 3*time.Second || authorization.ExpiresIn != time.Minute {
		t.Fatalf("authorization = %#v", authorization)
	}
	if deviceForm.Get("client_id") != "native-client" || deviceForm.Get("scope") != "openid profile" || tokenForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || tokenForm.Get("device_code") != "device-code" || tokenForm.Get("client_id") != "native-client" || tokenCalls != 2 || len(waits) != 1 || waits[0] != 3*time.Second {
		t.Fatalf("device form = %q token form = %q calls = %d waits = %v", deviceForm, tokenForm, tokenCalls, waits)
	}
}

func TestDeviceAuthorizationFormattingHidesDeviceCode(t *testing.T) {
	authorization := DeviceAuthorization{DeviceCode: "device-code-secret", UserCode: "USER-CODE", VerificationURI: "https://verify.example.com"}
	for _, formatted := range []string{authorization.String(), authorization.GoString(), fmt.Sprint(authorization), fmt.Sprintf("%+v", authorization), fmt.Sprintf("%#v", authorization)} {
		if strings.Contains(formatted, authorization.DeviceCode) {
			t.Fatalf("formatted authorization leaked device code: %q", formatted)
		}
	}
}

func TestAuthenticateDeviceUsesDefaultIntervalAndSlowDown(t *testing.T) {
	calls := 0
	server := loopbackServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/device" {
			_, _ = w.Write([]byte(`{"device_code":"device-code","user_code":"USER-CODE","verification_uri":"https://verify.example.com","expires_in":60}`))
			return
		}
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"slow_down"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"` + oidcJWT(time.Now().Add(time.Hour)) + `","token_type":"Bearer","refresh_token":"refresh"}`))
	}))
	defer server.Close()
	client, _ := New(server.URL)
	var waits []time.Duration
	client.wait = func(_ context.Context, delay time.Duration) error { waits = append(waits, delay); return nil }
	if _, err := client.AuthenticateDevice(context.Background(), deviceConfig(server.URL), deviceProvider(server.URL), DeviceLoginOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(waits) != 2 || waits[0] != 10*time.Second || waits[1] != 15*time.Second {
		t.Fatalf("waits = %v", waits)
	}
}

func TestAuthenticateDeviceStopsOnProviderErrors(t *testing.T) {
	for _, code := range []string{"access_denied", "expired_token"} {
		t.Run(code, func(t *testing.T) {
			server := loopbackServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/device" {
					_, _ = w.Write([]byte(`{"device_code":"device-secret","user_code":"USER-CODE","verification_uri":"https://verify.example.com","expires_in":60}`))
					return
				}
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"` + code + `","error_description":"device-secret"}`))
			}))
			defer server.Close()
			client, _ := New(server.URL)
			_, err := client.AuthenticateDevice(context.Background(), deviceConfig(server.URL), deviceProvider(server.URL), DeviceLoginOptions{})
			if !errors.Is(err, ErrProtocol) || strings.Contains(err.Error(), "device-secret") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestAuthenticateDeviceBoundsLifetimeAndCancellation(t *testing.T) {
	t.Run("local expiry", func(t *testing.T) {
		server := deviceServer(t, `{"device_code":"device-code","user_code":"USER-CODE","verification_uri":"https://verify.example.com","expires_in":60}`, `{"error":"authorization_pending"}`)
		defer server.Close()
		client, _ := New(server.URL, WithMaxWait(time.Second))
		now := time.Unix(1_784_800_000, 0)
		client.now = func() time.Time { return now }
		client.wait = func(_ context.Context, delay time.Duration) error { now = now.Add(delay); return nil }
		_, err := client.AuthenticateDevice(context.Background(), deviceConfig(server.URL), deviceProvider(server.URL), DeviceLoginOptions{})
		if !errors.Is(err, ErrLoginExpired) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("cancellation", func(t *testing.T) {
		server := deviceServer(t, `{"device_code":"device-code","user_code":"USER-CODE","verification_uri":"https://verify.example.com","expires_in":60}`, `{"error":"authorization_pending"}`)
		defer server.Close()
		client, _ := New(server.URL)
		ctx, cancel := context.WithCancel(context.Background())
		client.wait = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
		_, err := client.AuthenticateDevice(ctx, deviceConfig(server.URL), deviceProvider(server.URL), DeviceLoginOptions{})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestAuthenticateDeviceRejectsUnsafeResponses(t *testing.T) {
	for _, test := range []struct{ name, body string }{
		{"missing endpoint", ""},
		{"malformed", `{"device_code":`},
		{"trailing", `{"device_code":"device-code","user_code":"USER-CODE","verification_uri":"https://verify.example.com","expires_in":60}{}`},
		{"oversized", `{"device_code":"` + strings.Repeat("x", maxOIDCTokenResponseBytes) + `","user_code":"USER-CODE","verification_uri":"https://verify.example.com","expires_in":60}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, _ := New("https://proxy.example.com")
			provider := deviceProvider("https://idp.example.com")
			if test.name == "missing endpoint" {
				provider.DeviceAuthorizationEndpoint = ""
			} else {
				server := deviceServer(t, test.body, "")
				defer server.Close()
				provider = deviceProvider(server.URL)
			}
			_, err := client.AuthenticateDevice(context.Background(), deviceConfig("https://idp.example.com"), provider, DeviceLoginOptions{})
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestAuthenticateDeviceProvidesFallbackVerificationData(t *testing.T) {
	server := deviceServer(t, `{"device_code":"device-code","user_code":"USER-CODE","verification_uri":"https://verify.example.com","expires_in":60}`, `{"access_token":"`+oidcJWT(time.Now().Add(time.Hour))+`","token_type":"Bearer","refresh_token":"refresh"}`)
	defer server.Close()
	client, _ := New(server.URL)
	var got DeviceAuthorization
	_, err := client.AuthenticateDevice(context.Background(), deviceConfig(server.URL), deviceProvider(server.URL), DeviceLoginOptions{OnAuthorization: func(_ context.Context, authorization DeviceAuthorization) error { got = authorization; return nil }})
	if err != nil || got.VerificationURI != "https://verify.example.com" || got.UserCode != "USER-CODE" || got.VerificationURIComplete != "" {
		t.Fatalf("authorization = %#v error = %v", got, err)
	}
}

func deviceConfig(discovery string) NativeOIDCConfig {
	return NativeOIDCConfig{Issuer: discovery, ClientID: "native-client", Scopes: []string{"openid", "profile"}}
}

func deviceProvider(base string) OIDCProvider {
	return OIDCProvider{Issuer: base, AuthorizationEndpoint: base + "/authorize", TokenEndpoint: base + "/token", DeviceAuthorizationEndpoint: base + "/device"}
}

func deviceServer(t *testing.T, device, token string) *httptest.Server {
	t.Helper()
	return loopbackServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/device" {
			_, _ = w.Write([]byte(device))
			return
		}
		if !strings.Contains(token, `"access_token"`) {
			w.WriteHeader(http.StatusBadRequest)
		}
		_, _ = w.Write([]byte(token))
	}))
}
