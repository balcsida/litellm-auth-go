package litellmauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/balcsida/litellm-auth-go/internal/testserver"
)

func TestDiscoverProxyConfiguration(t *testing.T) {
	valid := `{"native_oidc":{"discovery_url":"https://idp.example.com/.well-known/openid-configuration","client_id":"litellm-native","scopes":["openid","profile"]}}`
	for _, test := range []struct {
		name    string
		body    string
		want    *NativeOIDCConfig
		wantErr error
	}{
		{name: "absent", body: `{}`, want: nil},
		{name: "explicit null", body: `{"native_oidc":null}`, wantErr: ErrProtocol},
		{name: "valid", body: valid, want: &NativeOIDCConfig{DiscoveryURL: "https://idp.example.com/.well-known/openid-configuration", ClientID: "litellm-native", Scopes: []string{"openid", "profile"}}},
		{name: "trailing document", body: valid + `{}`, wantErr: ErrProtocol},
		{name: "oversized document", body: `{"native_oidc":` + strings.Repeat(" ", 1<<20) + `null}`, wantErr: ErrProtocol},
		{name: "blank client ID", body: `{"native_oidc":{"discovery_url":"https://idp.example.com/config","client_id":" ","scopes":["openid"]}}`, wantErr: ErrProtocol},
		{name: "control character", body: `{"native_oidc":{"discovery_url":"https://idp.example.com/config","client_id":"client\u0000id","scopes":["openid"]}}`, wantErr: ErrProtocol},
		{name: "unexpected native OIDC field", body: `{"native_oidc":{"discovery_url":"https://idp.example.com/config","client_id":"client","scopes":["openid"],"client_secret":"secret"}}`, wantErr: ErrProtocol},
		{name: "insecure remote URL", body: `{"native_oidc":{"discovery_url":"http://idp.example.com/config","client_id":"client","scopes":["openid"]}}`, wantErr: ErrProtocol},
		{name: "loopback HTTP", body: `{"native_oidc":{"discovery_url":"http://127.0.0.1:8080/config","client_id":"client","scopes":["openid"]}}`, want: &NativeOIDCConfig{DiscoveryURL: "http://127.0.0.1:8080/config", ClientID: "client", Scopes: []string{"openid"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := testserver.New(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/.well-known/litellm-ui-config" {
					t.Fatalf("request = %s %s", r.Method, r.URL)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(test.body))
			})
			defer server.Close()

			client, err := New(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.Discover(context.Background())
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Discover() error = %v, want %v", err, test.wantErr)
			}
			if !equalNativeOIDCConfig(got, test.want) {
				t.Fatalf("Discover() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestDiscoverRejectsRedirects(t *testing.T) {
	server := testserver.New(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://idp.example.com/openid-configuration", http.StatusFound)
	})
	defer server.Close()

	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Discover(context.Background()); !errors.Is(err, ErrProtocol) {
		t.Fatalf("Discover() error = %v, want ErrProtocol", err)
	}
	if _, err := client.DiscoverProvider(context.Background(), NativeOIDCConfig{DiscoveryURL: server.URL + "/openid-configuration", ClientID: "client", Scopes: []string{"openid"}}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("DiscoverProvider() error = %v, want ErrProtocol", err)
	}
}

func TestDiscoverProvider(t *testing.T) {
	for _, test := range []struct {
		name    string
		body    string
		want    OIDCProvider
		wantErr error
	}{
		{name: "required endpoints", body: `{"issuer":"https://idp.example.com","authorization_endpoint":"https://idp.example.com/authorize","token_endpoint":"https://idp.example.com/token"}`, want: OIDCProvider{Issuer: "https://idp.example.com", AuthorizationEndpoint: "https://idp.example.com/authorize", TokenEndpoint: "https://idp.example.com/token"}},
		{name: "optional device endpoint", body: `{"issuer":"https://idp.example.com","authorization_endpoint":"https://idp.example.com/authorize","token_endpoint":"https://idp.example.com/token","device_authorization_endpoint":"https://idp.example.com/device"}`, want: OIDCProvider{Issuer: "https://idp.example.com", AuthorizationEndpoint: "https://idp.example.com/authorize", TokenEndpoint: "https://idp.example.com/token", DeviceAuthorizationEndpoint: "https://idp.example.com/device"}},
		{name: "missing token endpoint", body: `{"issuer":"https://idp.example.com","authorization_endpoint":"https://idp.example.com/authorize"}`, wantErr: ErrProtocol},
		{name: "URL credentials", body: `{"issuer":"https://idp.example.com","authorization_endpoint":"https://user@idp.example.com/authorize","token_endpoint":"https://idp.example.com/token"}`, wantErr: ErrProtocol},
		{name: "URL fragment", body: `{"issuer":"https://idp.example.com","authorization_endpoint":"https://idp.example.com/authorize#fragment","token_endpoint":"https://idp.example.com/token"}`, wantErr: ErrProtocol},
		{name: "insecure remote issuer", body: `{"issuer":"http://idp.example.com","authorization_endpoint":"https://idp.example.com/authorize","token_endpoint":"https://idp.example.com/token"}`, wantErr: ErrProtocol},
		{name: "loopback HTTP", body: `{"issuer":"http://127.0.0.1:8080","authorization_endpoint":"http://127.0.0.1:8080/authorize","token_endpoint":"http://127.0.0.1:8080/token"}`, want: OIDCProvider{Issuer: "http://127.0.0.1:8080", AuthorizationEndpoint: "http://127.0.0.1:8080/authorize", TokenEndpoint: "http://127.0.0.1:8080/token"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := testserver.New(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/openid-configuration" {
					t.Fatalf("request = %s %s", r.Method, r.URL)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(test.body))
			})
			defer server.Close()

			client, err := New(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.DiscoverProvider(context.Background(), NativeOIDCConfig{DiscoveryURL: server.URL + "/openid-configuration", ClientID: "client", Scopes: []string{"openid"}})
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("DiscoverProvider() error = %v, want %v", err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("DiscoverProvider() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestDiscoverHonorsCancellation(t *testing.T) {
	client, err := New("https://proxy.example.com")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Discover(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Discover() error = %v, want context canceled", err)
	}
	if _, err := client.DiscoverProvider(ctx, NativeOIDCConfig{DiscoveryURL: "https://idp.example.com/config", ClientID: "client", Scopes: []string{"openid"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("DiscoverProvider() error = %v, want context canceled", err)
	}
}

func equalNativeOIDCConfig(got, want *NativeOIDCConfig) bool {
	if got == nil || want == nil {
		return got == want
	}
	return got.DiscoveryURL == want.DiscoveryURL && got.ClientID == want.ClientID && strings.Join(got.Scopes, "\x00") == strings.Join(want.Scopes, "\x00")
}
