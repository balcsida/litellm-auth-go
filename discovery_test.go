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
	valid := `{"native_oidc":{"issuer":"https://idp.example.com","client_id":"litellm-native","scopes":["openid","profile"]}}`
	validWithSiblings := `{"proxy_base_url":"https://proxy.example.com","admin_ui_disabled":false,"native_oidc":{"issuer":"https://idp.example.com","client_id":"litellm-native","scopes":["openid","profile"]},"use_admin_single_sign_on":true}`
	for _, test := range []struct {
		name    string
		body    string
		want    *NativeOIDCConfig
		wantErr error
	}{
		{name: "absent", body: `{}`, want: nil},
		{name: "absent with standard siblings", body: `{"proxy_base_url":"https://proxy.example.com","admin_ui_disabled":false,"use_admin_single_sign_on":true}`, want: nil},
		{name: "explicit null", body: `{"native_oidc":null}`, wantErr: ErrProtocol},
		{name: "valid", body: valid, want: &NativeOIDCConfig{Issuer: "https://idp.example.com", ClientID: "litellm-native", Scopes: []string{"openid", "profile"}}},
		{name: "valid with standard siblings", body: validWithSiblings, want: &NativeOIDCConfig{Issuer: "https://idp.example.com", ClientID: "litellm-native", Scopes: []string{"openid", "profile"}}},
		{name: "trailing document", body: valid + `{}`, wantErr: ErrProtocol},
		{name: "oversized document", body: `{"native_oidc":` + strings.Repeat(" ", 1<<20) + `null}`, wantErr: ErrProtocol},
		{name: "blank client ID", body: `{"native_oidc":{"issuer":"https://idp.example.com","client_id":" ","scopes":["openid"]}}`, wantErr: ErrProtocol},
		{name: "control character", body: `{"native_oidc":{"issuer":"https://idp.example.com","client_id":"client\u0000id","scopes":["openid"]}}`, wantErr: ErrProtocol},
		{name: "unexpected native OIDC field", body: `{"native_oidc":{"issuer":"https://idp.example.com","client_id":"client","scopes":["openid"],"client_secret":"secret"}}`, wantErr: ErrProtocol},
		{name: "legacy discovery_url field rejected", body: `{"native_oidc":{"discovery_url":"https://idp.example.com/.well-known/openid-configuration","client_id":"client","scopes":["openid"]}}`, wantErr: ErrProtocol},
		{name: "insecure remote issuer", body: `{"native_oidc":{"issuer":"http://idp.example.com","client_id":"client","scopes":["openid"]}}`, wantErr: ErrProtocol},
		{name: "issuer with query", body: `{"native_oidc":{"issuer":"https://idp.example.com/tenant?x=1","client_id":"client","scopes":["openid"]}}`, wantErr: ErrProtocol},
		{name: "issuer preserved byte-for-byte", body: `{"native_oidc":{"issuer":"https://IdP.Example.com:8443/tenant/","client_id":"client","scopes":["openid"]}}`, want: &NativeOIDCConfig{Issuer: "https://IdP.Example.com:8443/tenant/", ClientID: "client", Scopes: []string{"openid"}}},
		{name: "loopback HTTP", body: `{"native_oidc":{"issuer":"http://127.0.0.1:8080","client_id":"client","scopes":["openid"]}}`, want: &NativeOIDCConfig{Issuer: "http://127.0.0.1:8080", ClientID: "client", Scopes: []string{"openid"}}},
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
	if _, err := client.DiscoverProvider(context.Background(), NativeOIDCConfig{Issuer: server.URL, ClientID: "client", Scopes: []string{"openid"}}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("DiscoverProvider() error = %v, want ErrProtocol", err)
	}
}

// TestDiscoverProvider drives the provider document over a real loopback
// server. {{ISSUER}} in a body or in want.Issuer is replaced with that
// server's origin, which is what the client advertises as its issuer.
func TestDiscoverProvider(t *testing.T) {
	for _, test := range []struct {
		name    string
		body    string
		want    OIDCProvider
		wantErr error
	}{
		{name: "issuer mismatch", body: `{"issuer":"https://evil.example.com","authorization_endpoint":"https://evil.example.com/authorize","token_endpoint":"https://evil.example.com/token"}`, wantErr: ErrProtocol},
		{name: "issuer differing only by trailing slash", body: `{"issuer":"{{ISSUER}}/","authorization_endpoint":"https://idp.example.com/authorize","token_endpoint":"https://idp.example.com/token"}`, wantErr: ErrProtocol},
		{name: "required endpoints", body: `{"issuer":"{{ISSUER}}","authorization_endpoint":"https://idp.example.com/authorize","token_endpoint":"https://idp.example.com/token"}`, want: OIDCProvider{Issuer: "{{ISSUER}}", AuthorizationEndpoint: "https://idp.example.com/authorize", TokenEndpoint: "https://idp.example.com/token"}},
		{name: "optional device endpoint", body: `{"issuer":"{{ISSUER}}","authorization_endpoint":"https://idp.example.com/authorize","token_endpoint":"https://idp.example.com/token","device_authorization_endpoint":"https://idp.example.com/device"}`, want: OIDCProvider{Issuer: "{{ISSUER}}", AuthorizationEndpoint: "https://idp.example.com/authorize", TokenEndpoint: "https://idp.example.com/token", DeviceAuthorizationEndpoint: "https://idp.example.com/device"}},
		{name: "missing token endpoint", body: `{"issuer":"{{ISSUER}}","authorization_endpoint":"https://idp.example.com/authorize"}`, wantErr: ErrProtocol},
		{name: "URL credentials", body: `{"issuer":"{{ISSUER}}","authorization_endpoint":"https://user@idp.example.com/authorize","token_endpoint":"https://idp.example.com/token"}`, wantErr: ErrProtocol},
		{name: "URL fragment", body: `{"issuer":"{{ISSUER}}","authorization_endpoint":"https://idp.example.com/authorize#fragment","token_endpoint":"https://idp.example.com/token"}`, wantErr: ErrProtocol},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Declared before assignment so the handler can echo the
			// server's own origin as the issuer it advertises.
			var server *testserver.Server
			server = testserver.New(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != providerConfigurationPath {
					t.Fatalf("request = %s %s", r.Method, r.URL)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(strings.ReplaceAll(test.body, "{{ISSUER}}", server.URL)))
			})
			defer server.Close()

			client, err := New(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			want := test.want
			want.Issuer = strings.ReplaceAll(want.Issuer, "{{ISSUER}}", server.URL)
			got, err := client.DiscoverProvider(context.Background(), NativeOIDCConfig{Issuer: server.URL, ClientID: "client", Scopes: []string{"openid"}})
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("DiscoverProvider() error = %v, want %v", err, test.wantErr)
			}
			if got != want {
				t.Fatalf("DiscoverProvider() = %#v, want %#v", got, want)
			}
		})
	}
}

func TestProviderConfigurationURL(t *testing.T) {
	for _, test := range []struct{ issuer, want string }{
		{issuer: "https://idp.example.com", want: "https://idp.example.com/.well-known/openid-configuration"},
		{issuer: "https://idp.example.com/", want: "https://idp.example.com/.well-known/openid-configuration"},
		{issuer: "https://idp.example.com/tenant", want: "https://idp.example.com/tenant/.well-known/openid-configuration"},
		{issuer: "https://idp.example.com/tenant/", want: "https://idp.example.com/tenant/.well-known/openid-configuration"},
		{issuer: "https://IdP.Example.com:8443/T", want: "https://IdP.Example.com:8443/T/.well-known/openid-configuration"},
	} {
		if got := providerConfigurationURL(test.issuer); got != test.want {
			t.Fatalf("providerConfigurationURL(%q) = %q, want %q", test.issuer, got, test.want)
		}
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
	if _, err := client.DiscoverProvider(ctx, NativeOIDCConfig{Issuer: "https://idp.example.com", ClientID: "client", Scopes: []string{"openid"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("DiscoverProvider() error = %v, want context canceled", err)
	}
}

func equalNativeOIDCConfig(got, want *NativeOIDCConfig) bool {
	if got == nil || want == nil {
		return got == want
	}
	return got.Issuer == want.Issuer && got.ClientID == want.ClientID && strings.Join(got.Scopes, "\x00") == strings.Join(want.Scopes, "\x00")
}
