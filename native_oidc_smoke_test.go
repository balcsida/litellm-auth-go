package litellmauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestLiteLLMNativeOIDCSmoke(t *testing.T) {
	baseURL := os.Getenv("LITELLM_SMOKE_URL")
	if baseURL == "" {
		t.Skip("LITELLM_SMOKE_URL is not set")
	}
	issuer := os.Getenv("LITELLM_NATIVE_OIDC_ISSUER")
	if issuer == "" {
		t.Fatal("LITELLM_NATIVE_OIDC_ISSUER is not set")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	oidc := nativeOIDCSmokeServer(t, issuer, key)
	defer oidc.Close()

	proxyURL := nativeOIDCSmokeProxy(t, baseURL, oidc.URL)
	defer proxyURL.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := New(proxyURL.URL, WithAllowInsecureHTTP())
	if err != nil {
		t.Fatal(err)
	}
	config, err := client.Discover(ctx)
	if err != nil || config == nil {
		t.Fatalf("discovery = %#v, %v", config, err)
	}
	provider, err := client.DiscoverProvider(ctx, *config)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := client.AuthenticateDevice(ctx, *config, provider, DeviceLoginOptions{})
	if err != nil {
		t.Fatal(err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, proxyURL.URL+"/v1/models", nil)
	if err != nil {
		t.Fatal(err)
	}
	binder, err := NewBearerHeader("Authorization")
	if err != nil {
		t.Fatal(err)
	}
	if err := binder.Bind(request, credential); err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("protected request status = %d, body = %s", response.StatusCode, body)
	}
	select {
	case authorization := <-proxyURL.authorization:
		if authorization != "Bearer "+credential.Key {
			t.Fatalf("forwarded authorization = %q", authorization)
		}
	case <-time.After(time.Second):
		t.Fatal("protected request did not reach the LiteLLM proxy")
	}

	mappings := nativeOIDCSmokeMappings(t, ctx, baseURL)
	for _, mapping := range mappings.Mappings {
		if mapping.ClaimName == "sub" && mapping.ClaimValue == "native-oidc-smoke-user" && mapping.Active {
			return
		}
	}
	t.Fatalf("mapped virtual-key policy = %#v", mappings)
}

type nativeOIDCSmokeMappingList struct {
	Mappings []struct {
		ClaimName  string `json:"jwt_claim_name"`
		ClaimValue string `json:"jwt_claim_value"`
		Active     bool   `json:"is_active"`
	} `json:"mappings"`
}

func nativeOIDCSmokeMappings(t *testing.T, ctx context.Context, baseURL string) nativeOIDCSmokeMappingList {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/jwt/key/mapping/list", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer sk-smoke-master-key")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("mapping policy status = %d, body = %s", response.StatusCode, body)
	}
	var mappings nativeOIDCSmokeMappingList
	if err := json.Unmarshal(body, &mappings); err != nil {
		t.Fatalf("mapping policy = %q, %v", body, err)
	}
	return mappings
}

type nativeOIDCSmokeProxyServer struct {
	*httptest.Server
	authorization chan string
}

func nativeOIDCSmokeProxy(t *testing.T, baseURL, issuer string) *nativeOIDCSmokeProxyServer {
	t.Helper()
	backend, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	forward := httputil.NewSingleHostReverseProxy(backend)
	proxy := &nativeOIDCSmokeProxyServer{authorization: make(chan string, 1)}
	proxy.Server = nativeOIDCSmokeHTTPServer(t, "127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/.well-known/litellm-ui-config" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"native_oidc":{"discovery_url":"`+issuer+`/.well-known/openid-configuration","client_id":"native-oidc-smoke","scopes":["openid","profile"]}}`)
			return
		}
		if request.URL.Path == "/v1/models" {
			proxy.authorization <- request.Header.Get("Authorization")
		}
		forward.ServeHTTP(w, request)
	}))
	return proxy
}

func nativeOIDCSmokeServer(t *testing.T, rawIssuer string, key *rsa.PrivateKey) *httptest.Server {
	t.Helper()
	issuer, err := url.Parse(rawIssuer)
	if err != nil || issuer.Scheme != "http" || issuer.Host == "" {
		t.Fatalf("LITELLM_NATIVE_OIDC_ISSUER = %q", rawIssuer)
	}
	token := nativeOIDCSmokeJWT(t, rawIssuer, key)
	server := nativeOIDCSmokeHTTPServer(t, issuer.Host, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = io.WriteString(w, `{"issuer":"`+rawIssuer+`","authorization_endpoint":"`+rawIssuer+`/authorize","token_endpoint":"`+rawIssuer+`/token","device_authorization_endpoint":"`+rawIssuer+`/device"}`)
		case "/device":
			_, _ = io.WriteString(w, `{"device_code":"native-oidc-smoke-device","user_code":"SMOKE","verification_uri":"`+rawIssuer+`/verify","expires_in":60,"interval":1}`)
		case "/token":
			if err := request.ParseForm(); err != nil || request.Form.Get("grant_type") != deviceGrantType {
				t.Fatalf("token form = %q, %v", request.Form, err)
			}
			_, _ = io.WriteString(w, `{"access_token":"`+token+`","token_type":"Bearer","refresh_token":"native-oidc-smoke-refresh","scope":"openid profile"}`)
		case "/jwks":
			_, _ = io.WriteString(w, nativeOIDCSmokeJWKS(key))
		default:
			http.NotFound(w, request)
		}
	}))
	if server.URL != rawIssuer {
		server.Close()
		t.Fatalf("mock issuer = %q, want %q", server.URL, rawIssuer)
	}
	return server
}

func nativeOIDCSmokeHTTPServer(t *testing.T, address string, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: handler}}
	server.Start()
	return server
}

func nativeOIDCSmokeJWT(t *testing.T, issuer string, key *rsa.PrivateKey) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"native-oidc-smoke","typ":"JWT"}`))
	payload, err := json.Marshal(map[string]any{"iss": issuer, "sub": "native-oidc-smoke-user", "exp": time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := header + "." + encodedPayload
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func nativeOIDCSmokeJWKS(key *rsa.PrivateKey) string {
	return `{"keys":[{"kty":"RSA","kid":"native-oidc-smoke","alg":"RS256","use":"sig","n":"` + base64.RawURLEncoding.EncodeToString(key.N.Bytes()) + `","e":"` + base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()) + `"}]}`
}
