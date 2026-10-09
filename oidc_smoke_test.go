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
	"net/url"
	"os"
	"testing"
	"time"
)

const (
	oidcSmokeClientID   = "litellm-auth-smoke"
	oidcSmokeDeviceCode = "oidc-smoke-device-code"
)

func TestLiteLLMOIDCSmoke(t *testing.T) {
	baseURL := os.Getenv("LITELLM_SMOKE_URL")
	if baseURL == "" {
		t.Skip("LITELLM_SMOKE_URL is not set")
	}
	issuer := os.Getenv("LITELLM_OIDC_SMOKE_ISSUER")
	if issuer == "" {
		t.Fatal("LITELLM_OIDC_SMOKE_ISSUER is not set")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	oidc := nativeOIDCSmokeServer(t, issuer, key)
	defer oidc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := New(baseURL, WithAllowInsecureHTTP())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := client.AuthenticateOIDCDevice(ctx, OIDCDeviceOptions{
		Provider: OIDCProvider{Issuer: issuer, ClientID: oidcSmokeClientID, Scope: "openid"},
	})
	if err != nil {
		t.Fatal(err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v1/models", nil)
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
}

func nativeOIDCSmokeServer(t *testing.T, rawIssuer string, key *rsa.PrivateKey) *httptest.Server {
	t.Helper()
	issuer, err := url.Parse(rawIssuer)
	if err != nil || issuer.Scheme != "http" || issuer.Host == "" {
		t.Fatalf("LITELLM_OIDC_SMOKE_ISSUER = %q", rawIssuer)
	}
	idToken := nativeOIDCSmokeJWT(t, rawIssuer, key)
	server := nativeOIDCSmokeHTTPServer(t, issuer.Host, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/.well-known/openid-configuration":
			_, _ = io.WriteString(w, `{"issuer":"`+rawIssuer+`","authorization_endpoint":"`+rawIssuer+`/authorize","token_endpoint":"`+rawIssuer+`/token","device_authorization_endpoint":"`+rawIssuer+`/device","jwks_uri":"`+rawIssuer+`/jwks","code_challenge_methods_supported":["S256"]}`)
		case request.Method == http.MethodGet && request.URL.Path == "/jwks":
			_, _ = io.WriteString(w, nativeOIDCSmokeJWKS(key))
		case request.Method == http.MethodPost && request.URL.Path == "/device":
			_, _ = io.WriteString(w, `{"device_code":"`+oidcSmokeDeviceCode+`","user_code":"SMOKE","verification_uri":"`+rawIssuer+`/activate","expires_in":300,"interval":1}`)
		case request.Method == http.MethodPost && request.URL.Path == "/token":
			if err := request.ParseForm(); err == nil &&
				request.PostForm.Get("grant_type") == "urn:ietf:params:oauth:grant-type:device_code" &&
				request.PostForm.Get("device_code") == oidcSmokeDeviceCode &&
				request.PostForm.Get("client_id") == oidcSmokeClientID {
				_, _ = io.WriteString(w, `{"access_token":"oidc-smoke-access","token_type":"Bearer","expires_in":3600,"id_token":"`+idToken+`"}`)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_request"}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_request"}`)
		}
	}))
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
	now := time.Now()
	payload, err := json.Marshal(map[string]any{
		"iss": issuer,
		"aud": oidcSmokeClientID,
		"sub": "native-oidc-smoke-user",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	signingInput := header + "." + base64.RawURLEncoding.EncodeToString(payload)
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
