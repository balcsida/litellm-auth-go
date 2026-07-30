package litellmauth

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/balcsida/litellm-auth-go/internal/testserver"
)

func TestOIDCTokenExchangesCode(t *testing.T) {
	server := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Fatalf("request = %s content-type=%q", r.Method, r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		if form.Get("grant_type") != "authorization_code" || form.Get("code") != "code" {
			t.Fatalf("form = %q", form)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + oidcJWT(time.Now().Add(time.Hour)) + `","token_type":"Bearer","refresh_token":"rotated"}`))
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	refresh := validOIDCRefresh(server.URL)
	credential, err := client.exchangeToken(context.Background(), server.URL, url.Values{"grant_type": {"authorization_code"}, "code": {"code"}}, refresh)
	if err != nil {
		t.Fatal(err)
	}
	if credential.AuthMethod != AuthMethodOIDC || credential.TokenType != "Bearer" || credential.OIDCRefresh == nil || credential.OIDCRefresh.RefreshToken != "rotated" || credential.ExpiresAt.IsZero() {
		t.Fatalf("credential = %#v", credential)
	}
}

func TestRefreshSendsGrantAndPreservesOrRotatesToken(t *testing.T) {
	refreshToken := "original"
	server := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		if form.Get("grant_type") != "refresh_token" || form.Get("client_id") != "client" || form.Get("refresh_token") != refreshToken {
			t.Fatalf("form = %q", form)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + oidcJWT(time.Now().Add(time.Hour)) + `","token_type":"Bearer"}`))
	}))
	defer server.Close()
	client, _ := New(server.URL)
	refresh := validOIDCRefresh(server.URL)
	refresh.RefreshToken = refreshToken
	credential, err := client.Refresh(context.Background(), Credential{BaseURL: "https://proxy.example.com", UserID: "user", AuthMethod: AuthMethodOIDC, OIDCRefresh: &refresh})
	if err != nil {
		t.Fatal(err)
	}
	if credential.OIDCRefresh.RefreshToken != refreshToken {
		t.Fatalf("refresh token = %q", credential.OIDCRefresh.RefreshToken)
	}
	if credential.BaseURL != "https://proxy.example.com" || credential.UserID != "user" {
		t.Fatalf("credential metadata = %#v", credential)
	}
}

func TestRefreshRotatesToken(t *testing.T) {
	server := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + oidcJWT(time.Now().Add(time.Hour)) + `","token_type":"Bearer","refresh_token":"rotated"}`))
	}))
	defer server.Close()
	client, _ := New(server.URL)
	refresh := validOIDCRefresh(server.URL)
	credential, err := client.Refresh(context.Background(), Credential{AuthMethod: AuthMethodOIDC, OIDCRefresh: &refresh})
	if err != nil {
		t.Fatal(err)
	}
	if credential.OIDCRefresh.RefreshToken != "rotated" {
		t.Fatalf("refresh token = %q", credential.OIDCRefresh.RefreshToken)
	}
}

func TestOIDCTokenRejectsUnsafeResponses(t *testing.T) {
	for _, test := range []struct {
		name, body string
		status     int
	}{
		{"oauth error", `{"error":"invalid_grant","error_description":"secret-refresh"}`, http.StatusBadRequest},
		{"missing token", `{"token_type":"Bearer"}`, http.StatusOK},
		{"opaque token", `{"access_token":"opaque","token_type":"Bearer"}`, http.StatusOK},
		{"JWT missing exp", `{"access_token":"header.eyJzdWIiOiJ1c2VyIn0.signature","token_type":"Bearer"}`, http.StatusOK},
		{"wrong type", `{"access_token":"` + oidcJWT(time.Now().Add(time.Hour)) + `","token_type":"DPoP"}`, http.StatusOK},
		{"expired", `{"access_token":"` + oidcJWT(time.Now().Add(-time.Hour)) + `","token_type":"Bearer"}`, http.StatusOK},
		{"trailing", `{"access_token":"` + oidcJWT(time.Now().Add(time.Hour)) + `","token_type":"Bearer"}{}`, http.StatusOK},
		{"oversized", `{"access_token":"` + strings.Repeat("x", maxOIDCTokenResponseBytes) + `","token_type":"Bearer"}`, http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := testserver.New(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			client, _ := New(server.URL)
			_, err := client.exchangeToken(context.Background(), server.URL, url.Values{"grant_type": {"authorization_code"}}, validOIDCRefresh(server.URL))
			if (test.status == http.StatusOK && !errors.Is(err, ErrProtocol)) || strings.Contains(err.Error(), "secret-refresh") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func oidcJWT(exp time.Time) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":` + strconv.FormatInt(exp.Unix(), 10) + `}`))
	return "header." + payload + ".signature"
}

func validOIDCRefresh(endpoint string) OIDCRefresh {
	return OIDCRefresh{DiscoveryURL: endpoint, TokenEndpoint: endpoint, ClientID: "client", RefreshToken: "refresh", Scopes: []string{"openid"}}
}
