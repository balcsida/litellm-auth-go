package litellmauth

import (
	"net/url"
	"strings"
	"testing"
)

func TestNewNormalizesAndValidatesBaseURL(t *testing.T) {
	for _, test := range []struct {
		name    string
		baseURL string
		opts    []Option
		want    string
		wantErr bool
	}{
		{name: "canonical HTTPS prefix", baseURL: "HTTPS://EXAMPLE.COM:443/proxy///", want: "https://example.com/proxy"},
		{name: "HTTPS accepted", baseURL: "https://gateway.example.com", want: "https://gateway.example.com"},
		{name: "loopback hostname HTTP", baseURL: "HTTP://LOCALHOST:80///", want: "http://localhost"},
		{name: "loopback IPv4 HTTP", baseURL: "http://127.0.0.1:8080/proxy/", want: "http://127.0.0.1:8080/proxy"},
		{name: "loopback IPv6 HTTP", baseURL: "http://[::1]/proxy/", want: "http://[::1]/proxy"},
		{name: "canonical IPv6 literal", baseURL: "https://[0:0:0:0:0:0:0:1]/proxy", want: "https://[::1]/proxy"},
		{name: "explicit HTTP allowance", baseURL: "http://gateway.example.com/api/", opts: []Option{WithAllowInsecureHTTP()}, want: "http://gateway.example.com/api"},
		{name: "userinfo", baseURL: "https://user@gateway.example.com", wantErr: true},
		{name: "query", baseURL: "https://gateway.example.com?x=1", wantErr: true},
		{name: "empty query", baseURL: "https://gateway.example.com?", wantErr: true},
		{name: "fragment", baseURL: "https://gateway.example.com#fragment", wantErr: true},
		{name: "empty fragment", baseURL: "https://gateway.example.com#", wantErr: true},
		{name: "missing host", baseURL: "https:///proxy", wantErr: true},
		{name: "unsupported scheme", baseURL: "ftp://gateway.example.com", wantErr: true},
		{name: "non-loopback HTTP", baseURL: "http://gateway.example.com", wantErr: true},
		{name: "invalid port", baseURL: "https://gateway.example.com:not-a-port", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := New(test.baseURL, test.opts...)
			if test.wantErr {
				if err == nil {
					t.Fatal("New() error = nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if client.baseURL != test.want {
				t.Fatalf("baseURL = %q, want %q", client.baseURL, test.want)
			}
		})
	}
}

func TestClientEndpointsEscapePathAndQueryValues(t *testing.T) {
	client, err := New("https://gateway.example.com/proxy/")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if got, want := client.startURL().String(), "https://gateway.example.com/proxy/sso/cli/start"; got != want {
		t.Fatalf("startURL() = %q, want %q", got, want)
	}

	loginID := "login id +/ % 東京"
	teamID := "team id +/ 東京"
	pollURL := client.pollURL(loginID, teamID)
	if got, want := pollURL.EscapedPath(), "/proxy/sso/cli/poll/login%20id%20+%2F%20%25%20%E6%9D%B1%E4%BA%AC"; got != want {
		t.Fatalf("pollURL path = %q, want %q", got, want)
	}
	if got := pollURL.Query().Get("team_id"); got != teamID {
		t.Fatalf("pollURL team_id = %q, want %q", got, teamID)
	}
	if strings.Contains(pollURL.RawQuery, "+/") {
		t.Fatalf("pollURL query was not encoded: %q", pollURL.RawQuery)
	}

	browserURL := client.browserURL(loginID)
	if got, want := browserURL.EscapedPath(), "/proxy/sso/key/generate"; got != want {
		t.Fatalf("browserURL path = %q, want %q", got, want)
	}
	if got := browserURL.Query(); got.Get("source") != "litellm-cli" || got.Get("key") != loginID {
		t.Fatalf("browserURL query = %q", browserURL.RawQuery)
	}
}

func TestVerificationURLUsesOnlySafeSameOriginURI(t *testing.T) {
	client, err := New("https://gateway.example.com/proxy")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	loginID := "login-id"
	secret := "poll-secret-abc"
	fallback := client.browserURL(loginID)

	for _, test := range []struct {
		name string
		uri  string
		want *url.URL
	}{
		{name: "same origin", uri: "HTTPS://GATEWAY.EXAMPLE.COM:443/verify?state=ok", want: mustParseURL(t, "HTTPS://GATEWAY.EXAMPLE.COM:443/verify?state=ok")},
		{name: "cross origin", uri: "https://other.example.com/verify", want: fallback},
		{name: "userinfo", uri: "https://user@gateway.example.com/verify", want: fallback},
		{name: "secret in URI", uri: "https://gateway.example.com/verify?state=poll-secret-abc", want: fallback},
		{name: "encoded secret query", uri: "https://gateway.example.com/verify?state=poll%2Dsecret%2Dabc", want: fallback},
		{name: "secret in encoded query key", uri: "https://gateway.example.com/verify?prefix%2Dpoll%2Dsecret%2Dabc=value", want: fallback},
		{name: "secret in encoded query value substring", uri: "https://gateway.example.com/verify?state=prefix%2Dpoll%2Dsecret%2Dabc-suffix", want: fallback},
		{name: "secret in encoded path", uri: "https://gateway.example.com/verify/prefix%2Dpoll%2Dsecret%2Dabc-suffix", want: fallback},
		{name: "secret in encoded fragment", uri: "https://gateway.example.com/verify#prefix%2Dpoll%2Dsecret%2Dabc-suffix", want: fallback},
		{name: "relative URI", uri: "/verify", want: fallback},
		{name: "unsupported scheme", uri: "ftp://gateway.example.com/verify", want: fallback},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := client.verificationURL(test.uri, loginID, secret)
			if got.String() != test.want.String() {
				t.Fatalf("verificationURL() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestVerificationURLMatchesEquivalentIPLiteralOrigin(t *testing.T) {
	client, err := New("https://[0:0:0:0:0:0:0:1]/proxy")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	got := client.verificationURL("https://[::1]:443/verify", "login-id", "poll-secret")
	if want := "https://[::1]:443/verify"; got.String() != want {
		t.Fatalf("verificationURL() = %q, want %q", got, want)
	}
}

func TestMappedIPv6LoopbackUsesIPv4Origin(t *testing.T) {
	client, err := New("http://[::ffff:127.0.0.1]/proxy")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if want := "http://127.0.0.1/proxy"; client.baseURL != want {
		t.Fatalf("baseURL = %q, want %q", client.baseURL, want)
	}
	if want := "http://127.0.0.1/proxy/sso/cli/start"; client.startURL().String() != want {
		t.Fatalf("startURL() = %q, want %q", client.startURL(), want)
	}
	if want := "http://127.0.0.1/verify"; client.verificationURL(want, "login-id", "poll-secret").String() != want {
		t.Fatalf("verificationURL() = %q, want %q", client.verificationURL(want, "login-id", "poll-secret"), want)
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", raw, err)
	}
	return u
}
