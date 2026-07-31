package litellmauth

import (
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/balcsida/litellm-auth-go/internal/baseurl"
)

func normalizeBaseURL(raw string, allowInsecureHTTP bool) (*url.URL, error) {
	u, err := baseurl.Normalize(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "http" && !allowInsecureHTTP && !isLoopbackHost(u.Hostname()) {
		return nil, errors.New("invalid LiteLLM base URL")
	}
	return u, nil
}

func isLoopbackHost(host string) bool {
	return strings.EqualFold(host, "localhost") || net.ParseIP(host).IsLoopback()
}

func normalizeOIDCURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Fragment != "" || u.ForceQuery || u.Opaque != "" {
		return nil, errors.New("invalid OIDC URL")
	}
	scheme, host, ok := baseurl.Origin(u)
	if !ok || (scheme == "http" && !isLoopbackHost(u.Hostname())) {
		return nil, errors.New("invalid OIDC URL")
	}
	u.Scheme, u.Host = scheme, host
	return u, nil
}

func (c *Client) startURL() *url.URL { return c.endpoint("sso", "cli", "start") }

func (c *Client) pollURL(loginID, teamID string) *url.URL {
	u := c.endpoint("sso", "cli", "poll", loginID)
	if teamID != "" {
		query := url.Values{"team_id": {teamID}}
		u.RawQuery = query.Encode()
	}
	return u
}

func (c *Client) browserURL(loginID string) *url.URL {
	u := c.endpoint("sso", "key", "generate")
	u.RawQuery = (url.Values{"source": {"litellm-cli"}, "key": {loginID}}).Encode()
	return u
}

func (c *Client) endpoint(segments ...string) *url.URL {
	base, _ := url.Parse(c.baseURL)
	u := *base
	path, rawPath := u.Path, u.EscapedPath()
	for _, segment := range segments {
		path += "/" + segment
		rawPath += "/" + url.PathEscape(segment)
	}
	u.Path, u.RawPath = path, rawPath
	return &u
}

func (c *Client) verificationURL(raw, loginID, pollSecret string) *url.URL {
	fallback := c.browserURL(loginID)
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || !sameOrigin(c.baseURL, u) || containsPollSecret(raw, u, pollSecret) {
		return fallback
	}
	return u
}

func containsPollSecret(raw string, u *url.URL, secret string) bool {
	if secret == "" {
		return false
	}
	if strings.Contains(raw, secret) || strings.Contains(u.Path, secret) || strings.Contains(u.Fragment, secret) {
		return true
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return true
	}
	for key, values := range query {
		if strings.Contains(key, secret) {
			return true
		}
		for _, value := range values {
			if strings.Contains(value, secret) {
				return true
			}
		}
	}
	return false
}

func sameOrigin(base string, candidate *url.URL) bool {
	baseURL, err := url.Parse(base)
	if err != nil {
		return false
	}
	baseScheme, baseHost, baseOK := baseurl.Origin(baseURL)
	candidateScheme, candidateHost, candidateOK := baseurl.Origin(candidate)
	return baseOK && candidateOK && baseScheme == candidateScheme && baseHost == candidateHost
}
