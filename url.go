package litellmauth

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

func normalizeBaseURL(raw string, allowInsecureHTTP bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || strings.Contains(raw, "#") || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("invalid LiteLLM base URL")
	}
	scheme, host, ok := normalizedOrigin(u)
	if !ok || (scheme == "http" && !allowInsecureHTTP && !isLoopbackHost(u.Hostname())) {
		return nil, errors.New("invalid LiteLLM base URL")
	}
	u.Scheme, u.Host = scheme, host
	path := strings.TrimRight(u.EscapedPath(), "/")
	u.Path, err = url.PathUnescape(path)
	if err != nil {
		return nil, errors.New("invalid LiteLLM base URL")
	}
	if path == u.Path {
		u.RawPath = ""
	} else {
		u.RawPath = path
	}
	return u, nil
}

func normalizedOrigin(u *url.URL) (scheme, host string, ok bool) {
	if u == nil || u.Host == "" {
		return "", "", false
	}
	scheme = strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", false
	}
	hostname := strings.ToLower(u.Hostname())
	if hostname == "" || !validURLHost(u.Host) {
		return "", "", false
	}
	if ip := net.ParseIP(hostname); ip != nil {
		hostname = ip.String()
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port == "" {
		if strings.HasPrefix(u.Host, "[") {
			return scheme, "[" + hostname + "]", true
		}
		return scheme, hostname, true
	}
	return scheme, net.JoinHostPort(hostname, port), true
}

func validURLHost(host string) bool {
	if strings.HasPrefix(host, "[") {
		end := strings.LastIndex(host, "]")
		if end < 0 {
			return false
		}
		tail := host[end+1:]
		return tail == "" || (strings.HasPrefix(tail, ":") && tail[1:] != "")
	}
	return !strings.Contains(host, ":") || !strings.HasSuffix(host, ":")
}

func isLoopbackHost(host string) bool {
	return strings.EqualFold(host, "localhost") || net.ParseIP(host).IsLoopback()
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
	baseScheme, baseHost, baseOK := normalizedOrigin(baseURL)
	candidateScheme, candidateHost, candidateOK := normalizedOrigin(candidate)
	return baseOK && candidateOK && baseScheme == candidateScheme && baseHost == candidateHost
}
