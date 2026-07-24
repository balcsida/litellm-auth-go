package baseurl

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

func Normalize(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || strings.Contains(raw, "#") || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("invalid LiteLLM base URL")
	}
	scheme, host, ok := Origin(u)
	if !ok {
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

func Origin(u *url.URL) (scheme, host string, ok bool) {
	if u == nil || u.Host == "" {
		return "", "", false
	}
	scheme = strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", false
	}
	hostname := strings.ToLower(u.Hostname())
	if hostname == "" || !validHost(u.Host) {
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
		if strings.Contains(hostname, ":") {
			return scheme, "[" + hostname + "]", true
		}
		return scheme, hostname, true
	}
	return scheme, net.JoinHostPort(hostname, port), true
}

func validHost(host string) bool {
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
