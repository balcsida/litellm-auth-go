package litellmauth

import (
	"errors"
	"net/http"
	"time"
)

const (
	defaultMaxWait        = 10 * time.Minute
	defaultPollInterval   = 2 * time.Second
	defaultRequestTimeout = 10 * time.Second
)

// Option configures a Client created by New.
type Option func(*Client) error

// New creates a Client for baseURL. HTTPS is required except for loopback
// development URLs configured with WithAllowInsecureHTTP.
func New(baseURL string, opts ...Option) (*Client, error) {
	c := &Client{
		baseURL:        baseURL,
		httpClient:     &http.Client{},
		maxWait:        defaultMaxWait,
		pollInterval:   defaultPollInterval,
		requestTimeout: defaultRequestTimeout,
		now:            time.Now,
		wait:           defaultWait,
	}
	for _, option := range opts {
		if option == nil {
			return nil, errors.New("nil LiteLLM client option")
		}
		if err := option(c); err != nil {
			return nil, err
		}
	}
	normalized, err := normalizeBaseURL(c.baseURL, c.allowInsecureHTTP)
	if err != nil {
		return nil, err
	}
	c.baseURL = normalized.String()
	return c, nil
}

// WithAllowInsecureHTTP permits non-loopback HTTP for development only.
func WithAllowInsecureHTTP() Option {
	return func(c *Client) error {
		c.allowInsecureHTTP = true
		return nil
	}
}

// WithHTTPClient uses client for LiteLLM requests.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) error {
		if client == nil {
			return errors.New("LiteLLM HTTP client must not be nil")
		}
		c.httpClient = client
		return nil
	}
}

// WithMaxWait limits the total duration of one login session.
func WithMaxWait(wait time.Duration) Option {
	return withPositiveDuration("maximum wait", wait, func(c *Client, value time.Duration) { c.maxWait = value })
}

// WithPollInterval sets the delay between pending polling requests.
func WithPollInterval(interval time.Duration) Option {
	return withPositiveDuration("poll interval", interval, func(c *Client, value time.Duration) { c.pollInterval = value })
}

// WithRequestTimeout limits one HTTP request.
func WithRequestTimeout(timeout time.Duration) Option {
	return withPositiveDuration("request timeout", timeout, func(c *Client, value time.Duration) { c.requestTimeout = value })
}

func withPositiveDuration(name string, duration time.Duration, set func(*Client, time.Duration)) Option {
	return func(c *Client) error {
		if duration <= 0 {
			return errors.New("LiteLLM " + name + " must be positive")
		}
		set(c, duration)
		return nil
	}
}
