package litellmauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"
)

const (
	legacySessionLifetime = 5 * time.Minute
	maxStartResponseBytes = 1024 * 1024
)

var errStartRedirect = errors.New("LiteLLM CLI SSO start redirect")

type startResponse struct {
	LoginID                 string          `json:"login_id"`
	PollSecret              string          `json:"poll_secret"`
	UserCode                string          `json:"user_code"`
	ExpiresIn               json.RawMessage `json:"expires_in"`
	VerificationURIComplete string          `json:"verification_uri_complete"`
}

func (c *Client) Start(ctx context.Context) (Session, error) {
	requestURL := c.startURL().String()
	ctx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, nil)
	if err != nil {
		return Session{}, fmt.Errorf("LiteLLM CLI SSO start request to %s failed", requestURL)
	}
	req.Header.Set("Accept", "application/json")

	client := *c.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errStartRedirect }
	response, err := client.Do(req)
	if err != nil {
		if errors.Is(err, errStartRedirect) {
			return Session{}, errors.New("LiteLLM CLI SSO start: redirects are not allowed")
		}
		if ctx.Err() != nil {
			return Session{}, fmt.Errorf("LiteLLM CLI SSO start request to %s: %w", requestURL, ctx.Err())
		}
		return Session{}, fmt.Errorf("LiteLLM CLI SSO start request to %s failed", requestURL)
	}
	defer response.Body.Close()

	body, detail, oversized, readErr := readStartResponse(response)
	if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusMethodNotAllowed {
		return Session{}, fmt.Errorf("%w: upgrade the LiteLLM proxy or check the base URL", ErrUnsupportedProxy)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return Session{}, &HTTPError{
			Op:         "start",
			StatusCode: response.StatusCode,
			Detail:     detail,
			Retryable:  response.StatusCode == http.StatusTooManyRequests,
		}
	}
	if readErr != nil {
		return Session{}, protocolReadError("start", readErr)
	}
	if oversized || responseContentType(response) != "application/json" {
		return Session{}, protocolError(detail)
	}

	var decoded startResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return Session{}, protocolError(detail)
	}
	if decoded.LoginID == "" || decoded.PollSecret == "" || decoded.UserCode == "" {
		return Session{}, protocolError(detail)
	}
	expiresIn, err := c.startExpiry(decoded.ExpiresIn)
	if err != nil {
		return Session{}, protocolError(detail)
	}

	return Session{
		LoginID:         decoded.LoginID,
		UserCode:        decoded.UserCode,
		VerificationURL: c.verificationURL(decoded.VerificationURIComplete, decoded.LoginID, decoded.PollSecret),
		ExpiresIn:       expiresIn,
		pollSecret:      decoded.PollSecret,
		expiresAt:       c.now().Add(expiresIn),
	}, nil
}

func (c *Client) startExpiry(raw json.RawMessage) (time.Duration, error) {
	if raw == nil {
		return legacySessionLifetime, nil
	}
	var seconds int64
	if err := json.Unmarshal(raw, &seconds); err != nil || seconds <= 0 {
		return 0, ErrProtocol
	}
	if seconds > int64(c.maxWait/time.Second) {
		return c.maxWait, nil
	}
	return time.Duration(seconds) * time.Second, nil
}

func readStartResponse(response *http.Response) ([]byte, string, bool, error) {
	body, err := io.ReadAll(io.LimitReader(response.Body, maxStartResponseBytes+1))
	return body, fmt.Sprintf("content-type=%s bytes=%d", responseContentType(response), len(body)), len(body) > maxStartResponseBytes, err
}

func responseContentType(response *http.Response) string {
	contentType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || len(contentType) == 0 {
		return "invalid"
	}
	if len(contentType) > 128 {
		return contentType[:128]
	}
	return contentType
}

func protocolError(detail string) error { return fmt.Errorf("%w: %s", ErrProtocol, detail) }

func protocolReadError(op string, err error) error { return responseReadError{op: op, err: err} }

type responseReadError struct {
	op  string
	err error
}

func (e responseReadError) Error() string {
	return "LiteLLM CLI SSO " + e.op + " response body read failed"
}

func (e responseReadError) GoString() string { return e.Error() }

func (e responseReadError) Unwrap() []error { return []error{ErrProtocol, e.err} }
