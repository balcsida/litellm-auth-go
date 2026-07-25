package litellmauth

import (
	"errors"
	"net/http"
	"net/textproto"
	"regexp"
	"strings"
)

// Binder attaches one credential to an HTTP request.
type Binder interface {
	Bind(*http.Request, Credential) error
}

// BinderFunc adapts a function to Binder.
type BinderFunc func(*http.Request, Credential) error

// Bind calls f.
func (f BinderFunc) Bind(request *http.Request, credential Credential) error {
	if f == nil {
		return errors.New("authentication binder is nil")
	}
	return f(request, credential)
}

type headerBinder struct {
	header string
	prefix string
	raw    bool
}

var backendAliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// NewBearerHeader creates a Bearer header binder.
func NewBearerHeader(header string) (Binder, error) {
	return newHeaderBinder(header, "Bearer", false)
}

// NewRawHeader creates a raw token header binder.
func NewRawHeader(header string) (Binder, error) {
	return newHeaderBinder(header, "", true)
}

// NewPrefixedHeader creates a fixed-prefix header binder.
func NewPrefixedHeader(header, prefix string) (Binder, error) {
	if !validHTTPToken(prefix) {
		return nil, errors.New("invalid authentication header prefix")
	}
	return newHeaderBinder(header, prefix, false)
}

// NewMCPBearerHeader creates LiteLLM's per-MCP-server bearer header.
func NewMCPBearerHeader(serverAlias string) (Binder, error) {
	if !backendAliasPattern.MatchString(serverAlias) {
		return nil, errors.New("invalid MCP server alias")
	}
	return NewBearerHeader("x-mcp-" + serverAlias + "-authorization")
}

// NewA2ABearerHeader creates LiteLLM's per-A2A-agent bearer header.
func NewA2ABearerHeader(agentName string) (Binder, error) {
	if !backendAliasPattern.MatchString(agentName) {
		return nil, errors.New("invalid A2A agent name")
	}
	return NewBearerHeader("x-a2a-" + agentName + "-authorization")
}

func newHeaderBinder(header, prefix string, raw bool) (Binder, error) {
	if strings.ContainsRune(header, ':') || !validHTTPToken(header) {
		return nil, errors.New("invalid authentication header name")
	}
	canonical := textproto.CanonicalMIMEHeaderKey(header)
	return &headerBinder{header: canonical, prefix: prefix, raw: raw}, nil
}

func (b *headerBinder) Bind(request *http.Request, credential Credential) error {
	if b == nil || request == nil {
		return errors.New("invalid authentication binding")
	}
	if err := credential.Validate(); err != nil {
		return err
	}
	value := credential.Key
	if !b.raw {
		value = b.prefix + " " + credential.Key
	}
	request.Header.Set(b.header, value)
	return nil
}

func (*headerBinder) String() string { return "authentication header binder" }

func (b *headerBinder) GoString() string { return b.String() }
