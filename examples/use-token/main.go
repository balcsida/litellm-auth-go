// Command use-token loads a stored LiteLLM key into an HTTP transport.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"time"

	litellmauth "github.com/balcsida/litellm-auth-go"
	"github.com/balcsida/litellm-auth-go/tokenstore"
)

type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (t bearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.Header = request.Header.Clone()
	copy.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(copy)
}

func main() {
	proxyURL, err := url.Parse("https://proxy.example.com")
	if err != nil {
		log.Fatal(err)
	}
	store, err := tokenstore.NewFileStore("")
	if err != nil {
		log.Fatal(err)
	}
	credential, err := store.Load(context.Background(), proxyURL)
	if err != nil {
		log.Fatal(err)
	}
	if !credential.Fresh(time.Now()) {
		log.Fatal(litellmauth.ErrCredentialStale)
	}
	if credential.AuthorizationHeader() == "" {
		log.Fatal(errors.New("stored credential has no valid bearer token"))
	}

	client := &http.Client{Transport: bearerTransport{token: credential.Key, base: http.DefaultTransport}}
	_ = client // Use client for requests to the proxy's OpenAI-compatible API.
}
