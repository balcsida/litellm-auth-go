// Command dual-auth demonstrates a LiteLLM gateway key plus a delegated user token.
package main

import (
	"log"
	"net/http"

	litellmauth "github.com/balcsida/litellm-auth-go"
)

func main() {
	gatewaySource, err := litellmauth.NewEnvSource(
		"LITELLM_API_KEY",
		litellmauth.SourceConfig{NonExpiring: true},
	)
	if err != nil {
		log.Fatal(err)
	}
	userSource, err := litellmauth.NewTokenFileSource(
		"/var/run/secrets/litellm-user-token",
		litellmauth.SourceConfig{},
	)
	if err != nil {
		log.Fatal(err)
	}

	gatewayBinder, err := litellmauth.NewBearerHeader("x-litellm-api-key")
	if err != nil {
		log.Fatal(err)
	}
	userBinder, err := litellmauth.NewBearerHeader("Authorization")
	if err != nil {
		log.Fatal(err)
	}

	authenticator, err := litellmauth.NewAuthenticator(
		litellmauth.Binding{Source: gatewaySource, Binder: gatewayBinder},
		litellmauth.Binding{Source: userSource, Binder: userBinder},
	)
	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{Transport: authenticator.Transport(nil)}
	_ = client
}
