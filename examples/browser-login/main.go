// Command browser-login opens a LiteLLM browser login session.
package main

import (
	"context"
	"log"

	"github.com/balcsida/litellm-auth-go"
	"github.com/cli/browser"
)

func main() {
	client, err := litellmauth.New("https://proxy.example.com")
	if err != nil {
		log.Fatal(err)
	}
	credential, err := client.Authenticate(context.Background(), litellmauth.AuthenticateOptions{
		OnSession: func(_ context.Context, session litellmauth.Session) error {
			return browser.OpenURL(session.VerificationURL.String())
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("authenticated as %s", credential.UserID)
}
