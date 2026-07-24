// Command manual-login prints a LiteLLM login URL for headless use.
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/balcsida/litellm-auth-go"
)

func main() {
	client, err := litellmauth.New("https://proxy.example.com")
	if err != nil {
		log.Fatal(err)
	}
	credential, err := client.Authenticate(context.Background(), litellmauth.AuthenticateOptions{
		TeamID: "team-engineering",
		OnSession: func(_ context.Context, session litellmauth.Session) error {
			fmt.Printf("Open %s\\nCode: %s\\n", session.VerificationURL, session.UserCode)
			return nil
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("authenticated for team %s", credential.TeamID)
}
