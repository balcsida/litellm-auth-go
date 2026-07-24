package main

import (
	"context"
	"io"
	"os"
	"os/signal"

	"github.com/balcsida/litellm-auth-go/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if cli.Execute(ctx, args, stdin, stdout, stderr) != nil {
		return 1
	}
	return 0
}
