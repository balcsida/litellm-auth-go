package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunReturnsNonzeroQuietlyForCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stdout, stderr := new(bytes.Buffer), new(bytes.Buffer)

	if code := run(ctx, []string{"login", "--no-browser"}, strings.NewReader(""), stdout, stderr); code == 0 {
		t.Fatal("run() exit code = 0")
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("canceled run output: stdout=%q stderr=%q", stdout, stderr)
	}
}
