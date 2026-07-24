//go:build windows

package tokenstore

import (
	"context"
	"fmt"
	"syscall"
	"testing"
)

func TestReplacementRetryRetriesWrappedAccessDenied(t *testing.T) {
	attempts := 0
	_, err := retryCredentialFile(context.Background(), func() (struct{}, error) {
		attempts++
		if attempts == 1 {
			return struct{}{}, fmt.Errorf("replace credential: %w", syscall.ERROR_ACCESS_DENIED)
		}
		return struct{}{}, nil
	})
	if err != nil || attempts != 2 {
		t.Fatalf("replacement attempts = %d, error = %v; want 2, nil", attempts, err)
	}
}
