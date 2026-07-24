//go:build windows

package tokenstore

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"
)

func openCredentialFile(ctx context.Context, path string) (*os.File, error) {
	return retryOpenCredentialFile(ctx, func() (*os.File, error) { return os.Open(path) })
}

func replaceCredentialFile(ctx context.Context, oldPath, newPath string) error {
	_, err := retryCredentialFile(ctx, func() (struct{}, error) {
		return struct{}{}, os.Rename(oldPath, newPath)
	})
	return err
}

func retryOpenError(err error) bool {
	return errors.Is(err, syscall.Errno(32))
}

func retryReplacementError(err error) bool {
	return retryOpenError(err) || errors.Is(err, syscall.ERROR_ACCESS_DENIED)
}

func retryOpenCredentialFile[T any](ctx context.Context, operation func() (T, error)) (T, error) {
	return retryCredentialFileWith(ctx, retryOpenError, operation)
}

func retryCredentialFile[T any](ctx context.Context, operation func() (T, error)) (T, error) {
	return retryCredentialFileWith(ctx, retryReplacementError, operation)
}

func retryCredentialFileWith[T any](ctx context.Context, retryError func(error) bool, operation func() (T, error)) (T, error) {
	var zero T
	deadline := time.Now().Add(time.Second)
	var lastErr error
	attempts := 0
	for {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		if attempts > 0 && !time.Now().Before(deadline) {
			return zero, lastErr
		}
		result, err := operation()
		attempts++
		if err == nil || !retryError(err) {
			return result, err
		}
		lastErr = err
		wait := 10 * time.Millisecond
		if remaining := time.Until(deadline); remaining <= 0 {
			return zero, lastErr
		} else if remaining < wait {
			wait = remaining
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, ctx.Err()
		case <-timer.C:
		}
	}
}
