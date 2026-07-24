//go:build !windows

package tokenstore

import (
	"context"
	"os"
)

func openCredentialFile(_ context.Context, path string) (*os.File, error) {
	return os.Open(path)
}

func replaceCredentialFile(_ context.Context, oldPath, newPath string) error {
	return os.Rename(oldPath, newPath)
}
