// internal/storage/acme.go
package storage

import (
	"ad-pki-ca/internal/config"
	"os"
	"path/filepath"
)

// EnsureACMEDirs — erstellt alle ACME Verzeichnisse
func EnsureACMEDirs() error {
	base := config.BasePath()

	dirs := []string{
		filepath.Join(base, "acme", "accounts"),
		filepath.Join(base, "acme", "orders"),
		filepath.Join(base, "acme", "authz"),
		filepath.Join(base, "acme", "certs"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	return nil
}
