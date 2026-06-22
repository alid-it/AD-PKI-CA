package storage

import (
	"os"
	"path/filepath"

	"ad-pki-ca/internal/config"
)

func StoreRoot(cert []byte) error {
	base := filepath.Join(config.BasePath(), "root")

	if err := os.MkdirAll(base, 0755); err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(base, "root.crt"), cert, 0644)
}
