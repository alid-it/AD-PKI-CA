package storage

import (
	"os"
	"path/filepath"

	"ad-pki-ca/internal/config"
)

func StoreIntermediate(id string, cert, key []byte) (string, string, error) {

	base := filepath.Join(config.BasePath(), "intermediates", id)

	// NEU: base erst mit 0750 (www-data in adpki-Gruppe kann eintreten)
	if err := os.MkdirAll(base, 0750); err != nil {
		return "", "", err
	}
	// private/ separat mit 0700 bleibt
	if err := os.MkdirAll(filepath.Join(base, "private"), 0700); err != nil {
		return "", "", err
	}

	crtPath := filepath.Join(base, "intermediate.crt")
	keyPath := filepath.Join(base, "private", "intermediate.key")

	if err := os.WriteFile(crtPath, cert, 0644); err != nil {
		return "", "", err
	}

	if err := os.WriteFile(keyPath, key, 0640); err != nil {
		return "", "", err
	}

	return crtPath, keyPath, nil
}
