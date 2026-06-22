// internal/storage/tsa.go
package storage

import (
	"os"
	"path/filepath"

	"ad-pki-ca/internal/config"
)

// StoreTSACertificate speichert TSA Zertifikat + Key
func StoreTSACertificate(certPEM, keyPEM []byte) error {
	base := config.BasePath()

	// 🔥 Verzeichnisse anlegen
	certDir := filepath.Join(base, "tsa")
	keyDir  := filepath.Join(base, "tsa", "private")

	if err := os.MkdirAll(certDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return err
	}

	// 🔥 Zertifikat speichern
	certPath := filepath.Join(certDir, "tsa.crt")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return err
	}

	// 🔥 Private Key speichern (restriktive Rechte)
	keyPath := filepath.Join(keyDir, "tsa.key")
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return err
	}

	return nil
}