package storage

import (
	"os"
	"path/filepath"
	"regexp"

	"ad-pki-ca/internal/config"
)

func StoreCertificate(
	commonName,
	serial string,
	cert,
	csr,
	key,
	chain []byte,
) (string, string, string, string, error) {

	baseDir := config.BasePath()

	// 🔐 CN sanitizen
	safeName := regexp.MustCompile(`[^a-zA-Z0-9.-]`).ReplaceAllString(commonName, "_")

	// 🔐 issued/<cn>-<serial>
	base := filepath.Join(baseDir, "issued", safeName+"-"+serial)

	err := os.MkdirAll(base, 0755)
	if err != nil {
		return "", "", "", "", err
	}

	crtPath := filepath.Join(base, "certificate.crt")
	csrPath := filepath.Join(base, "request.csr")

	var keyPath string
	var chainPath string

	// 🔥 Zertifikat
	if err := os.WriteFile(crtPath, cert, 0644); err != nil {
		return "", "", "", "", err
	}

	// 🔥 CSR
	if err := os.WriteFile(csrPath, csr, 0644); err != nil {
		return "", "", "", "", err
	}

	// 🔥 Private Key (optional)
	if key != nil {
		keyPath = filepath.Join(base, "private.key")

		if err := os.WriteFile(keyPath, key, 0640); err != nil {
			return "", "", "", "", err
		}
	}

	// 🔥 Fullchain (optional)
	if chain != nil {
		chainPath = filepath.Join(base, "fullchain.pem")

		if err := os.WriteFile(chainPath, chain, 0644); err != nil {
			return "", "", "", "", err
		}
	}

	return crtPath, csrPath, keyPath, chainPath, nil
}
