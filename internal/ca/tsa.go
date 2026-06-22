// internal/ca/tsa.go
package ca

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"ad-pki-ca/internal/config"
)

// TSACertificate — generiertes TSA Zertifikat + Key
type TSACertificate struct {
	CertPEM []byte
	KeyPEM  []byte
}

// GenerateTSACertificate erstellt ein RFC 3161 konformes TSA Zertifikat via OpenSSL
func GenerateTSACertificate(intermediateID string) (*TSACertificate, error) {
	base := config.BasePath()

	// 🔥 Pfade
	intCert := filepath.Join(base, "intermediates", intermediateID, "intermediate.crt")
	intKey := filepath.Join(base, "intermediates", intermediateID, "private", "intermediate.key")

	// 🔥 Temporäres Verzeichnis
	tmpDir, err := os.MkdirTemp("", "tsa-gen-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	tsaKeyTmp := filepath.Join(tmpDir, "tsa.key")
	tsaCSRTmp := filepath.Join(tmpDir, "tsa.csr")
	tsaCertTmp := filepath.Join(tmpDir, "tsa.crt")
	extFile := filepath.Join(tmpDir, "tsa.ext")

	// =====================================================
	// 🔥 1. TSA Key generieren
	// =====================================================
	if out, err := exec.Command("openssl", "genrsa", "-out", tsaKeyTmp, "2048").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("genrsa failed: %w — %s", err, out)
	}

	// =====================================================
	// 🔥 2. CSR erstellen
	// =====================================================
	if out, err := exec.Command("openssl", "req", "-new",
		"-key", tsaKeyTmp,
		"-out", tsaCSRTmp,
		"-subj", "/CN=AD-PKI Timestamp Authority",
	).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("req failed: %w — %s", err, out)
	}

	// =====================================================
	// 🔥 3. Extension File — Critical EKU für RFC 3161
	// =====================================================
	extContent := `[ tsa_ext ]
keyUsage = critical, nonRepudiation, digitalSignature
extendedKeyUsage = critical, timeStamping
basicConstraints = critical, CA:FALSE
`
	if err := os.WriteFile(extFile, []byte(extContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write ext file: %w", err)
	}

	// =====================================================
	// 🔥 4. Zertifikat signieren durch Intermediate
	// =====================================================
	if out, err := exec.Command("openssl", "x509", "-req",
		"-in", tsaCSRTmp,
		"-CA", intCert,
		"-CAkey", intKey,
		"-CAcreateserial",
		"-out", tsaCertTmp,
		"-days", "3650",
		"-sha256",
		"-extfile", extFile,
		"-extensions", "tsa_ext",
	).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("x509 sign failed: %w — %s", err, out)
	}

	// =====================================================
	// 🔥 5. Dateien lesen
	// =====================================================
	certPEM, err := os.ReadFile(tsaCertTmp)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert: %w", err)
	}

	keyPEM, err := os.ReadFile(tsaKeyTmp)
	if err != nil {
		return nil, fmt.Errorf("failed to read key: %w", err)
	}

	return &TSACertificate{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

// LoadTSACertificate lädt das gespeicherte TSA Zertifikat
func LoadTSACertificate() (*CA, error) {
	base := config.BasePath()

	certPath := filepath.Join(base, "tsa", "tsa.crt")
	keyPath := filepath.Join(base, "tsa", "private", "tsa.key")

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	return LoadCAFromPEM(certPEM, keyPEM)
}

// TSAExists prüft ob ein TSA Zertifikat vorhanden ist
func TSAExists() bool {
	base := config.BasePath()
	certPath := filepath.Join(base, "tsa", "tsa.crt")
	_, err := os.Stat(certPath)
	return err == nil
}
