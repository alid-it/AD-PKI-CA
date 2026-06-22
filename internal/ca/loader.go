package ca

import (
	"ad-pki-ca/internal/config"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func LoadCA(certPath, keyPath string) (*CA, error) {

	// Zertifikat laden
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse cert PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cert: %w", err)
	}

	// Key laden
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to parse key PEM")
	}

	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	return &CA{
		Cert: cert,
		Key:  key,
	}, nil

}

func LoadAllIntermediates() ([]*CA, error) {

	base := filepath.Join(config.BasePath(), "intermediates")

	dirs, err := os.ReadDir(base)
	if err != nil {
		return nil, err
	}

	var cas []*CA

	for _, d := range dirs {

		if !d.IsDir() {
			continue
		}

		id := d.Name()

		certPath := filepath.Join(base, id, "intermediate.crt")
		keyPath := filepath.Join(base, id, "private", "intermediate.key")

		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			log.Println("[WARN] failed to read cert:", certPath, err)
			continue
		}

		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			log.Println("[WARN] failed to read key:", keyPath, err)
			continue
		}

		caObj, err := LoadCAFromPEM(certPEM, keyPEM)
		if err != nil {
			log.Println("[WARN] failed to load CA:", id, err)
			continue
		}

		// 🔥 ID setzen!
		caObj.ID = id

		cas = append(cas, caObj)
	}

	return cas, nil
}
