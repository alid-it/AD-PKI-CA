package ca

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"ad-pki-ca/internal/config"
)

func SignCSR(
	csr *x509.CertificateRequest,
	intermediateID string,
	crlURL string,
	ipAddresses []net.IP,
	ocspURL string,
	certType string,
	validityDays int, // 🔥 NEU
) ([]byte, string, error) {

	base := config.BasePath()

	certPath := filepath.Join(base, "intermediates", intermediateID, "intermediate.crt")
	keyPath := filepath.Join(base, "intermediates", intermediateID, "private", "intermediate.key")

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, "", err
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, "", err
	}

	ca, err := LoadCAFromPEM(certPEM, keyPEM)
	if err != nil {
		return nil, "", err
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, "", err
	}

	serialHex := serialNumber.Text(16)
	now := time.Now()

	// 🔥 Gültigkeit — Fallback auf 365 Tage
	if validityDays <= 0 {
		validityDays = 365
	}

	// 🔥 TYPE LOGIK
	var keyUsage x509.KeyUsage
	var extKeyUsage []x509.ExtKeyUsage

	switch certType {
	case "tls":
		keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "client":
		keyUsage = x509.KeyUsageDigitalSignature
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case "codesign":
		keyUsage = x509.KeyUsageDigitalSignature
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	default:
		return nil, "", fmt.Errorf("invalid certificate type: %s", certType)
	}

	// 🔥 TEMPLATE
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, validityDays), // 🔥 dynamisch
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  false,
		CRLDistributionPoints: []string{crlURL},
		OCSPServer:            []string{ocspURL},
	}

	// 🔥 SAN NUR FÜR TLS
	if certType == "tls" {
		template.DNSNames = csr.DNSNames
		template.IPAddresses = ipAddresses
	}

	// 🔥 SIGN
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		ca.Cert,
		csr.PublicKey,
		ca.Key,
	)
	if err != nil {
		return nil, "", err
	}

	certPEMOut := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEMOut, serialHex, nil
}
