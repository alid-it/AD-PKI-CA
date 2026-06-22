package ca

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func ValidateIntermediate(rootCertPEM, intermediateCertPEM []byte) error {

	// Root laden
	rootBlock, _ := pem.Decode(rootCertPEM)
	if rootBlock == nil {
		return fmt.Errorf("invalid root cert")
	}

	rootCert, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		return err
	}

	// Intermediate laden
	intBlock, _ := pem.Decode(intermediateCertPEM)
	if intBlock == nil {
		return fmt.Errorf("invalid intermediate cert")
	}

	intCert, err := x509.ParseCertificate(intBlock.Bytes)
	if err != nil {
		return err
	}

	// 🔥 NEU: Basic Constraints prüfen
	if !intCert.IsCA {
	return fmt.Errorf("certificate is not a CA")
}

if !intCert.BasicConstraintsValid {
	return fmt.Errorf("invalid basic constraints")
}

	if !intCert.IsCA {
		return fmt.Errorf("certificate is not a CA")
	}

	// 🔥 Prüfen: Issuer == Root
	if intCert.Issuer.String() != rootCert.Subject.String() {
		return fmt.Errorf("issuer mismatch")
	}

	// 🔥 Prüfen: Signatur gültig
	err = intCert.CheckSignatureFrom(rootCert)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	return nil
}