package ca

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func LoadCAFromPEM(certPEM, keyPEM []byte) (*CA, error) {

	// Zertifikat
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("invalid cert PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// Key
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("invalid key PEM")
	}

	var key interface{}

	// 🔥 Try PKCS8
	key, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err == nil {
		return &CA{Cert: cert, Key: key}, nil
	}

	// 🔥 Try RSA PKCS1
	rsaKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err == nil {
		return &CA{Cert: cert, Key: rsaKey}, nil
	}

	// 🔥 Try EC
	ecKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err == nil {
		return &CA{Cert: cert, Key: ecKey}, nil
	}

	return nil, fmt.Errorf("unsupported private key format")
}
