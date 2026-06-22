package ca

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"crypto/rsa"
)

func ValidateKeyMatchesCert(certPEM, keyPEM []byte) error {

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("invalid cert")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("invalid key")
	}

	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		if cert.PublicKey.(*rsa.PublicKey).N.Cmp(k.N) != 0 {
			return fmt.Errorf("key does not match certificate")
		}
	default:
		return fmt.Errorf("unsupported key type")
	}

	return nil
}
