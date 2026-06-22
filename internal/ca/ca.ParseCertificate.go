package ca

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"
)

type CertMeta struct {
	CommonName string
	Serial     string
	ValidFrom  time.Time
	ValidTo    time.Time
}

func ParseCertificate(certPEM []byte) (*CertMeta, error) {

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("invalid PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &CertMeta{
		CommonName: cert.Subject.CommonName,
		Serial:     cert.SerialNumber.Text(16),
		ValidFrom:  cert.NotBefore,
		ValidTo:    cert.NotAfter,
	}, nil
}
