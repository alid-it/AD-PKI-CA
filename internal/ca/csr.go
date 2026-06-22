package ca

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func ParseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("invalid CSR")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}

	err = csr.CheckSignature()
	if err != nil {
		return nil, fmt.Errorf("invalid CSR signature")
	}

	return csr, nil
}
