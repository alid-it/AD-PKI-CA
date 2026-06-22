package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
)

type CSRInput struct {
	CommonName   string
	Organization string
	OU           string
	Locality     string
	State        string
	Country      string
	Email        string
	DNSNames     []string
	IPAddresses  []string
}

func CreateCSR(input CSRInput, privateKey interface{}) (*x509.CertificateRequest, error) {

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         input.CommonName,
			Organization:       []string{input.Organization},
			OrganizationalUnit: []string{input.OU},
			Locality:           []string{input.Locality},
			Province:           []string{input.State},
			Country:            []string{input.Country},
		},
		DNSNames: input.DNSNames,
	}

	csrBytes, err := x509.CreateCertificateRequest(
		nil,
		template,
		privateKey,
	)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificateRequest(csrBytes)
}