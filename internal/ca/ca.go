package ca

import (
	"crypto/x509"
)

type CA struct {
	ID   string
	Cert *x509.Certificate
	Key  interface{}
}
