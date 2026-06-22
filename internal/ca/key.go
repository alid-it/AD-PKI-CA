package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func GenerateKey(keyType string, keySize int, curve string) (interface{}, error) {

	switch keyType {

	case "rsa":
		return rsa.GenerateKey(rand.Reader, keySize)

	case "ecdsa":

		if curve == "" {
			curve = "P256" // 🔥 DEFAULT
		}

		var c elliptic.Curve

		switch curve {
		case "P256":
			c = elliptic.P256()
		case "P384":
			c = elliptic.P384()
		case "P521":
			c = elliptic.P521()
		default:
			return nil, fmt.Errorf("invalid curve")
		}

		return ecdsa.GenerateKey(c, rand.Reader)

	default:
		return nil, fmt.Errorf("invalid key type")
	}
}
