package ca

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"ad-pki-ca/internal/config"
)

type RevokedCert struct {
	SerialNumber string `json:"serial_number"`
	RevokedAt    string `json:"revoked_at"`
}

func FetchRevokedCertificates(apiURL string) ([]pkix.RevokedCertificate, error) {

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-CA-Token", os.Getenv("CA_TOKEN"))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data []RevokedCert
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return nil, err
	}

	var revoked []pkix.RevokedCertificate

	for _, r := range data {

		serial := new(big.Int)
		serial.SetString(r.SerialNumber, 16)

		t, _ := time.Parse("2006-01-02 15:04:05", r.RevokedAt)

		revoked = append(revoked, pkix.RevokedCertificate{
			SerialNumber:   serial,
			RevocationTime: t,
		})
	}

	return revoked, nil
}

func GenerateCRL(intermediateID string, revoked []pkix.RevokedCertificate) ([]byte, error) {

	base := config.BasePath()

	// 🔐 Pfade sauber bauen
	certPath := filepath.Join(base, "intermediates", intermediateID, "intermediate.crt")
	keyPath := filepath.Join(base, "intermediates", intermediateID, "private", "intermediate.key")

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	ca, err := LoadCAFromPEM(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	crlBytes, err := ca.Cert.CreateCRL(
		rand.Reader,
		ca.Key,
		revoked,
		now,
		now.Add(24*time.Hour),
	)
	if err != nil {
		return nil, err
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlBytes,
	})

	return crlPEM, nil
}
