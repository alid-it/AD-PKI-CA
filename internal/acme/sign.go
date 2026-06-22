// internal/acme/sign.go
package acme

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"ad-pki-ca/internal/ca"
	"ad-pki-ca/internal/config"
	"ad-pki-ca/internal/storage"
)

func backendURL() string {
	u := os.Getenv("BACKEND_URL")
	if u == "" {
		return "http://127.0.0.1:8000"
	}
	return u
}

func SignCSR(csr *x509.CertificateRequest, order *Order) ([]byte, error) {
	settings, err := ca.FetchSettings(backendURL() + "/api/internal/acme-settings")
	if err != nil || settings.IntermediateID == "" {
		settings.IntermediateID = activeIntermediateID()
	}
	if settings.ValidityDays <= 0 {
		settings.ValidityDays = 90
	}

	certPEM, serial, err := ca.SignCSR(
		csr,
		settings.IntermediateID,
		settings.CRLURL,
		nil,
		settings.OCSPURL,
		"tls",
		settings.ValidityDays,
	)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	cn := csr.Subject.CommonName
	if cn == "" && len(csr.DNSNames) > 0 {
		cn = csr.DNSNames[0]
	}

	crtPath, _, _, _, err := storage.StoreCertificate(cn, serial, certPEM, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("storage failed: %w", err)
	}

	go notifyLaravel(csr, serial, crtPath, settings, order.AccountID)

	chain, err := ca.BuildChain(certPEM, settings.IntermediateID)
	if err != nil {
		return nil, fmt.Errorf("chain build failed: %w", err)
	}

	return chain, nil
}

func notifyLaravel(csr *x509.CertificateRequest, serial, crtPath string, settings ca.SettingsResponse, accountID string) {
	cn := csr.Subject.CommonName
	if cn == "" && len(csr.DNSNames) > 0 {
		cn = csr.DNSNames[0]
	}

	payload := map[string]interface{}{
		"common_name":     cn,
		"san":             csr.DNSNames,
		"serial_number":   serial,
		"valid_from":      time.Now().Format(time.RFC3339),
		"valid_to":        time.Now().AddDate(0, 0, settings.ValidityDays).Format(time.RFC3339),
		"crt_path":        crtPath,
		"acme_account_id": accountID,
	}

	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", backendURL()+"/api/internal/acme-certificate", bytes.NewReader(body))
	if err != nil {
		fmt.Println("🔥 notifyLaravel request error:", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CA-Token", os.Getenv("CA_TOKEN"))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("🔥 notifyLaravel http error:", err)
		return
	}
	defer resp.Body.Close()
	fmt.Println("🔥 notifyLaravel response:", resp.StatusCode)
}

func activeIntermediateID() string {
	base := config.BasePath()

	// Erst Symlink prüfen
	linkPath := filepath.Join(base, "intermediates", "active")
	target, err := os.Readlink(linkPath)
	if err == nil {
		return filepath.Base(target)
	}

	// Fallback: neuestes int-* Verzeichnis
	entries, err := os.ReadDir(filepath.Join(base, "intermediates"))
	if err != nil {
		return ""
	}

	latest := ""
	for _, e := range entries {
		if e.IsDir() && e.Name() != "active" {
			latest = e.Name()
		}
	}

	return latest
}

func SaveCertificate(certPEM []byte) (string, error) {
	id, err := NewOrderID()
	if err != nil {
		return "", err
	}
	if err := ensureDir(acmePath("certs")); err != nil {
		return "", err
	}
	if err := writeStringFile(acmePath("certs", id+".pem"), string(certPEM)); err != nil {
		return "", err
	}
	return id, nil
}

func LoadCertificate(id string) ([]byte, error) {
	data, err := readStringFile(acmePath("certs", id+".pem"))
	if err != nil {
		return nil, fmt.Errorf("certificate not found: %s", id)
	}
	return []byte(data), nil
}

func fetchACMESettings() (ca.SettingsResponse, error) {
	return ca.FetchSettings(backendURL() + "/api/internal/acme-settings")
}
