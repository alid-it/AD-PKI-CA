package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	"ad-pki-ca/internal/ca"
	"ad-pki-ca/internal/crypto"
	"ad-pki-ca/internal/storage"
)

type SignResponse struct {
	Type         string    `json:"type"`
	CommonName   string    `json:"common_name"`
	SAN          []string  `json:"san"`
	SerialNumber string    `json:"serial_number"`
	ValidFrom    time.Time `json:"valid_from"`
	ValidTo      time.Time `json:"valid_to"`
	CRTPath      string    `json:"crt_path"`
	CSRPath      string    `json:"csr_path"`
	KeyPath      *string   `json:"key_path"`
	ChainPath    *string   `json:"chain_path"`
}

// 🔥 CSR UPLOAD HANDLER
func SignHandler(w http.ResponseWriter, r *http.Request) {

	csrFile, _, err := r.FormFile("csr")
	if err != nil {
		http.Error(w, "missing csr", http.StatusBadRequest)
		return
	}

	csrBytes, err := io.ReadAll(csrFile)
	if err != nil {
		http.Error(w, "failed to read csr", http.StatusInternalServerError)
		return
	}

	csr, err := ca.ParseCSR(csrBytes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	intermediateID := r.FormValue("intermediate")
	if intermediateID == "" {
		http.Error(w, "missing intermediate", http.StatusBadRequest)
		return
	}

	crlURL := r.FormValue("crl_url")
	ocspURL := r.FormValue("ocsp_url")

	if crlURL == "" {
		http.Error(w, "missing crl_url", http.StatusBadRequest)
		return
	}

	certType := r.FormValue("type")
	if certType == "" {
		certType = "tls"
	}

	// 🔥 Gültigkeit aus FormData (Fallback: 365)
	validityDays := 365
	if v := r.FormValue("validity_days"); v != "" {
		fmt.Sscanf(v, "%d", &validityDays)
	}

	// 🔥 SIGN
	cert, serial, err := ca.SignCSR(
		csr,
		intermediateID,
		crlURL,
		nil,
		ocspURL,
		certType,
		validityDays, // 🔥 NEU
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	chain, err := ca.BuildChain(cert, intermediateID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	crtPath, csrPath, keyPathValue, chainPathValue, err := storage.StoreCertificate(
		csr.Subject.CommonName,
		serial,
		cert,
		csrBytes,
		nil,
		chain,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var keyPath *string
	if keyPathValue != "" {
		keyPath = &keyPathValue
	}

	var chainPath *string
	if chainPathValue != "" {
		chainPath = &chainPathValue
	}

	var san []string
	if certType == "tls" {
		san = csr.DNSNames
	}

	now := time.Now()
	response := SignResponse{
		Type:         certType,
		CommonName:   csr.Subject.CommonName,
		SAN:          san,
		SerialNumber: serial,
		ValidFrom:    now,
		ValidTo:      now.AddDate(0, 0, validityDays), // 🔥 dynamisch
		CRTPath:      crtPath,
		CSRPath:      csrPath,
		KeyPath:      keyPath,
		ChainPath:    chainPath,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// 🔥 DATA HANDLER (KEY + CSR GENERATION)
func SignFromDataHandler(w http.ResponseWriter, r *http.Request) {

	var input struct {
		Type         string   `json:"type"`
		CommonName   string   `json:"common_name"`
		Organization string   `json:"organization"`
		OU           string   `json:"ou"`
		Locality     string   `json:"locality"`
		State        string   `json:"state"`
		Country      string   `json:"country"`
		Email        string   `json:"email"`
		DNSNames     []string `json:"san_dns"`
		IPAddresses  []string `json:"san_ips"`
		KeySize      int      `json:"key_size"`
		KeyType      string   `json:"key_type"`
		Curve        string   `json:"curve"`
		Intermediate string   `json:"intermediate"`
		CRLURL       string   `json:"crl_url"`
		OCSPURL      string   `json:"ocsp_url"`
		ValidityDays int      `json:"validity_days"` // 🔥 NEU
	}

	err := json.NewDecoder(r.Body).Decode(&input)
	if err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	fmt.Println("KEY TYPE:", input.KeyType)
	fmt.Println("CURVE:", input.Curve)
	fmt.Println("KEY SIZE:", input.KeySize)
	fmt.Println("VALIDITY DAYS:", input.ValidityDays)

	certType := input.Type
	if certType == "" {
		certType = "tls"
	}

	if input.KeyType == "" {
		input.KeyType = "rsa"
	}

	// 🔥 Fallback Gültigkeit
	if input.ValidityDays <= 0 {
		input.ValidityDays = 365
	}

	switch input.KeyType {
	case "rsa":
		if input.KeySize != 2048 && input.KeySize != 3072 && input.KeySize != 4096 {
			input.KeySize = 3072
		}
	case "ecdsa":
		if input.Curve == "" {
			input.Curve = "P256"
		}
	default:
		http.Error(w, "invalid key type", http.StatusBadRequest)
		return
	}

	key, err := ca.GenerateKey(input.KeyType, input.KeySize, input.Curve)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	keyPEM := crypto.EncodePrivateKeyToPEM(key)

	csr, err := ca.CreateCSR(ca.CSRInput{
		CommonName:   input.CommonName,
		Organization: input.Organization,
		OU:           input.OU,
		Locality:     input.Locality,
		State:        input.State,
		Country:      input.Country,
		Email:        input.Email,
		DNSNames:     input.DNSNames,
	}, key)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csr, key)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	var ips []net.IP
	if certType == "tls" {
		for _, ipStr := range input.IPAddresses {
			ip := net.ParseIP(ipStr)
			if ip != nil {
				ips = append(ips, ip)
			}
		}
	}

	// 🔥 SIGN
	cert, serial, err := ca.SignCSR(
		csr,
		input.Intermediate,
		input.CRLURL,
		ips,
		input.OCSPURL,
		certType,
		input.ValidityDays, // 🔥 NEU
	)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	chain, err := ca.BuildChain(cert, input.Intermediate)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	crtPath, csrPath, keyPathValue, chainPathValue, err := storage.StoreCertificate(
		input.CommonName,
		serial,
		cert,
		csrPEM,
		keyPEM,
		chain,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var keyPath *string
	if keyPathValue != "" {
		keyPath = &keyPathValue
	}

	var chainPath *string
	if chainPathValue != "" {
		chainPath = &chainPathValue
	}

	var san []string
	if certType == "tls" {
		san = append(input.DNSNames, input.IPAddresses...)
	}

	now := time.Now()
	response := SignResponse{
		Type:         certType,
		CommonName:   input.CommonName,
		SAN:          san,
		SerialNumber: serial,
		ValidFrom:    now,
		ValidTo:      now.AddDate(0, 0, input.ValidityDays), // 🔥 dynamisch
		CRTPath:      crtPath,
		CSRPath:      csrPath,
		KeyPath:      keyPath,
		ChainPath:    chainPath,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
