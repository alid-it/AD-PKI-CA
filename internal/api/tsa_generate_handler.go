// internal/api/tsa_generate_handler.go
package api

import (
	"encoding/json"
	"net/http"

	"ad-pki-ca/internal/ca"
	"ad-pki-ca/internal/storage"
)

type TSAGenerateRequest struct {
	IntermediateID string `json:"intermediate_id"`
}

type TSAGenerateResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// TSAGenerateHandler generiert ein neues TSA Zertifikat
// POST /tsa/generate
func TSAGenerateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)

	var input TSAGenerateRequest

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if input.IntermediateID == "" {
		http.Error(w, "intermediate_id is required", http.StatusBadRequest)
		return
	}

	// 🔥 TSA Zertifikat generieren
	tsaCert, err := ca.GenerateTSACertificate(input.IntermediateID)
	if err != nil {
		http.Error(w, "failed to generate TSA certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 🔥 Speichern
	if err := storage.StoreTSACertificate(tsaCert.CertPEM, tsaCert.KeyPEM); err != nil {
		http.Error(w, "failed to store TSA certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(TSAGenerateResponse{
		Success: true,
		Message: "TSA Zertifikat erfolgreich erstellt",
	}); err != nil {
		return
	}
}

// TSAStatusHandler gibt zurück ob ein TSA Zertifikat vorhanden ist
// GET /tsa/status
func TSAStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	exists := ca.TSAExists()

	status := map[string]interface{}{
		"exists": exists,
	}

	// 🔥 Wenn vorhanden — Zertifikat Info laden
	if exists {
		tsaCA, err := ca.LoadTSACertificate()
		if err == nil {
			status["common_name"] = tsaCA.Cert.Subject.CommonName
			status["valid_from"] = tsaCA.Cert.NotBefore
			status["valid_to"] = tsaCA.Cert.NotAfter
			status["serial"] = tsaCA.Cert.SerialNumber.Text(16)
		}
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(status); err != nil {
		return
	}
}
