package api

import (
	"encoding/json"
	"io"
	"net/http"

	"ad-pki-ca/internal/ca"
	"ad-pki-ca/internal/storage"
)

func ImportIntermediateHandler(w http.ResponseWriter, r *http.Request) {

	name := r.FormValue("name")
	if name == "" {
		http.Error(w, "missing name", 400)
		return
	}

	rootFile, _, err := r.FormFile("root")
	if err != nil {
		http.Error(w, "missing root", 400)
		return
	}

	intFile, _, err := r.FormFile("intermediate")
	if err != nil {
		http.Error(w, "missing intermediate", 400)
		return
	}

	keyFile, _, err := r.FormFile("key")
	if err != nil {
		http.Error(w, "missing key", 400)
		return
	}

	rootBytes, err := io.ReadAll(rootFile)
	if err != nil {
		http.Error(w, "failed to read root", 500)
		return
	}

	intBytes, err := io.ReadAll(intFile)
	if err != nil {
		http.Error(w, "failed to read intermediate", 500)
		return
	}

	keyBytes, err := io.ReadAll(keyFile)
	if err != nil {
		http.Error(w, "failed to read key", 500)
		return
	}

	// 1. Validate
	if err := ca.ValidateIntermediate(rootBytes, intBytes); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	if err := ca.ValidateKeyMatchesCert(intBytes, keyBytes); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	// 2. Store
	crtPath, keyPath, err := storage.StoreIntermediate(name, intBytes, keyBytes)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// 3. Parse Cert
	meta, err := ca.ParseCertificate(intBytes)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// 4. Response
	response := map[string]interface{}{
		"id":         name,
		"crt_path":   crtPath,
		"key_path":   keyPath,
		"cn":         meta.CommonName,
		"serial":     meta.Serial,
		"valid_from": meta.ValidFrom,
		"valid_to":   meta.ValidTo,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
