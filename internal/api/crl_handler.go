package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"ad-pki-ca/internal/config"
)

func CRLHandler(w http.ResponseWriter, r *http.Request) {

	// 🔥 Beispiel:
	// /crl/int-1.pem → int-1
	path := strings.TrimPrefix(r.URL.Path, "/crl/")
	id := strings.TrimSuffix(path, ".pem")

	if id == "" {
		http.Error(w, "missing CRL id", http.StatusBadRequest)
		return
	}

	// 🔥 Pfad: crl_int-1.pem
	crlPath := filepath.Join(config.BasePath(), "crl_"+id+".pem")

	crlBytes, err := os.ReadFile(crlPath)
	if err != nil {
		http.Error(w, "CRL not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Write(crlBytes)
}
