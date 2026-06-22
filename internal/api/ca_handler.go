package api

import (
	"io"
	"net/http"

	"ad-pki-ca/internal/ca"
)

func ValidateIntermediateHandler(w http.ResponseWriter, r *http.Request) {

	rootFile, _, _ := r.FormFile("root")
	intFile, _, _ := r.FormFile("intermediate")

	rootBytes, _ := io.ReadAll(rootFile)
	intBytes, _ := io.ReadAll(intFile)

	err := ca.ValidateIntermediate(rootBytes, intBytes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Write([]byte("valid"))
}
