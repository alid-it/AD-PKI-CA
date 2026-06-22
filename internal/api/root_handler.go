package api

import (
	"io"
	"net/http"

	"ad-pki-ca/internal/storage"
)

func ImportRootHandler(w http.ResponseWriter, r *http.Request) {

	rootFile, _, err := r.FormFile("root")
	if err != nil {
		http.Error(w, "missing root", 400)
		return
	}

	rootBytes, _ := io.ReadAll(rootFile)

	err = storage.StoreRoot(rootBytes)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Write([]byte("root stored"))
}
