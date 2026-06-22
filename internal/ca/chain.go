package ca

import (
	"os"
	"path/filepath"

	"ad-pki-ca/internal/config"
)

func BuildChain(cert []byte, intermediateID string) ([]byte, error) {

	base := config.BasePath()

	// 🔐 Intermediate laden
	intermediatePath := filepath.Join(base, "intermediates", intermediateID, "intermediate.crt")

	intermediate, err := os.ReadFile(intermediatePath)
	if err != nil {
		return nil, err
	}

	// 🔐 Root laden
	rootPath := filepath.Join(base, "root", "root.crt")

	root, err := os.ReadFile(rootPath)
	if err != nil {
		return nil, err
	}

	// 🔥 Reihenfolge: leaf → intermediate → root
	chain := make([]byte, 0, len(cert)+len(intermediate)+len(root))
	chain = append(chain, cert...)
	chain = append(chain, intermediate...)
	chain = append(chain, root...)

	return chain, nil
}
