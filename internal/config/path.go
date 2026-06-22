package config

import "os"

func BasePath() string {
	base := os.Getenv("PKI_BASE_DIR")
	if base == "" {
		base = "/var/lib/adpki"
	}
	return base
}
