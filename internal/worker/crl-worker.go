package crl

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"ad-pki-ca/internal/ca"
	"ad-pki-ca/internal/config"
)

func backendURL() string {
	u := os.Getenv("BACKEND_URL")
	if u == "" {
		return "http://127.0.0.1"
	}
	return u
}

func StartCRLWorker() {

	go func() {

		const interval = 5 * time.Minute
		const retry = 1 * time.Minute

		for {

			log.Println("[CRL] Updating CRLs...")

			// 🔥 alle Intermediates laden
			cas, err := ca.LoadAllIntermediates()
			if err != nil {
				log.Println("[CRL] failed to load intermediates:", err)
				time.Sleep(retry)
				continue
			}

			base := config.BasePath()

			for _, c := range cas {

				log.Println("[CRL] generating for:", c.ID)

				// 🔥 HIER IST DER WICHTIGE FIX
				url := backendURL() + "/api/internal/crl/revoked?intermediate=" + c.ID

				revoked, err := ca.FetchRevokedCertificates(url)
				if err != nil {
					log.Println("[CRL] fetch error:", c.ID, err)
					continue
				}

				crl, err := ca.GenerateCRL(c.ID, revoked)
				if err != nil {
					log.Println("[CRL] generate error:", c.ID, err)
					continue
				}

				crlPath := filepath.Join(base, "crl_"+c.ID+".pem")

				err = os.WriteFile(crlPath, crl, 0644)
				if err != nil {
					log.Println("[CRL] write error:", c.ID, err)
					continue
				}

				log.Println("[CRL] updated:", c.ID)
			}

			time.Sleep(interval)
		}
	}()
}
