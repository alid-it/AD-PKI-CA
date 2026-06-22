package api

import (
	"crypto"
	"io"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/ocsp"

	"ad-pki-ca/internal/ca"
)

type cachedResponse struct {
	Data      []byte
	ExpiresAt time.Time
}

var ocspCache = make(map[string]cachedResponse)

// 🔥 Cache Key (Serial + Issuer)
func buildCacheKey(serial string, issuerID string) string {
	return issuerID + ":" + serial
}

func backendURL() string {
	u := os.Getenv("BACKEND_URL")
	if u == "" {
		return "http://127.0.0.1"
	}
	return u
}

func OCSPHandler(w http.ResponseWriter, r *http.Request) {

	// 🔥 Request Body lesen
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// 🔥 OCSP Request parsen
	req, err := ocsp.ParseRequest(body)
	if err != nil {
		http.Error(w, "invalid ocsp request", http.StatusBadRequest)
		return
	}

	serial := req.SerialNumber.Text(16)

	// 🔥 Alle Intermediates laden
	caList, err := ca.LoadAllIntermediates()
	if err != nil {
		http.Error(w, "failed to load intermediates", http.StatusInternalServerError)
		return
	}

	// 🔥 Issuer finden
	issuer := ca.FindIssuer(req, caList)
	if issuer == nil {
		http.Error(w, "issuer not found", http.StatusNotFound)
		return
	}

	// 🔥 Cache Key (JETZT korrekt)
	cacheKey := buildCacheKey(serial, issuer.ID)

	// 🔥 CACHE HIT
	if cached, ok := ocspCache[cacheKey]; ok {
		if time.Now().Before(cached.ExpiresAt) {
			w.Header().Set("Content-Type", "application/ocsp-response")
			w.WriteHeader(http.StatusOK)
			w.Write(cached.Data)
			return
		}
	}

	// 🔥 Revocation Status bestimmen
	status := ocsp.Good
	revokedAt := time.Time{}

	url := backendURL() + "/api/certificates/revoked?intermediate=" + issuer.ID

	revokedList, err := ca.FetchRevokedCertificates(url)
	if err == nil {
		for _, r := range revokedList {
			if r.SerialNumber.Cmp(req.SerialNumber) == 0 {
				status = ocsp.Revoked
				revokedAt = r.RevocationTime
				break
			}
		}
	}

	now := time.Now()

	// 🔥 Response Template
	template := ocsp.Response{
		Status:       status,
		SerialNumber: req.SerialNumber,
		ThisUpdate:   now,
		NextUpdate:   now.Add(1 * time.Hour),
	}

	if status == ocsp.Revoked {
		template.RevokedAt = revokedAt
	}

	// 🔥 Response signieren
	respBytes, err := ocsp.CreateResponse(
		issuer.Cert,
		issuer.Cert,
		template,
		issuer.Key.(crypto.Signer),
	)
	if err != nil {
		http.Error(w, "failed to create response", http.StatusInternalServerError)
		return
	}

	// 🔥 CACHE SPEICHERN
	ocspCache[cacheKey] = cachedResponse{
		Data:      respBytes,
		ExpiresAt: template.NextUpdate,
	}

	// 🔥 Antwort
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}
