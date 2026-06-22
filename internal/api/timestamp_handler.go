// internal/api/timestamp_handler.go
package api

import (
	"crypto"
	"encoding/asn1"
	"io"
	"net/http"
	"time"

	"github.com/digitorus/timestamp"

	"ad-pki-ca/internal/ca"
)

// TimestampHandler — RFC 3161 Timestamp Authority
// POST /timestamp
func TimestampHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 10*1024*1024)

	// 🔥 Request Body lesen (DER-encoded TimeStampReq)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request", http.StatusBadRequest)
		return
	}

	// 🔥 RFC 3161 Request parsen
	tsReq, err := timestamp.ParseRequest(body)
	if err != nil {
		http.Error(w, "invalid timestamp request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 🔥 TSA Zertifikat laden
	tsaCA, err := ca.LoadTSACertificate()
	if err != nil {
		http.Error(w, "TSA certificate not available — generate one first", http.StatusServiceUnavailable)
		return
	}

	// 🔥 Timestamp erstellen aus Request Daten
	ts := &timestamp.Timestamp{
		HashAlgorithm:     tsReq.HashAlgorithm,
		HashedMessage:     tsReq.HashedMessage,
		Time:              time.Now().UTC(),
		Nonce:             tsReq.Nonce,
		AddTSACertificate: true, // TSA Cert in Response einbetten
		Policy:            asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1},
	}

	// 🔥 Signieren mit TSA Zertifikat
	signer, ok := tsaCA.Key.(crypto.Signer)
	if !ok {
		http.Error(w, "TSA key is not a valid signer", http.StatusInternalServerError)
		return
	}

	respDER, err := ts.CreateResponse(tsaCA.Cert, signer)
	if err != nil {
		http.Error(w, "failed to create timestamp response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/timestamp-reply")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(respDER); err != nil {
		return
	}
}
