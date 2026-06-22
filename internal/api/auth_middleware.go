// internal/api/middleware.go
package api

import (
	"net/http"
	"os"
)

// AuthMiddleware prüft den X-CA-Token Header
// Wenn CA_TOKEN nicht gesetzt → alle Requests erlaubt (Backward Compatible)
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := os.Getenv("CA_TOKEN")

		// 🔥 Kein Token konfiguriert → erlaubt (Dev-Modus)
		if token == "" {
			next(w, r)
			return
		}

		// 🔥 Token prüfen
		if r.Header.Get("X-CA-Token") != token {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}