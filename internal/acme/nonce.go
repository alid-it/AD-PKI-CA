// internal/acme/nonce.go
package acme

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// nonceEntry — gespeicherter Nonce mit Ablaufzeit
type nonceEntry struct {
	createdAt time.Time
}

// NonceManager — verwaltet ACME Replay Nonces
// RFC 8555: Jeder POST Request muss einen gültigen Nonce enthalten
type NonceManager struct {
	mu     sync.Mutex
	nonces map[string]nonceEntry
}

var Nonces = &NonceManager{
	nonces: make(map[string]nonceEntry),
}

// Generate — neuen Nonce erstellen
func (n *NonceManager) Generate() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	nonce := base64.RawURLEncoding.EncodeToString(b)

	n.mu.Lock()
	n.nonces[nonce] = nonceEntry{createdAt: time.Now()}
	n.mu.Unlock()

	// 🔥 Alte Nonces aufräumen (älter als 1 Stunde)
	go n.cleanup()

	return nonce, nil
}

// Consume — Nonce prüfen und verbrauchen (einmalig verwendbar!)
func (n *NonceManager) Consume(nonce string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	entry, exists := n.nonces[nonce]
	if !exists {
		return false // Nonce existiert nicht
	}

	// 🔥 Abgelaufen? (älter als 1 Stunde)
	if time.Since(entry.createdAt) > time.Hour {
		delete(n.nonces, nonce)
		return false
	}

	// 🔥 Verbrauchen — Replay Schutz
	delete(n.nonces, nonce)
	return true
}

// cleanup — abgelaufene Nonces entfernen
func (n *NonceManager) cleanup() {
	n.mu.Lock()
	defer n.mu.Unlock()

	for nonce, entry := range n.nonces {
		if time.Since(entry.createdAt) > time.Hour {
			delete(n.nonces, nonce)
		}
	}
}
