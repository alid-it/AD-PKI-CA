// internal/acme/account.go
package acme

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ad-pki-ca/internal/config"

	"github.com/go-jose/go-jose/v3"
)

// =====================================================
// 🔥 Account Key Thumbprint — eindeutige ID pro Key
// RFC 7638: SHA-256 des JWK (kanonisch)
// =====================================================

func KeyThumbprint(jwk *jose.JSONWebKey) (string, error) {
	thumb, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("thumbprint failed: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(thumb), nil
}

// =====================================================
// 🔥 Account ID generieren
// =====================================================

func NewAccountID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// =====================================================
// 🔥 Account by Key Thumbprint finden/speichern
// Mapping: /acme/accounts/by-key/{thumbprint} → account_id
// =====================================================

func thumbprintPath(thumbprint string) string {
	// Slashes aus Thumbprint entfernen (base64url safe)
	safe := strings.ReplaceAll(thumbprint, "/", "_")
	return filepath.Join(config.BasePath(), "acme", "accounts", "by-key", safe)
}

func FindAccountByKey(jwk *jose.JSONWebKey) (*Account, error) {
	thumb, err := KeyThumbprint(jwk)
	if err != nil {
		return nil, err
	}

	// Mapping Datei lesen
	data, err := os.ReadFile(thumbprintPath(thumb))
	if err != nil {
		return nil, nil // Nicht gefunden — kein Fehler
	}

	accountID := strings.TrimSpace(string(data))
	return LoadAccount(accountID)
}

func SaveAccountKeyMapping(accountID string, jwk *jose.JSONWebKey) error {
	thumb, err := KeyThumbprint(jwk)
	if err != nil {
		return err
	}

	dir := filepath.Dir(thumbprintPath(thumb))
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(thumbprintPath(thumb), []byte(accountID), 0644)
}

// =====================================================
// 🔥 Account aus JWK erstellen
// =====================================================

func NewAccount(jwk *jose.JSONWebKey, contact []string) (*Account, error) {
	id, err := NewAccountID()
	if err != nil {
		return nil, err
	}

	// JWK als JSON speichern
	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		return nil, err
	}

	acc := &Account{
		ID:           id,
		Status:       AccountValid,
		Contact:      contact,
		PublicKeyJWK: string(jwkJSON),
	}

	return acc, nil
}

// =====================================================
// 🔥 Account Public Key laden
// =====================================================

func LoadAccountJWK(acc *Account) (*jose.JSONWebKey, error) {
	var jwk jose.JSONWebKey
	if err := json.Unmarshal([]byte(acc.PublicKeyJWK), &jwk); err != nil {
		return nil, fmt.Errorf("failed to parse account JWK: %w", err)
	}
	return &jwk, nil
}
