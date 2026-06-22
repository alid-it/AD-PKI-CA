// internal/acme/jws.go
package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v3"
)

// JWSPayload — dekodierter JWS Request von Certbot/acme.sh
type JWSPayload struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// ParsedJWS — verarbeiteter JWS mit Daten
type ParsedJWS struct {
	AccountURL string           // URL des Accounts (aus kid Header)
	PublicKey  crypto.PublicKey // Public Key (aus jwk Header, nur bei new-account)
	Payload    []byte           // Dekodiertes Payload
	Nonce      string           // Nonce aus Protected Header
	URL        string           // URL aus Protected Header
}

// ParseAndVerifyJWS — JWS parsen + Signatur prüfen
func ParseAndVerifyJWS(body []byte) (*ParsedJWS, error) {
	var jws jose.JSONWebSignature

	if err := json.Unmarshal(body, &jws); err != nil {
		// 🔥 Fallback: als Flattened JWS parsen
		flatJWS, err2 := jose.ParseSigned(string(body))
		if err2 != nil {
			return nil, fmt.Errorf("invalid JWS: %w", err)
		}
		jws = *flatJWS
	}

	if len(jws.Signatures) == 0 {
		return nil, errors.New("no signatures in JWS")
	}

	sig := jws.Signatures[0]
	protected := sig.Protected

	// 🔥 Nonce prüfen
	nonce, ok := protected.ExtraHeaders["nonce"].(string)
	if !ok || nonce == "" {
		return nil, errors.New("missing nonce in JWS header")
	}

	if !Nonces.Consume(nonce) {
		return nil, errors.New("invalid or already used nonce")
	}

	// 🔥 URL prüfen
	url, _ := protected.ExtraHeaders["url"].(string)

	result := &ParsedJWS{
		Nonce: nonce,
		URL:   url,
	}

	// 🔥 Public Key aus JWK (new-account) oder kid (bestehender Account)
	if protected.KeyID != "" {
		// Bestehender Account — kid = Account URL
		result.AccountURL = protected.KeyID
	}

	// 🔥 Signatur verifizieren wenn JWK vorhanden
	if protected.JSONWebKey != nil {
		pubKey := protected.JSONWebKey.Public()

		var verifyErr error

		switch k := pubKey.Key.(type) {
		case *rsa.PublicKey:
			payload, err := jws.Verify(k)
			if err != nil {
				verifyErr = err
			} else {
				result.Payload = payload
				result.PublicKey = k
			}
		case *ecdsa.PublicKey:
			payload, err := jws.Verify(k)
			if err != nil {
				verifyErr = err
			} else {
				result.Payload = payload
				result.PublicKey = k
			}
		default:
			verifyErr = errors.New("unsupported key type")
		}

		if verifyErr != nil {
			return nil, fmt.Errorf("JWS verification failed: %w", verifyErr)
		}
	} else {
		// 🔥 Payload ohne Verifikation (wird später mit Account Key verifiziert)
		result.Payload = jws.UnsafePayloadWithoutVerification()
	}

	return result, nil
}
