// internal/acme/challenge.go
package acme

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ValidateHTTP01 — HTTP-01 Challenge validieren (RFC 8555 §8.3)
func ValidateHTTP01(authz *Authorization, chall *Challenge) error {
	acc, err := LoadAccount(authz.AccountID)
	if err != nil {
		return fmt.Errorf("account not found: %w", err)
	}

	jwk, err := LoadAccountJWK(acc)
	if err != nil {
		return fmt.Errorf("failed to load account key: %w", err)
	}

	thumb, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return fmt.Errorf("thumbprint failed: %w", err)
	}
	thumbStr := base64.RawURLEncoding.EncodeToString(thumb)
	keyAuth := chall.Token + "." + thumbStr

	url := fmt.Sprintf("http://%s/.well-known/acme-challenge/%s",
		authz.Identifier.Value, chall.Token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP-01 request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP-01 returned status %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read HTTP-01 response: %w", err)
	}

	got := strings.TrimSpace(string(bodyBytes))
	if got != keyAuth {
		return fmt.Errorf("HTTP-01 key authorization mismatch: got %q, want %q", got, keyAuth)
	}

	return nil
}

// =====================================================
// 🔥 DNS-01 Challenge validieren (RFC 8555 §8.4)
// =====================================================

func ValidateDNS01(authz *Authorization, chall *Challenge) error {
	acc, err := LoadAccount(authz.AccountID)
	if err != nil {
		return fmt.Errorf("account not found: %w", err)
	}

	jwk, err := LoadAccountJWK(acc)
	if err != nil {
		return fmt.Errorf("failed to load account key: %w", err)
	}

	thumb, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return fmt.Errorf("thumbprint failed: %w", err)
	}
	thumbStr := base64.RawURLEncoding.EncodeToString(thumb)
	keyAuth := chall.Token + "." + thumbStr

	// 🔥 DNS-01: SHA256(keyAuth) als Base64url
	h := sha256.Sum256([]byte(keyAuth))
	expectedTXT := base64.RawURLEncoding.EncodeToString(h[:])

	// 🔥 Domain für TXT-Record — Wildcard bereinigen
	domain := authz.Identifier.Value
	domain = strings.TrimPrefix(domain, "*.")
	txtDomain := "_acme-challenge." + domain

	fmt.Printf("🔥 DNS-01: identifier=%s txtDomain=%s expected=%s\n",
		authz.Identifier.Value, txtDomain, expectedTXT)

	// 🔥 DNS-Server aus Settings
	dnsServers, err := loadDNSServers()
	if err != nil || len(dnsServers) == 0 {
		fmt.Println("🔥 DNS-01: Fallback auf 8.8.8.8")
		dnsServers = []string{"8.8.8.8"}
	}

	fmt.Printf("🔥 DNS-01: verwende DNS-Server %s\n", dnsServers[0])

	// 🔥 TXT-Record abfragen
	txtRecords, err := lookupTXT(txtDomain, dnsServers[0])
	if err != nil {
		fmt.Printf("🔥 DNS-01: lookup error: %v\n", err)
		return fmt.Errorf("DNS lookup failed for %s: %w", txtDomain, err)
	}

	fmt.Printf("🔥 DNS-01: gefundene Records: %v\n", txtRecords)

	for _, txt := range txtRecords {
		if txt == expectedTXT {
			fmt.Println("🔥 DNS-01: Validierung erfolgreich ✅")
			return nil
		}
	}

	return fmt.Errorf("DNS-01 TXT record not found for %s (expected: %s, got: %v)",
		txtDomain, expectedTXT, txtRecords)
}

// =====================================================
// 🔥 TXT-Record über spezifischen DNS-Server abfragen
// =====================================================

func lookupTXT(domain, dnsServer string) ([]string, error) {
	if !strings.Contains(dnsServer, ":") {
		dnsServer = dnsServer + ":53"
	}

	c := dns.Client{Timeout: 10 * time.Second}

	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
	m.RecursionDesired = true

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	r, _, err := c.ExchangeContext(ctx, &m, dnsServer)
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %w", err)
	}

	var records []string
	for _, ans := range r.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			records = append(records, strings.Join(txt.Txt, ""))
		}
	}

	return records, nil
}

// =====================================================
// 🔥 DNS-Server aus Laravel Settings laden
// =====================================================

func loadDNSServers() ([]string, error) {
	settings, err := fetchACMESettings()
	if err != nil {
		fmt.Printf("🔥 loadDNSServers error: %v\n", err)
		return nil, err
	}
	fmt.Printf("🔥 loadDNSServers: %v\n", settings.DNSServers)
	return settings.DNSServers, nil
}

// =====================================================
// 🔥 Challenge Mappings
// =====================================================

func FindChallengeByID(challID string) (*Authorization, *Challenge, error) {
	mappingPath := acmePath("challenges", challID)
	authzID, err := readStringFile(mappingPath)
	if err != nil {
		return nil, nil, fmt.Errorf("challenge not found: %s", challID)
	}

	authz, err := LoadAuthz(authzID)
	if err != nil {
		return nil, nil, fmt.Errorf("authz not found for challenge: %w", err)
	}

	for i := range authz.Challenges {
		if authz.Challenges[i].ID == challID {
			return authz, &authz.Challenges[i], nil
		}
	}

	return nil, nil, fmt.Errorf("challenge %s not found in authz", challID)
}

func SaveChallengeMapping(challID, authzID string) error {
	if err := ensureDir(acmePath("challenges")); err != nil {
		return err
	}
	return writeStringFile(acmePath("challenges", challID), authzID)
}
