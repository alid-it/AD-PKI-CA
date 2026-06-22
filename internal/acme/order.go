// internal/acme/order.go
package acme

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

func NewOrderID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func NewAuthzID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func NewChallengeToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func NewChallengeID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func NewAuthorization(accountID, orderID string, identifier Identifier, baseURL string) (*Authorization, error) {
	authzID, err := NewAuthzID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate authz id: %w", err)
	}

	// 🔥 Challenge-Typen basierend auf Identifier
	var challenges []Challenge
	isWildcard := strings.HasPrefix(identifier.Value, "*.")

	// DNS-01 immer anbieten
	dns01ChallID, _ := NewChallengeID()
	dns01Token, _ := NewChallengeToken()
	challenges = append(challenges, Challenge{
		ID:     dns01ChallID,
		Type:   "dns-01",
		Status: ChallengePending,
		Token:  dns01Token,
		URL:    baseURL + "/acme/challenge/" + dns01ChallID,
	})

	// HTTP-01 nur für nicht-Wildcard Domains
	if !isWildcard {
		http01ChallID, _ := NewChallengeID()
		http01Token, _ := NewChallengeToken()
		challenges = append(challenges, Challenge{
			ID:     http01ChallID,
			Type:   "http-01",
			Status: ChallengePending,
			Token:  http01Token,
			URL:    baseURL + "/acme/challenge/" + http01ChallID,
		})
	}

	authz := &Authorization{
		ID:         authzID,
		AccountID:  accountID,
		OrderID:    orderID,
		Status:     AuthzPending,
		Identifier: identifier,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CreatedAt:  time.Now(),
		Challenges: challenges,
	}

	return authz, nil
}

func NewOrder(accountID string, identifiers []Identifier, baseURL string) (*Order, *[]Authorization, error) {
	orderID, err := NewOrderID()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate order id: %w", err)
	}

	authzURLs := []string{}
	authzList := []Authorization{}

	for _, ident := range identifiers {
		authz, err := NewAuthorization(accountID, orderID, ident, baseURL)
		if err != nil {
			return nil, nil, err
		}
		authzURLs = append(authzURLs, baseURL+"/acme/authz/"+authz.ID)
		authzList = append(authzList, *authz)
	}

	order := &Order{
		ID:             orderID,
		AccountID:      accountID,
		Status:         OrderPending,
		Identifiers:    identifiers,
		Authorizations: authzURLs,
		FinalizeURL:    baseURL + "/acme/finalize/" + orderID,
		ExpiresAt:      time.Now().Add(24 * time.Hour),
		CreatedAt:      time.Now(),
	}

	return order, &authzList, nil
}

func UpdateOrderStatus(orderID string) {
	order, err := LoadOrder(orderID)
	if err != nil {
		return
	}

	allValid := true
	anyInvalid := false

	for _, authzURL := range order.Authorizations {
		// Authz ID aus URL extrahieren
		authzID := authzURL[strings.LastIndex(authzURL, "/")+1:]
		authz, err := LoadAuthz(authzID)
		if err != nil {
			allValid = false
			continue
		}
		if authz.Status == AuthzInvalid {
			anyInvalid = true
		}
		if authz.Status != AuthzValid {
			allValid = false
		}
	}

	if anyInvalid {
		order.Status = OrderInvalid
	} else if allValid {
		order.Status = OrderReady
	}

	SaveOrder(order)
}
