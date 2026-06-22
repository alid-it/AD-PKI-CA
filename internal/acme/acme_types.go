// internal/acme/types.go
package acme

import "time"

// =====================================================
// 🔥 ACME Account (RFC 8555 §7.1.2)
// =====================================================

type AccountStatus string

const (
	AccountValid       AccountStatus = "valid"
	AccountDeactivated AccountStatus = "deactivated"
	AccountRevoked     AccountStatus = "revoked"
)

type Account struct {
	ID           string        `json:"id"`
	Status       AccountStatus `json:"status"`
	Contact      []string      `json:"contact,omitempty"`
	PublicKey    interface{}   `json:"-"`          // crypto.PublicKey
	PublicKeyJWK string        `json:"public_key"` // JSON encoded JWK
	CreatedAt    time.Time     `json:"created_at"`
}

// =====================================================
// 🔥 ACME Order (RFC 8555 §7.1.3)
// =====================================================

type OrderStatus string

const (
	OrderPending    OrderStatus = "pending"
	OrderReady      OrderStatus = "ready"
	OrderProcessing OrderStatus = "processing"
	OrderValid      OrderStatus = "valid"
	OrderInvalid    OrderStatus = "invalid"
)

type Order struct {
	ID             string       `json:"id"`
	AccountID      string       `json:"account_id"`
	Status         OrderStatus  `json:"status"`
	Identifiers    []Identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	FinalizeURL    string       `json:"finalize"`
	CertificateURL string       `json:"certificate,omitempty"`
	CertPath       string       `json:"cert_path,omitempty"`
	NotBefore      *time.Time   `json:"not_before,omitempty"`
	NotAfter       *time.Time   `json:"not_after,omitempty"`
	ExpiresAt      time.Time    `json:"expires"`
	CreatedAt      time.Time    `json:"created_at"`
	IntermediateID string       `json:"intermediate_id"`
}

// =====================================================
// 🔥 ACME Identifier
// =====================================================

type Identifier struct {
	Type  string `json:"type"`  // "dns"
	Value string `json:"value"` // "example.com"
}

// =====================================================
// 🔥 ACME Authorization (RFC 8555 §7.1.4)
// =====================================================

type AuthzStatus string

const (
	AuthzPending     AuthzStatus = "pending"
	AuthzValid       AuthzStatus = "valid"
	AuthzInvalid     AuthzStatus = "invalid"
	AuthzDeactivated AuthzStatus = "deactivated"
	AuthzExpired     AuthzStatus = "expired"
)

type Authorization struct {
	ID         string      `json:"id"`
	AccountID  string      `json:"account_id"`
	OrderID    string      `json:"order_id"`
	Status     AuthzStatus `json:"status"`
	Identifier Identifier  `json:"identifier"`
	Challenges []Challenge `json:"challenges"`
	ExpiresAt  time.Time   `json:"expires"`
	CreatedAt  time.Time   `json:"created_at"`
}

// =====================================================
// 🔥 ACME Challenge (RFC 8555 §8)
// =====================================================

type ChallengeStatus string

const (
	ChallengePending    ChallengeStatus = "pending"
	ChallengeProcessing ChallengeStatus = "processing"
	ChallengeValid      ChallengeStatus = "valid"
	ChallengeInvalid    ChallengeStatus = "invalid"
)

type Challenge struct {
	ID          string          `json:"id"`
	Type        string          `json:"type"` // "http-01" | "dns-01"
	Status      ChallengeStatus `json:"status"`
	Token       string          `json:"token"`
	URL         string          `json:"url"`
	ValidatedAt *time.Time      `json:"validated,omitempty"`
	Error       *ACMEError      `json:"error,omitempty"`
}

// =====================================================
// 🔥 ACME Error (RFC 8555 §6.7)
// =====================================================

type ACMEError struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

func (e *ACMEError) Error() string {
	return e.Detail
}

// Standard ACME Error Types
var (
	ErrBadNonce         = &ACMEError{Type: "urn:ietf:params:acme:error:badNonce", Status: 400}
	ErrMalformed        = &ACMEError{Type: "urn:ietf:params:acme:error:malformed", Status: 400}
	ErrUnauthorized     = &ACMEError{Type: "urn:ietf:params:acme:error:unauthorized", Status: 403}
	ErrNotFound         = &ACMEError{Type: "urn:ietf:params:acme:error:accountDoesNotExist", Status: 404}
	ErrRateLimited      = &ACMEError{Type: "urn:ietf:params:acme:error:rateLimited", Status: 429}
	ErrConnectionFailed = &ACMEError{Type: "urn:ietf:params:acme:error:connection", Status: 400}
)
