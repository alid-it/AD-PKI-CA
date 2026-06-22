// internal/api/acme_handler.go
package api

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"ad-pki-ca/internal/acme"

	"github.com/go-jose/go-jose/v3"
)

// =====================================================
// 🔥 ACME HELPERS
// =====================================================

// acmeBaseURL — Basis URL für ACME Links
func acmeBaseURL(r *http.Request) string {
	scheme := "http"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// writeACMEError — ACME Fehler Response
func writeACMEError(w http.ResponseWriter, err *acme.ACMEError, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(err.Status)

	resp := map[string]interface{}{
		"type":   err.Type,
		"detail": detail,
		"status": err.Status,
	}
	json.NewEncoder(w).Encode(resp)
}

// addNonce — neuen Nonce zu Response Header hinzufügen
func addNonce(w http.ResponseWriter) {
	nonce, err := acme.Nonces.Generate()
	if err == nil {
		w.Header().Set("Replay-Nonce", nonce)
	}
}

// =====================================================
// 🔥 DIRECTORY ENDPOINT (RFC 8555 §7.1.1)
// Einstiegspunkt für alle ACME Clients
// GET /acme/directory
// =====================================================

func ACMEDirectoryHandler(w http.ResponseWriter, r *http.Request) {
	base := acmeBaseURL(r)

	directory := map[string]interface{}{
		"newNonce":   base + "/acme/new-nonce",
		"newAccount": base + "/acme/new-account",
		"newOrder":   base + "/acme/new-order",
		"revokeCert": base + "/acme/revoke-cert",
		"keyChange":  base + "/acme/key-change",
		"meta": map[string]interface{}{
			"termsOfService":          base + "/acme/terms",
			"website":                 base,
			"caaIdentities":           []string{},
			"externalAccountRequired": false,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	addNonce(w)
	json.NewEncoder(w).Encode(directory)
}

// =====================================================
// 🔥 NEW NONCE (RFC 8555 §7.2)
// HEAD /acme/new-nonce → nur Header
// GET  /acme/new-nonce → 204 No Content
// =====================================================

func ACMENewNonceHandler(w http.ResponseWriter, r *http.Request) {
	nonce, err := acme.Nonces.Generate()
	if err != nil {
		http.Error(w, "failed to generate nonce", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Cache-Control", "no-store")

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	// GET → 204 No Content
	w.WriteHeader(http.StatusNoContent)
}

// =====================================================
// 🔥 PLACEHOLDER HANDLERS
// werden Schritt für Schritt implementiert
// =====================================================

// =====================================================
// 🔥 NEW ACCOUNT (RFC 8555 §7.3)
// POST /acme/new-account
// =====================================================

func ACMENewAccountHandler(w http.ResponseWriter, r *http.Request) {
	addNonce(w)

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeACMEError(w, acme.ErrMalformed, "failed to read request body")
		return
	}

	// 🔥 Raw JWS struct parsen — go-jose kennt "nonce" nicht als Standard-Header
	var rawJWS struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(body, &rawJWS); err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid JWS structure")
		return
	}

	// 🔥 Protected Header Base64url dekodieren
	protectedBytes, err := base64.RawURLEncoding.DecodeString(rawJWS.Protected)
	if err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid protected header encoding")
		return
	}

	var protectedHeader struct {
		Alg   string          `json:"alg"`
		Nonce string          `json:"nonce"`
		URL   string          `json:"url"`
		JWK   json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(protectedBytes, &protectedHeader); err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid protected header")
		return
	}

	// 🔥 Nonce validieren — JETZT aus manuell dekodiertem Header
	if protectedHeader.Nonce == "" || !acme.Nonces.Consume(protectedHeader.Nonce) {
		writeACMEError(w, acme.ErrBadNonce, "invalid or missing nonce")
		return
	}

	// 🔥 JWK aus Protected Header
	if protectedHeader.JWK == nil {
		writeACMEError(w, acme.ErrMalformed, "missing JWK in protected header")
		return
	}
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(protectedHeader.JWK, &jwk); err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid JWK: "+err.Error())
		return
	}

	// 🔥 Signatur verifizieren via go-jose
	jws, err := jose.ParseSigned(string(body))
	if err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid JWS: "+err.Error())
		return
	}
	payload, err := jws.Verify(&jwk)
	if err != nil {
		writeACMEError(w, acme.ErrUnauthorized, "JWS signature verification failed")
		return
	}

	// 🔥 Payload parsen
	var reqPayload struct {
		TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
		Contact              []string `json:"contact"`
		OnlyReturnExisting   bool     `json:"onlyReturnExisting"`
	}
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &reqPayload); err != nil {
			writeACMEError(w, acme.ErrMalformed, "invalid payload")
			return
		}
	}

	// 🔥 Existierenden Account suchen
	existingAcc, _ := acme.FindAccountByKey(&jwk)
	if existingAcc != nil {
		base := acmeBaseURL(r)
		accountURL := base + "/acme/account/" + existingAcc.ID
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", accountURL)
		w.WriteHeader(http.StatusOK)
		writeAccountResponse(w, existingAcc, accountURL)
		return
	}

	if reqPayload.OnlyReturnExisting {
		writeACMEError(w, acme.ErrNotFound, "account does not exist")
		return
	}

	acc, err := acme.NewAccount(&jwk, reqPayload.Contact)
	if err != nil {
		writeACMEError(w, acme.ErrMalformed, "failed to create account")
		return
	}
	acc.CreatedAt = time.Now()

	if err := acme.SaveAccount(acc); err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if err := acme.SaveAccountKeyMapping(acc.ID, &jwk); err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	base := acmeBaseURL(r)
	accountURL := base + "/acme/account/" + acc.ID
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", accountURL)
	w.WriteHeader(http.StatusCreated)
	writeAccountResponse(w, acc, accountURL)
}

// =====================================================
// 🔥 ACCOUNT RESPONSE
// =====================================================

func writeAccountResponse(w http.ResponseWriter, acc *acme.Account, accountURL string) {
	resp := map[string]interface{}{
		"status":  acc.Status,
		"contact": acc.Contact,
		"orders":  accountURL + "/orders",
	}
	json.NewEncoder(w).Encode(resp)
}

// =====================================================
// 🔥 GET ACCOUNT (RFC 8555 §7.3.3)
// POST /acme/account/{id}
// =====================================================

func ACMEAccountHandler(w http.ResponseWriter, r *http.Request) {
	addNonce(w)

	// ID aus URL extrahieren: /acme/account/{id}
	id := r.URL.Path[len("/acme/account/"):]
	if id == "" {
		writeACMEError(w, acme.ErrMalformed, "missing account id")
		return
	}

	acc, err := acme.LoadAccount(id)
	if err != nil {
		writeACMEError(w, acme.ErrNotFound, "account not found")
		return
	}

	base := acmeBaseURL(r)
	accountURL := base + "/acme/account/" + acc.ID

	w.Header().Set("Content-Type", "application/json")
	writeAccountResponse(w, acc, accountURL)
}

// =====================================================
// 🔥 NEW ORDER (RFC 8555 §7.4)
// POST /acme/new-order
// =====================================================

func ACMENewOrderHandler(w http.ResponseWriter, r *http.Request) {
	addNonce(w)

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeACMEError(w, acme.ErrMalformed, "failed to read request body")
		return
	}

	// 🔥 Protected Header manuell dekodieren
	var rawJWS struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(body, &rawJWS); err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid JWS structure")
		return
	}

	protectedBytes, err := base64.RawURLEncoding.DecodeString(rawJWS.Protected)
	if err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid protected header encoding")
		return
	}

	var protectedHeader struct {
		Nonce string `json:"nonce"`
		URL   string `json:"url"`
		KID   string `json:"kid"`
	}
	if err := json.Unmarshal(protectedBytes, &protectedHeader); err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid protected header")
		return
	}

	// 🔥 Nonce validieren
	if protectedHeader.Nonce == "" || !acme.Nonces.Consume(protectedHeader.Nonce) {
		writeACMEError(w, acme.ErrBadNonce, "invalid or missing nonce")
		return
	}

	// 🔥 Account via kid authentifizieren
	// kid = "http://127.0.0.1:8080/acme/account/{id}"
	if protectedHeader.KID == "" {
		writeACMEError(w, acme.ErrUnauthorized, "missing kid in protected header")
		return
	}

	accountID := extractID(protectedHeader.KID, "/acme/account/")
	if accountID == "" {
		writeACMEError(w, acme.ErrUnauthorized, "invalid kid format")
		return
	}

	acc, err := acme.LoadAccount(accountID)
	if err != nil || acc.Status != acme.AccountValid {
		writeACMEError(w, acme.ErrUnauthorized, "account not found or not valid")
		return
	}

	// 🔥 Signatur verifizieren
	jwk, err := acme.LoadAccountJWK(acc)
	if err != nil {
		writeACMEError(w, acme.ErrUnauthorized, "failed to load account key")
		return
	}

	jws, err := jose.ParseSigned(string(body))
	if err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid JWS")
		return
	}

	payload, err := jws.Verify(jwk)
	if err != nil {
		writeACMEError(w, acme.ErrUnauthorized, "JWS signature verification failed")
		return
	}

	// 🔥 Payload parsen
	var orderReq struct {
		Identifiers []acme.Identifier `json:"identifiers"`
		NotBefore   string            `json:"notBefore,omitempty"`
		NotAfter    string            `json:"notAfter,omitempty"`
	}
	if err := json.Unmarshal(payload, &orderReq); err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid order payload")
		return
	}

	// 🔥 Identifiers validieren
	if len(orderReq.Identifiers) == 0 {
		writeACMEError(w, acme.ErrMalformed, "no identifiers in order")
		return
	}
	for _, ident := range orderReq.Identifiers {
		if ident.Type != "dns" {
			writeACMEError(w, acme.ErrMalformed, "only dns identifiers supported, got: "+ident.Type)
			return
		}
		if ident.Value == "" {
			writeACMEError(w, acme.ErrMalformed, "identifier value must not be empty")
			return
		}
		// 🔥 Wildcard nur mit DNS-01 erlaubt — wird später beim Challenge-Typ geprüft
	}

	// 🔥 Order + Authorizations erstellen
	base := acmeBaseURL(r)
	order, authzList, err := acme.NewOrder(acc.ID, orderReq.Identifiers, base)
	if err != nil {
		http.Error(w, "failed to create order", http.StatusInternalServerError)
		return
	}

	// 🔥 Authorizations + Challenge-Mappings speichern
	for _, authz := range *authzList {
		authzCopy := authz
		if err := acme.SaveAuthz(&authzCopy); err != nil {
			http.Error(w, "storage error", http.StatusInternalServerError)
			return
		}
		// Challenge → Authz Mapping für schnelles Lookup
		for _, chall := range authz.Challenges {
			if err := acme.SaveChallengeMapping(chall.ID, authz.ID); err != nil {
				http.Error(w, "storage error", http.StatusInternalServerError)
				return
			}
		}
	}

	// 🔥 Order speichern
	if err := acme.SaveOrder(order); err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	// 🔥 Response (RFC 8555 §7.4)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", base+"/acme/order/"+order.ID)
	w.WriteHeader(http.StatusCreated)

	resp := map[string]interface{}{
		"status":         order.Status,
		"expires":        order.ExpiresAt,
		"identifiers":    order.Identifiers,
		"authorizations": order.Authorizations,
		"finalize":       order.FinalizeURL,
	}
	json.NewEncoder(w).Encode(resp)
}

// =====================================================
// 🔥 HELPER — ID aus URL extrahieren
// =====================================================

func extractID(url, prefix string) string {
	idx := len(prefix)
	for i := 0; i < len(url)-len(prefix)+1; i++ {
		if url[i:i+len(prefix)] == prefix {
			return url[i+idx:]
		}
	}
	return ""
}

func ACMEAuthzHandler(w http.ResponseWriter, r *http.Request) {
	addNonce(w)

	id := r.URL.Path[len("/acme/authz/"):]
	if id == "" {
		writeACMEError(w, acme.ErrMalformed, "missing authz id")
		return
	}

	authz, err := acme.LoadAuthz(id)
	if err != nil {
		writeACMEError(w, acme.ErrNotFound, "authorization not found")
		return
	}

	base := acmeBaseURL(r)

	challenges := []map[string]interface{}{}
	for _, chall := range authz.Challenges {
		c := map[string]interface{}{
			"type":   chall.Type,
			"status": chall.Status,
			"token":  chall.Token,
			"url":    base + "/acme/challenge/" + chall.ID,
		}
		if chall.ValidatedAt != nil {
			c["validated"] = chall.ValidatedAt
		}
		challenges = append(challenges, c)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := map[string]interface{}{
		"status":     authz.Status,
		"expires":    authz.ExpiresAt,
		"identifier": authz.Identifier,
		"challenges": challenges,
	}
	json.NewEncoder(w).Encode(resp)
}

func ACMEChallengeHandler(w http.ResponseWriter, r *http.Request) {
	addNonce(w)

	if r.Method != http.MethodPost {
		writeACMEError(w, acme.ErrMalformed, "method not allowed")
		return
	}

	challID := r.URL.Path[len("/acme/challenge/"):]
	if challID == "" {
		writeACMEError(w, acme.ErrMalformed, "missing challenge id")
		return
	}

	authz, chall, err := acme.FindChallengeByID(challID)
	if err != nil {
		writeACMEError(w, acme.ErrNotFound, "challenge not found")
		return
	}

	// 🔥 Nonce aus JWS validieren
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeACMEError(w, acme.ErrMalformed, "failed to read body")
		return
	}

	var rawJWS struct {
		Protected string `json:"protected"`
	}
	if err := json.Unmarshal(body, &rawJWS); err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid JWS")
		return
	}

	protectedBytes, err := base64.RawURLEncoding.DecodeString(rawJWS.Protected)
	if err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid protected header")
		return
	}

	var protectedHeader struct {
		Nonce string `json:"nonce"`
		KID   string `json:"kid"`
	}
	if err := json.Unmarshal(protectedBytes, &protectedHeader); err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid protected header")
		return
	}

	if protectedHeader.Nonce == "" || !acme.Nonces.Consume(protectedHeader.Nonce) {
		writeACMEError(w, acme.ErrBadNonce, "invalid or missing nonce")
		return
	}

	// 🔥 Challenge als "processing" markieren
	chall.Status = acme.ChallengeProcessing
	authz.Status = acme.AuthzPending

	// 🔥 HTTP-01 Validierung asynchron starten
	// 🔥 Challenge-Typ basierte Validierung
	go func() {
		var err error
		switch chall.Type {
		case "http-01":
			err = acme.ValidateHTTP01(authz, chall)
		case "dns-01":
			err = acme.ValidateDNS01(authz, chall)
		default:
			err = fmt.Errorf("unsupported challenge type: %s", chall.Type)
		}

		if err != nil {
			chall.Status = acme.ChallengeInvalid
			authz.Status = acme.AuthzInvalid
		} else {
			now := time.Now()
			chall.Status = acme.ChallengeValid
			chall.ValidatedAt = &now
			authz.Status = acme.AuthzValid
		}

		for i := range authz.Challenges {
			if authz.Challenges[i].ID == chall.ID {
				authz.Challenges[i] = *chall
				break
			}
		}
		acme.SaveAuthz(authz)
		acme.UpdateOrderStatus(authz.OrderID)
	}()

	// 🔥 Sofort antworten — Validierung läuft im Hintergrund
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Link", "<"+acmeBaseURL(r)+"/acme/authz/"+authz.ID+">;rel=\"up\"")
	w.WriteHeader(http.StatusOK)

	resp := map[string]interface{}{
		"type":   chall.Type,
		"status": acme.ChallengeProcessing,
		"token":  chall.Token,
		"url":    acmeBaseURL(r) + "/acme/challenge/" + chall.ID,
	}
	json.NewEncoder(w).Encode(resp)
}

func ACMEFinalizeHandler(w http.ResponseWriter, r *http.Request) {
	addNonce(w)

	if r.Method != http.MethodPost {
		writeACMEError(w, acme.ErrMalformed, "method not allowed")
		return
	}

	orderID := r.URL.Path[len("/acme/finalize/"):]
	if orderID == "" {
		writeACMEError(w, acme.ErrMalformed, "missing order id")
		return
	}

	order, err := acme.LoadOrder(orderID)
	if err != nil {
		writeACMEError(w, acme.ErrNotFound, "order not found")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeACMEError(w, acme.ErrMalformed, "failed to read body")
		return
	}

	var rawJWS struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(body, &rawJWS); err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid JWS structure")
		return
	}

	protectedBytes, err := base64.RawURLEncoding.DecodeString(rawJWS.Protected)
	if err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid protected header")
		return
	}

	var protectedHeader struct {
		Nonce string `json:"nonce"`
		KID   string `json:"kid"`
	}
	if err := json.Unmarshal(protectedBytes, &protectedHeader); err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid protected header")
		return
	}

	if protectedHeader.Nonce == "" || !acme.Nonces.Consume(protectedHeader.Nonce) {
		writeACMEError(w, acme.ErrBadNonce, "invalid or missing nonce")
		return
	}

	accountID := extractID(protectedHeader.KID, "/acme/account/")
	acc, err := acme.LoadAccount(accountID)
	if err != nil {
		writeACMEError(w, acme.ErrUnauthorized, "account not found")
		return
	}

	jwk, err := acme.LoadAccountJWK(acc)
	if err != nil {
		writeACMEError(w, acme.ErrUnauthorized, "failed to load account key")
		return
	}

	jws, err := jose.ParseSigned(string(body))
	if err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid JWS")
		return
	}

	payload, err := jws.Verify(jwk)
	if err != nil {
		writeACMEError(w, acme.ErrUnauthorized, "JWS verification failed")
		return
	}

	var finalizeReq struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payload, &finalizeReq); err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid finalize payload")
		return
	}

	csrDER, err := base64.RawURLEncoding.DecodeString(finalizeReq.CSR)
	if err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid CSR encoding")
		return
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid CSR: "+err.Error())
		return
	}

	if err := csr.CheckSignature(); err != nil {
		writeACMEError(w, acme.ErrMalformed, "CSR signature invalid")
		return
	}

	certPEM, err := acme.SignCSR(csr, order)
	if err != nil {
		http.Error(w, "failed to sign certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	certID, err := acme.SaveCertificate(certPEM)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	base := acmeBaseURL(r)
	order.Status = acme.OrderValid
	order.CertificateURL = base + "/acme/cert/" + certID
	acme.SaveOrder(order)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := map[string]interface{}{
		"status":      order.Status,
		"finalize":    order.FinalizeURL,
		"certificate": order.CertificateURL,
		"identifiers": order.Identifiers,
		"expires":     order.ExpiresAt,
	}
	json.NewEncoder(w).Encode(resp)
}

func ACMECertHandler(w http.ResponseWriter, r *http.Request) {
	addNonce(w)

	certID := r.URL.Path[len("/acme/cert/"):]
	if certID == "" {
		writeACMEError(w, acme.ErrMalformed, "missing cert id")
		return
	}

	certPEM, err := acme.LoadCertificate(certID)
	if err != nil {
		writeACMEError(w, acme.ErrNotFound, "certificate not found")
		return
	}

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	w.Write(certPEM)
}

func ACMEOrderHandler(w http.ResponseWriter, r *http.Request) {
	addNonce(w)

	orderID := r.URL.Path[len("/acme/order/"):]
	if orderID == "" {
		writeACMEError(w, acme.ErrMalformed, "missing order id")
		return
	}

	order, err := acme.LoadOrder(orderID)
	if err != nil {
		writeACMEError(w, acme.ErrNotFound, "order not found")
		return
	}

	base := acmeBaseURL(r)

	resp := map[string]interface{}{
		"status":         order.Status,
		"expires":        order.ExpiresAt,
		"identifiers":    order.Identifiers,
		"authorizations": order.Authorizations,
		"finalize":       order.FinalizeURL,
	}

	if order.CertificateURL != "" {
		resp["certificate"] = base + "/acme/cert/" + extractID(order.CertificateURL, "/acme/cert/")
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func ACMEAccountsListHandler(w http.ResponseWriter, r *http.Request) {
	accounts, err := acme.ListAccounts()
	if err != nil {
		http.Error(w, "failed to load accounts", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(accounts)
}

func ACMERevokeCertHandler(w http.ResponseWriter, r *http.Request) {
	addNonce(w)

	if r.Method != http.MethodPost {
		writeACMEError(w, acme.ErrMalformed, "method not allowed")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeACMEError(w, acme.ErrMalformed, "failed to read body")
		return
	}

	// 🔥 Protected Header dekodieren
	var rawJWS struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(body, &rawJWS); err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid JWS")
		return
	}

	protectedBytes, err := base64.RawURLEncoding.DecodeString(rawJWS.Protected)
	if err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid protected header")
		return
	}

	var protectedHeader struct {
		Nonce string `json:"nonce"`
		KID   string `json:"kid"`
	}
	if err := json.Unmarshal(protectedBytes, &protectedHeader); err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid protected header")
		return
	}

	if protectedHeader.Nonce == "" || !acme.Nonces.Consume(protectedHeader.Nonce) {
		writeACMEError(w, acme.ErrBadNonce, "invalid or missing nonce")
		return
	}

	// 🔥 Account laden + Signatur verifizieren
	accountID := extractID(protectedHeader.KID, "/acme/account/")
	acc, err := acme.LoadAccount(accountID)
	if err != nil {
		writeACMEError(w, acme.ErrUnauthorized, "account not found")
		return
	}

	jwk, err := acme.LoadAccountJWK(acc)
	if err != nil {
		writeACMEError(w, acme.ErrUnauthorized, "failed to load account key")
		return
	}

	jws, err := jose.ParseSigned(string(body))
	if err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid JWS")
		return
	}

	payload, err := jws.Verify(jwk)
	if err != nil {
		writeACMEError(w, acme.ErrUnauthorized, "JWS verification failed")
		return
	}

	// 🔥 Payload dekodieren
	var revokeReq struct {
		Certificate string `json:"certificate"` // Base64url DER
		Reason      int    `json:"reason"`
	}
	if err := json.Unmarshal(payload, &revokeReq); err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid revoke payload")
		return
	}

	// 🔥 Zertifikat dekodieren + Serial lesen
	certDER, err := base64.RawURLEncoding.DecodeString(revokeReq.Certificate)
	if err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid certificate encoding")
		return
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		writeACMEError(w, acme.ErrMalformed, "invalid certificate")
		return
	}

	serial := cert.SerialNumber.Text(16)

	// 🔥 ACME Reason Code → Laravel Reason String
	reasonMap := map[int]string{
		0: "unspecified",
		1: "key_compromise",
		5: "cessation_of_operation",
		4: "superseded",
	}
	reason := reasonMap[revokeReq.Reason]
	if reason == "" {
		reason = "unspecified"
	}

	// 🔥 Laravel aufrufen
	if err := acme.RevokeVieLaravel(serial, reason); err != nil {
		writeACMEError(w, acme.ErrMalformed, "revocation failed: "+err.Error())
		return
	}

	w.WriteHeader(http.StatusOK)
}

func ACMEDeactivateAccountHandler(w http.ResponseWriter, r *http.Request) {
	addNonce(w)

	id := r.URL.Path[len("/acme/account/deactivate/"):]
	if id == "" {
		writeACMEError(w, acme.ErrMalformed, "missing account id")
		return
	}

	acc, err := acme.LoadAccount(id)
	if err != nil {
		writeACMEError(w, acme.ErrNotFound, "account not found")
		return
	}

	acc.Status = acme.AccountDeactivated

	if err := acme.SaveAccount(acc); err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": string(acme.AccountDeactivated),
	})
}
