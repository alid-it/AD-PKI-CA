package main

import (
	"log"
	"net/http"

	"ad-pki-ca/internal/api"
	crl "ad-pki-ca/internal/worker"

	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("Keine .env Datei gefunden — nutze Systemumgebung")
	}

	// =====================================================
	// 🔥 ROUTES
	// =====================================================

	http.HandleFunc("/sign", api.AuthMiddleware(api.SignHandler))
	http.HandleFunc("/ca/import-root", api.AuthMiddleware(api.ImportRootHandler))
	http.HandleFunc("/ca/validate-intermediate", api.AuthMiddleware(api.ValidateIntermediateHandler))
	http.HandleFunc("/ca/import-intermediate", api.AuthMiddleware(api.ImportIntermediateHandler))
	http.HandleFunc("/crl/", api.AuthMiddleware(api.CRLHandler))
	http.HandleFunc("/ocsp", api.AuthMiddleware(api.OCSPHandler))
	http.HandleFunc("/ocsp/clear-cache", api.AuthMiddleware(api.ClearOCSPCacheHandler))
	http.HandleFunc("/sign-from-data", api.AuthMiddleware(api.SignFromDataHandler))
	http.HandleFunc("/system/info", api.AuthMiddleware(api.SystemInfoHandler))
	http.HandleFunc("/system/ntp", api.AuthMiddleware(api.SetNTPHandler))
	http.HandleFunc("/acme/accounts", api.AuthMiddleware(api.ACMEAccountsListHandler))
	http.HandleFunc("/acme/account/deactivate/", api.AuthMiddleware(api.ACMEDeactivateAccountHandler))

	// 🔥 TSA — Timestamp Authority
	http.HandleFunc("/tsa/generate", api.AuthMiddleware(api.TSAGenerateHandler))
	http.HandleFunc("/tsa/status", api.AuthMiddleware(api.TSAStatusHandler))
	http.HandleFunc("/timestamp", api.TimestampHandler) // 🔥 PUBLIC — wie /ocsp

	// ACME — Public (kein Auth Token nötig)
	http.HandleFunc("/acme/directory", api.ACMEDirectoryHandler)
	http.HandleFunc("/acme/new-nonce", api.ACMENewNonceHandler)
	http.HandleFunc("/acme/new-account", api.ACMENewAccountHandler)
	http.HandleFunc("/acme/new-order", api.ACMENewOrderHandler)
	http.HandleFunc("/acme/authz/", api.ACMEAuthzHandler)
	http.HandleFunc("/acme/challenge/", api.ACMEChallengeHandler)
	http.HandleFunc("/acme/finalize/", api.ACMEFinalizeHandler)
	http.HandleFunc("/acme/cert/", api.ACMECertHandler)
	http.HandleFunc("/acme/order/", api.ACMEOrderHandler)
	http.HandleFunc("/acme/revoke-cert", api.ACMERevokeCertHandler)

	crl.StartCRLWorker()
	crl.StartACMECleanupWorker()

	log.Println("CA Service running on 127.0.0.1:8080")
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", nil))
}
