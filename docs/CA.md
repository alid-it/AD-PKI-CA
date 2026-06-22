# AD-PKI CA Service — Technical Documentation

This document describes the internals of the AD-PKI CA Go service: its
architecture, filesystem layout, API surface, protocol implementations
(ACME, OCSP, CRL, RFC 3161), configuration, known limitations, and
deployment guidance.

It assumes familiarity with X.509, ACME (RFC 8555), OCSP (RFC 6960), and
RFC 3161 timestamping at a basic level.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Project Structure](#project-structure)
3. [Filesystem Layout (PKI_BASE_DIR)](#filesystem-layout-pki_base_dir)
4. [Configuration](#configuration)
5. [Authentication Model](#authentication-model)
6. [API Reference](#api-reference)
7. [Certificate Signing Internals](#certificate-signing-internals)
8. [ACME Protocol Implementation](#acme-protocol-implementation)
9. [CRL Internals](#crl-internals)
10. [OCSP Internals](#ocsp-internals)
11. [RFC 3161 Timestamp Authority](#rfc-3161-timestamp-authority)
12. [Background Workers](#background-workers)
13. [Known Limitations / TODOs](#known-limitations--todos)
14. [Deployment Guidance](#deployment-guidance)
15. [Local Development Setup](#local-development-setup)

---

## Architecture Overview

AD-PKI CA is a stateless-by-design crypto service: it does not maintain
its own database of issued/revoked certificates, issuance policy, or
audit history. Instead:

- **Outbound**, it queries a backend service over HTTP for:
  - issuance settings (CRL/OCSP URLs, active intermediate, validity days,
    DNS servers for DNS-01 validation)
  - the current revocation list (for CRL generation and OCSP lookups)
  - it also notifies the backend after issuing/revoking certificates
    (fire-and-forget) so the backend's certificate database stays in sync
- **Inbound**, it serves:
  - public protocol endpoints (ACME, OCSP, RFC 3161) that external
    clients (certbot, acme.sh, TLS clients) talk to directly
  - administrative endpoints (signing, import, system management) that
    only the backend (or an authorized operator) should call

All private key material and protocol state (ACME accounts/orders/
authorizations, issued certificates) is persisted to the local
filesystem under a single configurable root: `PKI_BASE_DIR`.

```
                 ┌─────────────────────┐
  ACME clients ─▶│                     │
  TLS clients  ─▶│   AD-PKI CA (Go)    │◀── X-CA-Token ── Backend (admin ops)
  (OCSP/TSA)   ─▶│                     │
                 └────────┬────────────┘
                          │ HTTP (settings / revoked list / notify)
                          ▼
                  AD-PKI Backend (policy, DB, audit)
```

## Project Structure

```
cmd/ca-server/main.go        Entry point: route registration, worker startup

internal/
  acme/                       ACME protocol logic (RFC 8555)
    acme_types.go               Account/Order/Authorization/Challenge types, error catalog
    account.go                  Account creation, key thumbprint, lookup-by-key mapping
    jws.go                       Standalone JWS parsing/verification helper
    nonce.go                     In-memory replay-nonce manager (1h TTL, single-use)
    order.go                     Order/authorization/challenge creation, status aggregation
    challenge.go                 HTTP-01 and DNS-01 challenge validation
    sign.go                      CSR signing within the ACME finalize flow, backend notify
    revoke.go                    ACME-triggered revocation via backend API
    storage.go                   JSON file persistence for accounts/orders/authorizations

  api/                        HTTP handlers (one file per functional area)
    auth_middleware.go          X-CA-Token enforcement
    acme_handler.go              All ACME endpoints (directory, nonce, account, order, ...)
    sign_handler.go              CSR upload signing + server-side key/CSR generation
    ca_handler.go                Intermediate validation endpoint
    crl_handler.go                CRL file serving
    ocsp_handler.go / ocsp_cache.go   OCSP responder + response cache
    import_handler.go / root_handler.go  Root/intermediate import
    system_handler.go / system_ntp_handler.go  System info, NTP configuration
    timestamp_handler.go / tsa_generate_handler.go  RFC 3161 TSA

  ca/                         Cryptographic core logic
    ca.go                        CA struct (certificate + key)
    sign.go                       SignCSR: template construction, extensions, signing
    crl.go                        CRL generation + revoked-certificate fetch
    ocsp.go                       Issuer matching for OCSP (name/key hash)
    tsa.go                        TSA certificate generation via OpenSSL subprocess
    intermediate.go                Default intermediate lookup from backend
    loader.go / loader_pem.go      Load CA material from disk/PEM
    chain.go                       Fullchain assembly (leaf + intermediate + root)
    csr.go / csr_builder.go        CSR parsing/creation
    key.go / key_validation.go     Key generation (RSA/ECDSA), key-certificate matching
    validate.go                    Intermediate-against-root chain validation
    settings.go                    Fetch issuance settings from backend
    ca.ParseCertificate.go         Certificate metadata extraction

  crypto/key.go                Private key → PEM encoding
  storage/                     Filesystem persistence (certificates, intermediates, root, TSA, ACME dirs)
  worker/                      Background jobs
    crl-worker.go                 Periodic CRL refresh (package name: crl)
    acme_cleanup_worker.go        Daily cleanup of expired ACME state
  config/path.go               PKI_BASE_DIR resolution
```

> Note: `internal/worker` is declared as `package crl` internally; this is
> a naming inconsistency (package name differs from directory name) but
> has no functional impact since both files live in the same package and
> are imported via their directory path.

## Filesystem Layout (PKI_BASE_DIR)

All persistent state lives under a single base directory (default
`/var/lib/adpki`, overridable via `PKI_BASE_DIR`):

```
PKI_BASE_DIR/
├── root/
│   └── root.crt
├── intermediates/
│   └── {intermediate-id}/
│       ├── intermediate.crt
│       └── private/
│           └── intermediate.key
├── issued/
│   └── {common-name}-{serial-hex}/
│       ├── certificate.crt
│       ├── request.csr
│       ├── private.key        (only present when the CA generated the key)
│       └── fullchain.pem      (only present when a chain was requested)
├── crl_{intermediate-id}.pem
├── tsa/
│   ├── tsa.crt
│   └── private/
│       └── tsa.key
└── acme/
    ├── accounts/
    │   ├── {account-id}.json
    │   └── by-key/{thumbprint}   (key-thumbprint → account-id mapping)
    ├── orders/{order-id}.json
    ├── authz/{authz-id}.json
    ├── challenges/{challenge-id}   (challenge-id → authz-id mapping)
    └── certs/{cert-id}.pem
```

Directory permissions: intermediate directories are created `0750`,
private key subdirectories `0700`, private key files `0600`. Other
material (certificates, CRLs, CSRs) is world-readable (`0644`)/`0755`,
which is appropriate since it is public by nature.

## Configuration

Environment variables (loaded via `godotenv` from `.env`, falling back to
the process environment):

| Variable | Purpose | Default if unset |
|---|---|---|
| `PKI_BASE_DIR` | Root directory for all PKI state | `/var/lib/adpki` |
| `BACKEND_URL` | Base URL of the backend service used for settings, revocation lookups, and issuance notifications | `http://127.0.0.1:8000` (used in `internal/acme/sign.go`); `http://127.0.0.1` (used in `internal/api/ocsp_handler.go` and `internal/worker/crl-worker.go`) |
| `CA_TOKEN` | Shared secret required in the `X-CA-Token` header for administrative endpoints | unset → administrative endpoints are **unauthenticated** |

> ⚠️ The `BACKEND_URL` fallback default differs between modules
> (`:8000` vs. no port). This is harmless as long as `BACKEND_URL` is
> always explicitly set, but should not be relied upon as a default in
> production. See [Known Limitations](#known-limitations--todos).

## Authentication Model

`internal/api/auth_middleware.go` implements a single shared-secret
check: if `CA_TOKEN` is set, every request to a wrapped handler must
include a matching `X-CA-Token` header, or it is rejected with `401`.

**Endpoints wrapped with `AuthMiddleware`** (administrative — intended
to be called only by a trusted backend or operator):

`/sign`, `/sign-from-data`, `/ca/import-root`, `/ca/validate-intermediate`,
`/ca/import-intermediate`, `/crl/`, `/ocsp`, `/ocsp/clear-cache`,
`/system/info`, `/system/ntp`, `/acme/accounts`,
`/acme/account/deactivate/`, `/tsa/generate`, `/tsa/status`.

**Public endpoints** (no token required, by protocol design):

`/timestamp`, `/acme/directory`, `/acme/new-nonce`, `/acme/new-account`,
`/acme/new-order`, `/acme/authz/`, `/acme/challenge/`,
`/acme/finalize/`, `/acme/cert/`, `/acme/order/`, `/acme/revoke-cert`.

Note that `/crl/` and `/ocsp` are also wrapped with `AuthMiddleware`,
which is unusual since CRL/OCSP are normally public-facing protocols. In
the AD-PKI deployment model, the backend exposes its own public proxy
endpoints for CRL/OCSP and forwards to this service internally with the
token attached — this service itself is not meant to be reachable
directly by TLS clients for those two paths. If you deploy this service
standalone and need public CRL/OCSP, put a reverse proxy in front that
injects the token, or adjust the routing in `cmd/ca-server/main.go`.

## API Reference

### Administrative

| Method & Path | Description |
|---|---|
| `POST /sign` | Multipart upload: `csr` (file), `intermediate`, `crl_url`, `ocsp_url`, `type` (`tls`/`client`/`codesign`, default `tls`), `validity_days`. Signs an externally-generated CSR. |
| `POST /sign-from-data` | JSON body describing subject fields, SANs, key type/size/curve, intermediate, CRL/OCSP URLs, validity. CA generates the key pair and CSR server-side, then signs it. Returns the private key in the response. |
| `POST /ca/import-root` | Multipart `root` file. Stores the root CA certificate. |
| `POST /ca/validate-intermediate` | Multipart `root` + `intermediate` files. Validates chain (issuer match, basic constraints, signature) without storing anything. |
| `POST /ca/import-intermediate` | Multipart `name`, `root`, `intermediate`, `key`. Validates chain + key match, then persists the intermediate. |
| `GET /crl/{id}.pem` | Returns the most recently generated CRL for intermediate `{id}`. |
| `POST /ocsp` | DER-encoded OCSP request body. Returns a signed OCSP response. |
| `POST /ocsp/clear-cache` | Clears the in-memory OCSP response cache. |
| `GET /system/info` | Go runtime version + filesystem usage of `PKI_BASE_DIR`. |
| `POST /system/ntp` | JSON `{"ntp_server": "..."}`. Invokes `sudo /usr/local/sbin/adpki-set-ntp <server>` on the host (15s timeout). |
| `GET /acme/accounts` | Lists all known ACME accounts (admin view, no pagination). |
| `POST /acme/account/deactivate/{id}` | Marks an ACME account as `deactivated`. |
| `POST /tsa/generate` | JSON `{"intermediate_id": "..."}`. Generates a new TSA certificate signed by the given intermediate. |
| `GET /tsa/status` | Returns whether a TSA certificate exists, plus its metadata if so. |

### Public — ACME (RFC 8555)

| Method & Path | Description |
|---|---|
| `GET /acme/directory` | Directory document advertising endpoint URLs. |
| `HEAD`/`GET /acme/new-nonce` | Issues a fresh replay nonce via `Replay-Nonce` header. |
| `POST /acme/new-account` | Creates or returns an existing account for a given JWK. |
| `POST /acme/new-order` | Creates an order + per-identifier authorizations/challenges. |
| `GET /acme/authz/{id}` (POST-as-GET in practice) | Returns authorization status and challenges. |
| `POST /acme/challenge/{id}` | Triggers challenge validation (runs asynchronously). |
| `POST /acme/finalize/{id}` | Submits the final CSR; on success, signs the certificate. |
| `GET /acme/cert/{id}` | Downloads the issued certificate chain (PEM). |
| `GET /acme/order/{id}` | Returns current order status. |
| `POST /acme/revoke-cert` | ACME-standard revocation request. |

### Public — Other Protocols

| Method & Path | Description |
|---|---|
| `POST /timestamp` | RFC 3161 timestamp request/response (DER-encoded). |

## Certificate Signing Internals

`internal/ca/sign.go` (`SignCSR`) is the single code path used by both
the direct `/sign*` admin endpoints and the ACME finalize flow
(`internal/acme/sign.go`).

- **Serial number**: random, up to 62 bits (`crypto/rand`), hex-encoded.
- **Validity**: caller-supplied `validityDays`; falls back to 365 days at
  the `ca.SignCSR` level, and to 90 days specifically in the ACME flow
  if the backend does not provide a value.
- **KeyUsage / ExtKeyUsage by `certType`**:
  - `tls` → `DigitalSignature | KeyEncipherment`, `ServerAuth`
  - `client` → `DigitalSignature`, `ClientAuth`
  - `codesign` → `DigitalSignature`, `CodeSigning`
  - anything else → rejected with an error
- **SAN (DNSNames/IPAddresses)** is only copied onto the certificate
  template for `certType == "tls"`.
- **CRLDistributionPoints** and **OCSPServer** are set from caller-
  supplied URLs (no validation of URL format is performed).
- The certificate is signed using the intermediate CA's key loaded fresh
  from disk on every call (no in-memory caching of CA key material
  across requests).

Key generation (`internal/ca/key.go`) supports RSA (any size accepted by
`crypto/rsa`, though callers constrain to 2048/3072/4096) and ECDSA on
P256/P384/P521 (default P256).

`internal/ca/key_validation.go` (`ValidateKeyMatchesCert`) — used during
intermediate import — only implements the RSA comparison path; ECDSA
keys fall through to an "unsupported key type" error. If you need to
import an ECDSA intermediate, this check will currently reject it.

## ACME Protocol Implementation

Implements the core RFC 8555 issuance flow: `new-account` → `new-order`
→ `authz`/`challenge` → `finalize` → `cert`, plus `revoke-cert`.

### Accounts

- Identified by a random 12-byte ID (base64url).
- Looked up by the SHA-256 JWK thumbprint (RFC 7638) via a flat mapping
  file under `acme/accounts/by-key/{thumbprint}`.
- `new-account` returns the existing account (200 + Location) if the key
  is already registered, honors `onlyReturnExisting`, otherwise creates a
  new account (201).

### Orders & Authorizations

- An order is created with one authorization per requested identifier.
- Each authorization always offers a `dns-01` challenge; `http-01` is
  additionally offered **unless** the identifier is a wildcard
  (`*.example.com`), since RFC 8555 disallows HTTP-01 for wildcards.
- `UpdateOrderStatus` recomputes order status by scanning all of its
  authorizations: `invalid` if any authorization is invalid, `ready` if
  all are valid, otherwise stays `pending`.

### Challenge Validation

- **HTTP-01** (`internal/acme/challenge.go`): plain HTTP GET to
  `http://{identifier}/.well-known/acme-challenge/{token}`, compares the
  response body against `token.<jwk-thumbprint>`. No retries, 10s
  timeout, no HTTPS fallback.
- **DNS-01**: queries `_acme-challenge.{identifier}` (wildcard prefix
  stripped) for TXT records using `github.com/miekg/dns`, against a
  recursive resolver. Resolver selection: the backend's configured DNS
  servers (`fetchACMESettings().DNSServers`), first entry used; if the
  backend call fails or returns none, falls back to `8.8.8.8`. Expected
  value is base64url(SHA-256(`token.<jwk-thumbprint>`)).
- Validation runs in a **goroutine** triggered by `POST
  /acme/challenge/{id}`; the HTTP response returns immediately with
  status `processing`. Clients are expected to poll the authorization
  URL.
- Debug logging for DNS-01 is written to stdout unconditionally
  (`fmt.Printf` with 🔥 markers) — verbose, intended for troubleshooting,
  not gated behind a log level.

### JWS / Nonce Handling

- Nonces: in-memory map, single-use, 1-hour TTL, with opportunistic
  cleanup goroutine triggered on every `Generate()` call. Not shared
  across processes — see [Known Limitations](#known-limitations--todos).
- JWS verification is implemented twice: a reusable helper in
  `internal/acme/jws.go` (`ParseAndVerifyJWS`, currently unused by the
  HTTP handlers) and inline per-handler parsing in
  `internal/api/acme_handler.go` (manually decoding the protected header
  to extract `nonce`/`url`/`kid`/`jwk` before calling `go-jose` for
  signature verification). Functionally consistent, but the duplication
  is a maintenance risk if one path is updated and the other is not.

### Certificate Issuance & Backend Notification

- On finalize, `internal/acme/sign.go` resolves issuance settings from
  the backend (`/api/internal/acme-settings`); if that fails or returns
  no intermediate, falls back to `activeIntermediateID()` (reads an
  `intermediates/active` symlink, or else the lexicographically-last
  `int-*` directory).
- After signing, the certificate is stored under `issued/` (same
  `StoreCertificate` path used by the admin signing flow) and the
  backend is notified asynchronously (`go notifyLaravel(...)`) — this is
  fire-and-forget; failures are logged to stdout only and do not affect
  the ACME response to the client.
- The certificate returned to the ACME client is the full chain
  (leaf + intermediate + root), assembled by `ca.BuildChain`.

### Revocation

- `POST /acme/revoke-cert` parses the certificate from the request,
  extracts the serial, maps the ACME numeric reason code to a string
  (`unspecified`, `key_compromise`, `cessation_of_operation`,
  `superseded`; anything else maps to `unspecified`), and forwards the
  revocation to the backend (`/api/internal/acme/revoke`). The CA service
  itself does not maintain a revocation list — see
  [CRL Internals](#crl-internals) and [OCSP Internals](#ocsp-internals).

### Cleanup

A daily worker (02:00 local time) deletes ACME `orders/`, `authz/`, and
`challenges/` entries whose file modification time is older than 30
days. Accounts and issued certificates (`acme/certs/`) are **not**
cleaned up by this job.

### Gaps vs. the Full RFC 8555 Surface

- `keyChange` is advertised in the directory document but has no
  handler — calling it will 404.
- No `externalAccountRequired` support (always advertised as `false`).
- No account-key rollover, no order/authorization deactivation endpoint
  beyond account deactivation.

## CRL Internals

- `internal/worker/crl-worker.go` runs every 5 minutes: loads all known
  intermediates from disk, and for each one fetches its revoked-
  certificate list from the backend
  (`{BACKEND_URL}/api/internal/crl/revoked?intermediate={id}`), then
  generates a fresh CRL signed by that intermediate
  (`internal/ca/crl.go`).
- CRL validity window is fixed: `thisUpdate = now`, `nextUpdate = now +
  24h`, regardless of the worker's 5-minute refresh cadence.
- Generated CRLs are written to `PKI_BASE_DIR/crl_{id}.pem` (PEM-encoded
  `X509 CRL`), and served as-is by `GET /crl/{id}.pem` — the handler does
  not regenerate on demand, it only serves the last cached file. If the
  worker has never successfully run for an intermediate, the file does
  not exist and requests return `404`.
- Revoked-certificate timestamps from the backend are parsed with the
  fixed format `2006-01-02 15:04:05` (no timezone) — ensure the backend
  emits revocation timestamps in this exact format.

## OCSP Internals

- `POST /ocsp` accepts a DER-encoded OCSP request, parses the serial and
  issuer name/key hash, and matches it against all loaded intermediates
  via `internal/ca/ocsp.go` (`FindIssuer`) — SHA-1 over `RawSubject` and
  the raw `SubjectPublicKey` bits, per RFC 6960 hash conventions.
- If no matching issuer is found among loaded intermediates, the
  response is `404` (not a signed "unknown" OCSP response).
- Revocation status is queried live per-request from the backend
  (`{BACKEND_URL}/api/certificates/revoked?intermediate={id}`) — there is
  no local revocation cache independent of the response cache below; a
  backend outage means OCSP requests fail open to `Good` status (since a
  fetch error is silently ignored and `status` stays at its default
  `ocsp.Good`). This is worth being aware of operationally — see
  [Known Limitations](#known-limitations--todos).
- Successful responses are cached in-memory, keyed by
  `{issuerID}:{serialHex}`, until the response's `nextUpdate` (1 hour
  after signing). `POST /ocsp/clear-cache` clears the entire cache (not
  scoped to a single certificate).

## RFC 3161 Timestamp Authority

- `POST /tsa/generate` (admin) creates a fresh TSA key/certificate pair
  via the `openssl` CLI (not Go's `crypto/x509`), because the critical
  `extendedKeyUsage = timeStamping` extension marked `critical` is needed
  and is easier to express via an OpenSSL extension file than via Go's
  x509 template API. The certificate is signed by the specified
  intermediate (`-CA`/`-CAkey`), valid for 3650 days, RSA-2048/SHA-256.
  All intermediate files are created in a temp directory that is removed
  afterward (`defer os.RemoveAll`).
- The resulting cert/key pair is stored under `PKI_BASE_DIR/tsa/` and
  **replaces** any previous TSA certificate (single active TSA identity
  per deployment — there is no rotation/versioning).
- `GET /tsa/status` reports existence + subject/serial/validity if a TSA
  certificate is present.
- `POST /timestamp` (public) parses an RFC 3161 `TimeStampReq`, builds a
  `Timestamp` response using `digitorus/timestamp` with the current time
  (UTC), embeds the TSA certificate in the response
  (`AddTSACertificate: true`), and signs it with the TSA private key.
  Uses a placeholder private policy OID
  (`1.3.6.1.4.1.99999.1`) — replace this with a real, registered OID
  before treating timestamps as legally significant in any jurisdiction
  that requires it.

## Background Workers

| Worker | Interval | Purpose |
|---|---|---|
| CRL refresh | every 5 minutes | Regenerate CRL for every loaded intermediate |
| ACME cleanup | daily at 02:00 local time | Delete `acme/{orders,authz,challenges}` entries older than 30 days |

Both are started as goroutines in `main()` and run for the lifetime of
the process; there is no external scheduler dependency (no cron). A
process restart simply re-triggers the next scheduled run from scratch.

## Known Limitations / TODOs

- **`ValidateKeyMatchesCert` only supports RSA.** Importing an ECDSA
  intermediate via `/ca/import-intermediate` will fail this check even
  if the key and certificate genuinely match.
- **`/acme/key-change` is advertised but not implemented** (404 if
  called).
- **No locking around concurrent ACME authorization updates.** Challenge
  validation runs in an unsynchronized goroutine that reads-modifies-
  writes the authorization JSON file; concurrent challenge validations
  for the same authorization (e.g., a client retrying) could race.
- **In-memory state is process-local and not shared across instances**:
  ACME nonces (`internal/acme/nonce.go`) and the OCSP response cache
  (`internal/api/ocsp_cache.go`) live in process memory. Running multiple
  instances behind a load balancer without sticky sessions will cause
  spurious `badNonce` errors and inconsistent OCSP caching.
- **OCSP fails open on backend errors.** If the revocation-status fetch
  to the backend fails, the response defaults to `Good` rather than
  erroring out or marking the status unknown.
- **Inconsistent `BACKEND_URL` fallback defaults** between
  `internal/acme/sign.go` (`http://127.0.0.1:8000`) and
  `internal/api/ocsp_handler.go` / `internal/worker/crl-worker.go`
  (`http://127.0.0.1`). Always set `BACKEND_URL` explicitly to avoid
  relying on either default.
- **No automated tests** (`*_test.go`) exist in the repository.
- **CRL/OCSP endpoints require the admin token**, which is atypical for
  these protocols; if you need them to be directly publicly reachable,
  you will need to either front them with a proxy that injects the
  token, or adjust routing/auth in `cmd/ca-server/main.go`.
- **TSA timestamp policy OID is a placeholder** private-enterprise OID,
  not a registered one.
- **DNS-01 debug logging is unconditional** (stdout, not behind a log
  level) — noisy in production.

## Deployment Guidance

- **Run behind a reverse proxy / firewall boundary.** Expose only the
  endpoints that genuinely need to be public (ACME `/acme/*` excluding
  admin-only paths, `/timestamp`). Keep `/sign*`, `/ca/*`, `/system/*`,
  `/tsa/generate`, `/tsa/status`, `/acme/accounts`,
  `/acme/account/deactivate/*` reachable only from the trusted backend
  network, even though they are additionally token-protected.
- **Always set `CA_TOKEN` in production.** Leaving it unset disables all
  authentication on administrative endpoints.
- **Protect `PKI_BASE_DIR`.** Private key directories are created with
  restrictive permissions (`0700`/`0600`), but the parent directory tree
  and the user/group the process runs as must also be locked down at the
  OS level. Do not run the service as `root` longer than strictly
  necessary for any privileged subprocess it invokes.
- **`POST /system/ntp` invokes `sudo` to run a host-level script**
  (`/usr/local/sbin/adpki-set-ntp`). This requires a corresponding
  `sudoers` entry granting the service's runtime user permission to run
  exactly that script without a password. Scope the sudoers rule
  narrowly (exact path, no wildcard arguments beyond what the script
  itself validates).
- **`openssl` CLI must be installed** on the host — it is a runtime
  dependency for TSA certificate generation, not just a build-time tool.
- **Single-instance deployment is recommended** given the in-memory
  nonce/OCSP-cache limitations described above. If horizontal scaling is
  required, the nonce and OCSP cache mechanisms would need to move to a
  shared store first.
- **Back up `PKI_BASE_DIR` regularly**, especially `root/`,
  `intermediates/*/private/`, and `tsa/private/` — loss of this directory
  means loss of all CA key material.

## Local Development Setup

1. Copy `.env.example` to `.env` and adjust:
   - `PKI_BASE_DIR` to a local writable directory (e.g. a path under your
     home directory) instead of `/var/lib/adpki`.
   - `BACKEND_URL` pointing at a locally running backend instance, or a
     stub if you only want to exercise the parts of the API that don't
     depend on it.
   - Leave `CA_TOKEN` empty for local testing to skip auth, or set it and
     pass `X-CA-Token` on every admin request.
2. Ensure the `openssl` CLI is available on your `PATH` (required for
   `/tsa/generate`).
3. Build and run:
   ```bash
   go build -o ca-server ./cmd/ca-server
   ./ca-server
   ```
4. Bootstrap a root + intermediate CA for testing (outside the scope of
   this service — generate them with `openssl` or another tool, then
   import via `POST /ca/import-root` and `POST /ca/import-intermediate`).
5. To exercise the ACME flow end-to-end, point a real ACME client (e.g.
   `certbot --server http://<host>:8080/acme/directory` or `acme.sh`) at
   the locally running service. HTTP-01 requires the challenge token to
   be servable at `http://<identifier>/.well-known/acme-challenge/...`,
   so HTTP-01 testing typically requires a real, resolvable domain or a
   manually staged challenge response; DNS-01 testing requires a DNS
   zone you can add TXT records to (and a backend providing the
   resolver(s) to query, or rely on the `8.8.8.8` fallback if your TXT
   record is publicly resolvable).
