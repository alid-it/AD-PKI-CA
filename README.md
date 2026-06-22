# AD-PKI CA

**English** · [Deutsch](README.de.md)

> A lightweight Certification Authority service written in Go and designed as the cryptographic core of a PKI deployment.

[![Go](https://img.shields.io/badge/Go-1.26.1-00ADD8)](https://go.dev/)
[![ACME](https://img.shields.io/badge/ACME-RFC%208555-success)](https://datatracker.ietf.org/doc/html/rfc8555)
[![RFC 3161](https://img.shields.io/badge/Timestamp-RFC%203161-orange)](https://datatracker.ietf.org/doc/html/rfc3161)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)

AD-PKI CA handles X.509 certificate signing, ACME issuance, RFC 3161 timestamping, OCSP, and CRL generation.

It is one component of the **AD-PKI** stack and is designed to run alongside an AD-PKI Backend for its management API, certificate database, policies, and settings, and an AD-PKI Frontend for its web UI. It can also operate standalone for ACME issuance, OCSP, and CRL distribution.

## Features

- **Certificate issuance** — TLS server, client-auth, and code-signing certificates with configurable key type, key size, and validity period
- **ACME v2 server** — RFC 8555 account, order, authorization, and finalize flows with HTTP-01 and DNS-01 challenge validation, including wildcard domain support through DNS-01
- **RFC 3161 Timestamp Authority** — Dedicated TSA certificate generation and signed timestamp responses
- **OCSP responder** — Signed revocation status responses with response caching
- **CRL generation** — Periodic CRL refresh for each intermediate CA
- **Root and intermediate CA management** — Import and chain validation, including basic constraints, issuer matching, and signature verification
- **Token-based authentication** — Protection for administrative endpoints

## Architecture

AD-PKI CA is intentionally stateless with respect to policy and does not own a database. An external backend provides certificate revocation lists, audit trails, and issuance settings—such as validity periods, CRL and OCSP URLs, and DNS servers—through a small internal HTTP API.

The CA service persists only cryptographic material and ACME protocol state on the local filesystem under a configurable base directory.

Public protocol endpoints for ACME, OCSP, and RFC 3161 timestamping are served directly by the service. Administrative endpoints for signing, imports, and system management are protected by a shared-secret token header.

## Getting Started

### Requirements

- Go 1.26+
- OpenSSL CLI, used internally to generate the RFC 3161 TSA certificate

### Build

```bash
go build -o ca-server ./cmd/ca-server
```

### Configure

```bash
cp .env.example .env
```

See [docs/CA.md](docs/CA.md) for the complete environment variable reference, filesystem layout, and API documentation.

### Run

```bash
./ca-server
```

## Documentation

[docs/CA.md](docs/CA.md) provides the complete API reference, ACME protocol flow, OCSP, CRL, and TSA internals, filesystem layout, known limitations, and deployment guidance.

## Security

This service holds private key material for one or more Certification Authorities and must be operated as a security-critical component.

- Always configure an authentication token in production. Without one, administrative endpoints are unauthenticated.
- Expose only the endpoints that must be public, such as ACME, OCSP, and timestamping. Keep administrative endpoints internal.
- Protect the filesystem location containing private keys with appropriate permissions.

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPLv3).