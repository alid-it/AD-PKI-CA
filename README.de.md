# AD-PKI CA

[English](README.md) · **Deutsch**

> Ein schlanker, in Go geschriebener Zertifizierungsstellen-Dienst, konzipiert als kryptografischer Kern einer PKI-Umgebung.

[![Go](https://img.shields.io/badge/Go-1.26.1-00ADD8)](https://go.dev/)
[![ACME](https://img.shields.io/badge/ACME-RFC%208555-success)](https://datatracker.ietf.org/doc/html/rfc8555)
[![RFC 3161](https://img.shields.io/badge/Timestamp-RFC%203161-orange)](https://datatracker.ietf.org/doc/html/rfc3161)
[![Lizenz: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)

AD-PKI CA übernimmt das Signieren von X.509-Zertifikaten, die Ausstellung über ACME, RFC-3161-Zeitstempel, OCSP und die Erstellung von Zertifikatsperrlisten (CRLs).

Der Dienst ist eine Komponente des **AD-PKI**-Stacks. Er ist für den gemeinsamen Betrieb mit einem AD-PKI Backend für Management-API, Zertifikatsdatenbank, Richtlinien und Einstellungen sowie einem AD-PKI Frontend für die Weboberfläche ausgelegt. Für die Ausstellung über ACME sowie die Bereitstellung von OCSP und CRLs kann er auch eigenständig betrieben werden.

## Funktionen

- **Zertifikatsausstellung** — TLS-Server-, Client-Authentifizierungs- und Code-Signing-Zertifikate mit konfigurierbarem Schlüsseltyp, konfigurierbarer Schlüssellänge und Gültigkeitsdauer
- **ACME-v2-Server** — Konto-, Auftrags-, Autorisierungs- und Abschlussabläufe nach RFC 8555 mit HTTP-01- und DNS-01-Challenge-Validierung, einschließlich Unterstützung für Wildcard-Domains über DNS-01
- **RFC-3161-Zeitstempelstelle** — Erzeugung eines dedizierten TSA-Zertifikats und Ausgabe signierter Zeitstempelantworten
- **OCSP-Responder** — Signierte Antworten zum Sperrstatus mit Antwort-Cache
- **CRL-Erstellung** — Regelmäßige Aktualisierung der Zertifikatsperrliste für jede Zwischenzertifizierungsstelle
- **Verwaltung von Root- und Intermediate-CAs** — Import und Validierung der Zertifikatskette, einschließlich Basic Constraints, Übereinstimmung des Ausstellers und Signaturprüfung
- **Tokenbasierte Authentifizierung** — Schutz administrativer Endpunkte

## Architektur

AD-PKI CA ist in Bezug auf Richtlinien bewusst zustandslos und besitzt keine eigene Datenbank. Ein externes Backend stellt Zertifikatsperrlisten, Audit-Protokolle und Ausstellungseinstellungen—darunter Gültigkeitszeiträume, CRL- und OCSP-URLs sowie DNS-Server—über eine kleine interne HTTP-API bereit.

Der CA-Dienst speichert ausschließlich kryptografisches Material und den ACME-Protokollzustand im lokalen Dateisystem unterhalb eines konfigurierbaren Basisverzeichnisses.

Öffentliche Protokollendpunkte für ACME, OCSP und RFC-3161-Zeitstempel werden direkt vom Dienst bereitgestellt. Administrative Endpunkte für Signierung, Import und Systemverwaltung sind durch einen Shared-Secret-Token im Header geschützt.

## Erste Schritte

### Voraussetzungen

- Go 1.26+
- OpenSSL CLI, intern zur Erstellung des RFC-3161-TSA-Zertifikats verwendet

### Build

```bash
go build -o ca-server ./cmd/ca-server
```

### Konfiguration

```bash
cp .env.example .env
```

Eine vollständige Referenz der Umgebungsvariablen sowie Informationen zur Dateisystemstruktur und API-Dokumentation befinden sich in [docs/CA.md](docs/CA.md).

### Ausführen

```bash
./ca-server
```

## Dokumentation

[docs/CA.md](docs/CA.md) enthält die vollständige API-Referenz, den ACME-Protokollablauf, OCSP-, CRL- und TSA-Interna, die Dateisystemstruktur, bekannte Einschränkungen und Bereitstellungshinweise.

## Sicherheit

Dieser Dienst verwaltet privates Schlüsselmaterial für eine oder mehrere Zertifizierungsstellen und muss als sicherheitskritische Komponente betrieben werden.

- Konfiguriere in Produktionsumgebungen immer ein Authentifizierungstoken. Ohne Token sind administrative Endpunkte nicht authentifiziert.
- Mache nur Endpunkte öffentlich erreichbar, bei denen dies erforderlich ist, beispielsweise ACME, OCSP und Zeitstempel. Halte administrative Endpunkte intern.
- Schütze den Speicherort der privaten Schlüssel im Dateisystem durch geeignete Berechtigungen.

## Lizenz

Dieses Projekt ist unter der [GNU Affero General Public License v3.0](LICENSE) (AGPLv3) lizenziert.
