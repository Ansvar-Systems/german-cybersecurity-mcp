# Coverage — German Cybersecurity MCP

This document describes the BSI corpus ingested into this MCP server.

**Source:** Bundesamt für Sicherheit in der Informationstechnik (BSI)
**Portal:** https://www.bsi.bund.de/

---

## Guidance Documents

### BSI Technical Guidelines (TR series)

BSI Technical Guidelines (Technische Richtlinien) specify minimum requirements and recommendations for IT security topics. Reference format: `BSI TR-XXXXX` (e.g., `BSI TR-02102`, `BSI TR-03116`).

Key series covered:
- **BSI TR-02102** — Cryptographic Mechanisms (TLS, SSH, S/MIME)
- **BSI TR-03116** — eHealth / electronic health card cryptography
- **BSI TR-03110** — Advanced Security Mechanisms for Machine Readable Travel Documents
- **BSI TR-03138** — RESISCAN (Replacing paper documents with scans)
- Other TR series documents as available

### IT-Grundschutz Kompendium

The IT-Grundschutz Kompendium provides building blocks (Bausteine) for establishing and maintaining an Information Security Management System (ISMS). Reference format: `SYS.1.1`, `APP.1.1`, `OPS.1.1`, etc.

Categories covered:
- **ISMS** — Information Security Management System
- **ORP** — Organisation und Personal (Organisation and Personnel)
- **CON** — Konzeption und Vorgehensweise (Concepts and Procedures)
- **OPS** — Betrieb (Operations)
- **DER** — Detektion und Reaktion (Detection and Response)
- **APP** — Anwendungen (Applications)
- **SYS** — IT-Systeme (IT Systems)
- **IND** — Industrielle IT (Industrial IT)
- **NET** — Netze und Kommunikation (Networks and Communication)
- **INF** — Infrastruktur (Infrastructure)

### BSI Standards (200 series)

The BSI Standards 200 series define the methodology for information security management.

- **BSI-Standard 200-1** — Information Security Management Systems (ISMS)
- **BSI-Standard 200-2** — IT-Grundschutz Methodology
- **BSI-Standard 200-3** — Risk Analysis based on IT-Grundschutz
- **BSI-Standard 200-4** — Business Continuity Management (BCM)

---

## Security Advisories

### CB-K Series

BSI security advisories and alerts (Cyber-Sicherheitswarnungen) covering vulnerabilities in software, hardware, and industrial systems. Reference format: `BSI-CB-K24-XXXX` (year-based).

Content includes:
- Vulnerability advisories with CVE references
- Affected product lists
- Severity ratings (critical, high, medium, low)
- Mitigation recommendations

---

## Frameworks

The `frameworks` table catalogues the series themselves:

| ID | Name |
|----|------|
| `IT-Grundschutz` | IT-Grundschutz Kompendium |
| `TR` | BSI Technical Guidelines (TR series) |
| `BSI-Standard` | BSI Standards (200 series) |

---

## Data Freshness

The database is populated by the ingest script (`scripts/ingest-bsi.ts`). A GitHub Actions workflow (`.github/workflows/check-updates.yml`) runs monthly to detect new BSI publications and alert maintainers.

Use the `de_cyber_check_data_freshness` tool to query the most recent document date in the live database.
