/**
 * Seed the BSI database with sample guidance documents, advisories, and
 * frameworks for testing.
 *
 * Includes representative BSI Technical Guidelines, IT-Grundschutz building
 * blocks, BSI Standards, and sample security advisories so MCP tools can be
 * tested without running a full data ingestion pipeline.
 *
 * Usage:
 *   npx tsx scripts/seed-sample.ts
 *   npx tsx scripts/seed-sample.ts --force   # drop and recreate
 */

import Database from "better-sqlite3";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

const DB_PATH = process.env["BSI_DB_PATH"] ?? "data/bsi.db";
const force = process.argv.includes("--force");

// --- Bootstrap database ------------------------------------------------------

const dir = dirname(DB_PATH);
if (!existsSync(dir)) {
  mkdirSync(dir, { recursive: true });
}

if (force && existsSync(DB_PATH)) {
  unlinkSync(DB_PATH);
  console.log(`Deleted existing database at ${DB_PATH}`);
}

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(SCHEMA_SQL);

console.log(`Database initialised at ${DB_PATH}`);

// --- Frameworks --------------------------------------------------------------

interface FrameworkRow {
  id: string;
  name: string;
  name_en: string;
  description: string;
  document_count: number;
}

const frameworks: FrameworkRow[] = [
  {
    id: "it-grundschutz",
    name: "IT-Grundschutz-Kompendium",
    name_en: "IT-Grundschutz Compendium",
    description:
      "Das IT-Grundschutz-Kompendium des BSI enthält Bausteine, Gefährdungen und Anforderungen für den Aufbau eines Informationssicherheitsmanagementsystems (ISMS). Es gliedert sich in Schichten: ISMS, ORP (Organisation und Personal), CON (Konzeption und Vorgehensweise), OPS (Betrieb), DER (Detektion und Reaktion), APP (Anwendungen), SYS (IT-Systeme), IND (Industrielle IT), NET (Netze und Kommunikation), INF (Infrastruktur).",
    document_count: 111,
  },
  {
    id: "bsi-tr",
    name: "BSI Technische Richtlinien (TR)",
    name_en: "BSI Technical Guidelines (TR)",
    description:
      "BSI Technische Richtlinien (TR) geben konkrete technische Empfehlungen zu spezifischen IT-Sicherheitsthemen. Sie richten sich an Hersteller, Betreiber und Anwender und decken Bereiche wie Kryptographie, eID, TLS, Cloud-Sicherheit und biometrische Verfahren ab.",
    document_count: 47,
  },
  {
    id: "bsi-standard",
    name: "BSI-Standards",
    name_en: "BSI Standards",
    description:
      "BSI-Standards beschreiben anerkannte Vorgehensweisen, Methoden und Verfahren zu Themen der Informationssicherheit. Die 200er-Reihe definiert die Grundlage für den IT-Grundschutz: BSI-Standard 200-1 (ISMS), 200-2 (IT-Grundschutz-Methodik), 200-3 (Risikoanalyse), 200-4 (Business Continuity Management).",
    document_count: 4,
  },
];

const insertFramework = db.prepare(
  "INSERT OR IGNORE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)",
);

for (const f of frameworks) {
  insertFramework.run(f.id, f.name, f.name_en, f.description, f.document_count);
}

console.log(`Inserted ${frameworks.length} frameworks`);

// --- Guidance documents ------------------------------------------------------

interface GuidanceRow {
  reference: string;
  title: string;
  title_en: string | null;
  date: string;
  type: string;
  series: string;
  summary: string;
  full_text: string;
  topics: string;
  status: string;
}

const guidance: GuidanceRow[] = [
  // BSI TR-03116 -- TLS recommendations
  {
    reference: "BSI TR-03116",
    title: "Kryptographische Vorgaben fuer Projekte der Bundesregierung -- Teil 4: Kommunikationsverfahren in Anwendungen",
    title_en: "Cryptographic Requirements for Federal Government Projects -- Part 4: Communication Protocols in Applications",
    date: "2022-03-01",
    type: "technical_guideline",
    series: "TR",
    summary:
      "BSI TR-03116 Part 4 legt kryptographische Mindestanforderungen an TLS-Verbindungen in Bundesbehoerden-Anwendungen fest. Es spezifiziert zulaessige TLS-Versionen (mindestens TLS 1.2), Cipher Suites, Zertifikatsanforderungen und Schluessellängen.",
    full_text:
      "BSI TR-03116-4 definiert kryptographische Vorgaben fuer Kommunikationsverfahren in Bundesbehoerden-Anwendungen. TLS-Versionen: Mindestens TLS 1.2 ist erforderlich; TLS 1.3 wird empfohlen. TLS 1.0 und 1.1 sind unzulaessig. Cipher Suites: Nur Forward Secrecy (FS)-Cipher Suites sind zulaessig, zum Beispiel TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384. Zertifikate: RSA-Schluessellaenge mindestens 3000 Bit; EC-Schluessel mindestens 250 Bit (empfohlen: NIST P-256 oder staerker). Zertifikatslaufzeit: Maximal 2 Jahre fuer TLS-Serverzertifikate. Hash-Algorithmen: SHA-256 oder staerker. MD5 und SHA-1 sind unzulaessig. HSTS: HTTP Strict Transport Security muss fuer oeffentlich erreichbare Dienste konfiguriert werden (max-age mindestens 6 Monate). Client-Authentifizierung: Mutual TLS (mTLS) wird fuer Maschine-zu-Maschine-Kommunikation empfohlen. Protokoll-Erweiterungen: OCSP Stapling sollte aktiviert sein. TLS-Kompression ist verboten (CRIME-Angriff). Renegotiation: Unsichere TLS-Renegotiation ist verboten.",
    topics: JSON.stringify(["tls", "kryptographie", "web-sicherheit"]),
    status: "current",
  },
  // BSI TR-02102 -- Cryptographic algorithms
  {
    reference: "BSI TR-02102",
    title: "Kryptographische Verfahren: Empfehlungen und Schluessellängen",
    title_en: "Cryptographic Mechanisms: Recommendations and Key Lengths",
    date: "2024-02-01",
    type: "technical_guideline",
    series: "TR",
    summary:
      "BSI TR-02102 gibt Empfehlungen zu kryptographischen Verfahren und empfohlenen Schluessellängen. Gliedert sich in vier Teile: Symmetrische Verschluesselung und Hash-Funktionen, Asymmetrische Verschluesselung, SSH, TLS. Wird jaehrlich aktualisiert.",
    full_text:
      "BSI TR-02102 beschreibt kryptographische Verfahren, die fuer den Einsatz in sicherheitskritischen Anwendungen geeignet sind, und gibt Empfehlungen zu Schluessellängen. Teil 1: Symmetrische Verschluesselungsverfahren -- AES mit mindestens 128 Bit ist das empfohlene Verfahren; AES-256 fuer langfristigen Schutz. 3DES ist nur noch in Legacy-Anwendungen akzeptabel und soll nicht neu eingesetzt werden. Block-Modi: GCM, CCM, CBC und CTR sind zulaessig; ECB ist verboten. Hash-Funktionen -- SHA-256 und staerker sind empfohlen. SHA-1 ist fuer digitale Signaturen nicht mehr zulaessig. MD5 ist vollstaendig verboten. Schluesselleitungsfunktionen -- HKDF, PBKDF2 mit SHA-256 und mindestens 100.000 Iterationen, Argon2id fuer Passwort-Hashing. Teil 2: Asymmetrische Verfahren -- RSA mit mindestens 3000-Bit-Schluesseln bis 2031 (danach 4096 Bit empfohlen). Elliptische Kurven: NIST P-256, P-384, Brainpool P-256r1 und staerker. ECDSA und EdDSA (Ed25519) fuer digitale Signaturen empfohlen. Post-Quanten-Kryptographie: BSI empfiehlt, Migration zu Post-Quanten-sicheren Verfahren vorzubereiten. Teil 3: SSH -- SSH-2 ist erforderlich; SSH-1 ist verboten. Zulaessige KEX-Algorithmen: ecdh-sha2-nistp256, curve25519-sha256. Teil 4: TLS -- Verweise auf BSI TR-03116.",
    topics: JSON.stringify(["kryptographie", "schluessellängen", "algorithmen"]),
    status: "current",
  },
  // BSI TR-03107 -- eID
  {
    reference: "BSI TR-03107",
    title: "Elektronische Identitaeten und Vertrauensdienste im E-Government",
    title_en: "Electronic Identities and Trust Services in E-Government",
    date: "2021-06-01",
    type: "technical_guideline",
    series: "TR",
    summary:
      "BSI TR-03107 definiert Anforderungen an elektronische Identifizierungsverfahren und Vertrauensdienste im deutschen E-Government. Legt Vertrauensniveaus (substantiell, hoch) gemaess eIDAS-Verordnung fest und beschreibt die technischen Anforderungen an die Online-Ausweisfunktion (eID).",
    full_text:
      "BSI TR-03107 beschreibt die Anforderungen an elektronische Identitaeten und Vertrauensdienste im E-Government in Anwendung der eIDAS-Verordnung (EU) Nr. 910/2014. Vertrauensniveaus nach eIDAS: Niedrig -- Identifizierung anhand selbst erklaerter Daten, keine Ueberpruefung. Substantiell -- Identifizierung mit Ueberpruefung, z. B. durch Abgleich mit Ausweisdokument; der deutsche Personalausweis (nPA) mit Online-Ausweisfunktion (eID) erfuellt dieses Niveau. Hoch -- Physische Praesenz oder gleichwertige Verfahren bei der Registrierung; eID mit qualifizierter elektronischer Signatur (QES). Online-Ausweisfunktion (eID): Der nPA mit aktivierter eID-Funktion (PACE-Protokoll, RFID-Chip) ermoeglicht die rechtssichere Online-Identifizierung. Dienste muessen ueber ein berechtigtes Dienstezertifikat verfuegen. eID-Server: Dienste, die eID nutzen, muessen einen BSI-zertifizierten eID-Server einsetzen. Qualifizierte elektronische Signatur (QES): Fuer hoechste Vertrauensniveaus; erfordert qualifiziertes Zertifikat von akkreditiertem Vertrauensdiensteanbieter (VDA).",
    topics: JSON.stringify(["eid", "e-government", "identifizierung"]),
    status: "current",
  },
  // BSI-Standard 200-1 -- ISMS
  {
    reference: "BSI-Standard 200-1",
    title: "Managementsysteme fuer Informationssicherheit (ISMS)",
    title_en: "Information Security Management Systems (ISMS)",
    date: "2017-10-01",
    type: "standard",
    series: "BSI-Standard",
    summary:
      "BSI-Standard 200-1 beschreibt die Anforderungen an ein Managementsystem fuer Informationssicherheit (ISMS) und ist kompatibel mit ISO/IEC 27001. Er definiert die grundlegenden Bestandteile eines ISMS: Sicherheitsleitlinie, Sicherheitsorganisation, Sicherheitskonzept und kontinuierlichen Verbesserungsprozess.",
    full_text:
      "BSI-Standard 200-1 legt die Anforderungen an ein Managementsystem fuer Informationssicherheit (ISMS) fest und ist mit ISO/IEC 27001 kompatibel. Ein ISMS nach BSI-Standard 200-1 umfasst: (1) Sicherheitsleitlinie -- Die Leitungsebene muss eine schriftliche Sicherheitsleitlinie verabschieden, die die Ziele und Grundsaetze der Informationssicherheit der Institution festlegt. Die Leitlinie ist regelmaessig zu ueberpruefern und zu aktualisieren. (2) Sicherheitsorganisation -- Es ist eine Sicherheitsorganisation mit klar definierten Rollen und Verantwortlichkeiten aufzubauen. Insbesondere muss ein Informationssicherheitsbeauftragter (ISB) benannt werden. (3) Sicherheitskonzept -- Das Sicherheitskonzept dokumentiert die Sicherheitsmassnahmen fuer die zu schuetzenden Informationen und IT-Systeme. Es basiert auf einer Risikoanalyse und der Anwendung von IT-Grundschutz-Bausteinen. (4) Kontinuierlicher Verbesserungsprozess -- Das ISMS muss regelmaessig auf seine Wirksamkeit ueberprueft werden, z. B. durch interne Audits und Management-Reviews. (5) Dokumentation -- Alle sicherheitsrelevanten Prozesse und Massnahmen muessen angemessen dokumentiert sein. (6) Schulung und Sensibilisierung -- Mitarbeiter muessen regelmaessig zu Informationssicherheit geschult und sensibilisiert werden. Kompatibilitaet mit ISO 27001: BSI-Standard 200-1 ist so gestaltet, dass Institutionen, die IT-Grundschutz nach BSI-Standard 200-2 umsetzen, auch die Anforderungen der ISO/IEC 27001 erfuellen koennen.",
    topics: JSON.stringify(["isms", "managementsystem", "iso27001"]),
    status: "current",
  },
  // BSI-Standard 200-2 -- IT-Grundschutz methodology
  {
    reference: "BSI-Standard 200-2",
    title: "IT-Grundschutz-Methodik",
    title_en: "IT-Grundschutz Methodology",
    date: "2017-10-01",
    type: "standard",
    series: "BSI-Standard",
    summary:
      "BSI-Standard 200-2 beschreibt die Methodik zur Umsetzung von IT-Grundschutz. Er definiert drei Vorgehensweisen: Basis-Absicherung (schneller Einstieg), Standard-Absicherung (vollstaendige IT-Grundschutz-Umsetzung) und Kern-Absicherung (Fokus auf kritische Assets). Enthaelt den IT-Grundschutz-Prozess von Strukturanalyse bis zur Zertifizierung.",
    full_text:
      "BSI-Standard 200-2 beschreibt, wie IT-Grundschutz in einer Institution eingefuehrt und umgesetzt wird. Drei Vorgehensweisen: (1) Basis-Absicherung -- Schneller Einstieg durch Umsetzung grundlegender Sicherheitsanforderungen aller relevanten Bausteine. Geeignet fuer Institutionen, die noch am Anfang stehen. Keine vollstaendige Schutzbedarfsfeststellung, keine individuelle Risikoanalyse. (2) Standard-Absicherung -- Vollstaendige IT-Grundschutz-Umsetzung: Initiierung des Sicherheitsprozesses, Organisation des Sicherheitsmanagements, Erstellung von Sicherheitskonzepten, Umsetzung, Ueberpruefung und Verbesserung. Basis fuer ISO 27001-Zertifizierung auf Basis von IT-Grundschutz. (3) Kern-Absicherung -- Fokus auf die kritischsten Assets der Institution (Kronjuwelen). IT-Grundschutz-Prozess (Standard-Absicherung): Schritt 1: Initiierung -- Sicherheitsleitlinie erstellen, ISB benennen, Ressourcen bereitstellen. Schritt 2: Strukturanalyse -- Erfassung aller Geschaeftsprozesse, Informationen, Anwendungen, IT-Systeme, Netzverbindungen und Raeume. Schritt 3: Schutzbedarfsfeststellung -- Bestimmung des Schutzbedarfs jedes Assets in den Kategorien Vertraulichkeit, Integritaet, Verfuegbarkeit (normal, hoch, sehr hoch). Schritt 4: Modellierung -- Zuordnung von IT-Grundschutz-Bausteinen zu den Komponenten. Schritt 5: IT-Grundschutz-Check -- Soll-Ist-Vergleich zwischen geforderten Anforderungen und tatsaechlich umgesetzten Massnahmen. Schritt 6: Risikoanalyse -- Fuer Bereiche mit hohem oder sehr hohem Schutzbedarf. Schritt 7: Realisierungsplanung -- Priorisierung und Planung der Umsetzung offener Anforderungen. Schritt 8: Umsetzung und Betrieb -- Implementierung der Massnahmen, Schulung, Sensibilisierung. Schritt 9: Ueberpruefung -- Interne Revisionen, Audits, Management-Review.",
    topics: JSON.stringify(["it-grundschutz", "methodik", "sicherheitskonzept"]),
    status: "current",
  },
  // BSI-Standard 200-3 -- Risk analysis
  {
    reference: "BSI-Standard 200-3",
    title: "Risikoanalyse auf der Basis von IT-Grundschutz",
    title_en: "Risk Analysis Based on IT-Grundschutz",
    date: "2017-10-01",
    type: "standard",
    series: "BSI-Standard",
    summary:
      "BSI-Standard 200-3 beschreibt eine vereinfachte Methode zur Risikoanalyse auf Basis von IT-Grundschutz. Er wird angewendet, wenn der Schutzbedarf hoch oder sehr hoch ist oder wenn kein geeigneter IT-Grundschutz-Baustein existiert. Enthaelt Methodik zur Gefaehrdungsidentifizierung, Risikoeinschaetzung und Risikobehandlung.",
    full_text:
      "BSI-Standard 200-3 ergaenzt die IT-Grundschutz-Methodik um eine strukturierte Risikoanalyse fuer Bereiche mit erhoehtem Schutzbedarf. Anwendungsbereich: Die Risikoanalyse nach BSI-Standard 200-3 ist erforderlich fuer: Zielobjekte mit hohem oder sehr hohem Schutzbedarf; Zielobjekte, fuer die kein passender IT-Grundschutz-Baustein existiert; Einsatzumgebungen, die im IT-Grundschutz-Kompendium nicht abgedeckt sind. Vorgehensweise: Schritt 1: Gefaehrdungsuebersicht erstellen -- Identifizierung aller relevanten Gefaehrdungen aus dem BSI-Gefaehrdungskatalog und spezifischer Gefaehrdungen aus dem Anwendungskontext. Schritt 2: Zustaetzliche Gefaehrdungen identifizieren -- Ueber den IT-Grundschutz hinausgehende Gefaehrdungen erfassen. Schritt 3: Einwirkung der Gefaehrdungen einschaetzen -- Bewertung der Eintrittswahrscheinlichkeit und des Schadensausmasses jeder Gefaehrdung. Risikomatrix: Eintrittswahrscheinlichkeit (selten, mittel, haeufig) x Schadensausmass (begrenzt, betraechtlich, existenzbedrohend) ergibt das Risiko (gering, mittel, hoch). Schritt 4: Behandlung der Gefaehrdungen -- Fuer jede relevante Gefaehrdung: Risikoakzeptanz (bei geringem Risiko), Risikoreduktion durch zustaetzliche Sicherheitsmassnahmen, Risikovermeidung, Risikotransfer (z. B. Versicherung). Schritt 5: Konsolidierung -- Dokumentation aller Risiken und Behandlungsoptionen im Sicherheitskonzept. Akzeptierte Restrisiken muessen von der Leitungsebene genehmigt werden.",
    topics: JSON.stringify(["risikoanalyse", "it-grundschutz", "risikomanagement"]),
    status: "current",
  },
  // IT-Grundschutz building block: SYS.1.1 -- General server
  {
    reference: "SYS.1.1",
    title: "Allgemeiner Server",
    title_en: "General Server",
    date: "2022-02-01",
    type: "it_grundschutz",
    series: "IT-Grundschutz",
    summary:
      "IT-Grundschutz-Baustein SYS.1.1 beschreibt Sicherheitsanforderungen fuer allgemeine Server unabhaengig vom Betriebssystem. Umfasst Planung, Inbetriebnahme, Betrieb und Ausserbbetriebnahme von Servern. Gilt als Basis fuer alle spezifischen Server-Bausteine (SYS.1.2, SYS.1.3 usw.).",
    full_text:
      "IT-Grundschutz-Baustein SYS.1.1 Allgemeiner Server richtet sich an Server-Administratoren und IT-Sicherheitsbeauftragte. Basisanforderungen (MUSS): SYS.1.1.A1 -- Zugangskontrolle und Authentifizierung: Alle administrativen Zugaenge zu Servern muessen authentifiziert sein. Passwoerter muessen komplex genug sein oder es muss ein anderes starkes Authentifizierungsverfahren eingesetzt werden. SYS.1.1.A2 -- Benutzerkonten: Fuer jede Aufgabe auf dem Server muessen getrennte Benutzerkonten eingesetzt werden. Administrative Taetigkeiten duerfen nicht mit normalen Benutzerkonten durchgefuehrt werden. SYS.1.1.A3 -- Kein ungesicherter Netzzugang: Alle Netzdienste auf dem Server, die nicht benoetigt werden, muessen deaktiviert sein. SYS.1.1.A4 -- Schutz von Administrationsschnittstellen: Der Zugang zu Verwaltungsschnittstellen (SSH, RDP, iLO/IPMI) muss auf autorisierte Administratoren beschraenkt und ueber verschluesselte Verbindungen abgesichert sein. SYS.1.1.A5 -- Datensicherung: Es muessen regelmaessige Datensicherungen durchgefuehrt werden. Standard-Anforderungen (SOLLTE): SYS.1.1.A6 -- Sicheres Loeschen und Vernichten: Beim Aussondern von Servern muessen Datentraeger sicher geloescht werden. SYS.1.1.A7 -- Updates und Patches: Sicherheits-Updates fuer das Betriebssystem und alle eingesetzten Anwendungen sind zeitnah einzuspielen. SYS.1.1.A8 -- Protokollierung: Alle sicherheitsrelevanten Ereignisse auf dem Server muessen protokolliert werden.",
    topics: JSON.stringify(["server", "betriebssystem", "zugangskontrolle"]),
    status: "current",
  },
  // IT-Grundschutz building block: APP.1.1 -- Office products
  {
    reference: "APP.1.1",
    title: "Office-Produkte",
    title_en: "Office Products",
    date: "2022-02-01",
    type: "it_grundschutz",
    series: "IT-Grundschutz",
    summary:
      "IT-Grundschutz-Baustein APP.1.1 beschreibt Sicherheitsanforderungen fuer den Einsatz von Office-Produkten (Textverarbeitung, Tabellenkalkulation, Praesentation). Umfasst Makrosicherheit, Dateiformat-Sicherheit, Update-Management und sichere Konfiguration.",
    full_text:
      "IT-Grundschutz-Baustein APP.1.1 Office-Produkte beschreibt Anforderungen fuer den sicheren Einsatz gaengiger Office-Anwendungen wie Microsoft Office oder LibreOffice. Basisanforderungen (MUSS): APP.1.1.A1 -- Sicherstellen der Integritaet von Office-Produkten: Office-Produkte muessen ueber vertrauenswuerdige Quellen bezogen werden; die Integritaet der Installationspakete muss geprueft werden. APP.1.1.A2 -- Einschraenken von Aktiven Inhalten: Das automatische Ausfuehren von Makros muss deaktiviert oder auf signierte Makros aus vertrauenswuerdigen Quellen beschraenkt sein. APP.1.1.A3 -- Oeffnen von Dokumenten aus externen Quellen: Dokumente aus externen Quellen (E-Mail-Anhaenge, Downloads) muessen in einer isolierten Umgebung (Protected View) geoeffnet werden. APP.1.1.A4 -- Absichern des laufenden Betriebs: Sicherheits-Updates fuer Office-Produkte muessen zeitnah eingespielt werden. Standard-Anforderungen (SOLLTE): APP.1.1.A5 -- Auswahl geeigneter Office-Produkte: Bei der Produktauswahl sollen Sicherheitseigenschaften beruecksichtigt werden, z. B. Unterstuetzung moderner Datei-Formate (OOXML, ODF) statt veralteter Binaerformate. APP.1.1.A6 -- Testen neuer Versionen: Neue Versionen von Office-Produkten sollen vor dem produktiven Einsatz getestet werden. APP.1.1.A7 -- Installation nur notwendiger Komponenten: Es sollen nur die tatsaechlich benoetigten Komponenten installiert werden.",
    topics: JSON.stringify(["office", "anwendungen", "makros"]),
    status: "current",
  },
  // IT-Grundschutz building block: NET.1.1 -- Network architecture
  {
    reference: "NET.1.1",
    title: "Netzarchitektur und -design",
    title_en: "Network Architecture and Design",
    date: "2022-02-01",
    type: "it_grundschutz",
    series: "IT-Grundschutz",
    summary:
      "IT-Grundschutz-Baustein NET.1.1 beschreibt Anforderungen an Planung und Design von Netzarchitekturen. Umfasst Netzsegmentierung, DMZ-Konzepte, sichere Administration von Netzkomponenten und Redundanz. Grundlage fuer alle spezifischeren Netz-Bausteine.",
    full_text:
      "IT-Grundschutz-Baustein NET.1.1 Netzarchitektur und -design legt Anforderungen an die Planung und Konzeption von Netzwerken fest. Basisanforderungen (MUSS): NET.1.1.A1 -- Sicherheitsrichtlinie fuer das Netz: Es muss eine Netz-Sicherheitsrichtlinie erstellt werden, die Netzdesign-Anforderungen, Segmentierung und Zugriffsregeln festlegt. NET.1.1.A2 -- Dokumentation des Netzes: Das Netz muss vollstaendig dokumentiert sein, einschliesslich Netzplaene, IP-Adressbereiche und Netzkomponenten. NET.1.1.A3 -- Anforderungsspezifikation fuer das Netz: Anforderungen an Verfuegbarkeit, Vertraulichkeit, Integritaet, Leistung und Skalierbarkeit muessen spezifiziert werden. NET.1.1.A4 -- Netztrennung: Das Netz muss in Zonen aufgeteilt sein: mindestens eine DMZ (Demilitarisierte Zone) fuer extern erreichbare Dienste, ein internes Netz fuer interne Systeme, ein Management-Netz fuer die Netzadministration. NET.1.1.A5 -- Client-Server-Trennung: Client-Systeme und Server muessen in getrennten Netzsegmenten betrieben werden. NET.1.1.A6 -- Sicherer Internetzugang: Der Internetzugang muss ueber einen sicheren Uebergangspunkt (Firewall, Proxy) erfolgen. Standard-Anforderungen (SOLLTE): NET.1.1.A7 -- Trennung sicherheitsrelevanter Systeme: Hochsicherheitssysteme (z. B. CA, HSM) sollen in eigenen Segmenten betrieben werden. NET.1.1.A8 -- Redundante Auslegung: Fuer kritische Netzverbindungen soll Redundanz geplant werden.",
    topics: JSON.stringify(["netzwerk", "segmentierung", "dmz"]),
    status: "current",
  },
];

const insertGuidance = db.prepare(`
  INSERT OR IGNORE INTO guidance
    (reference, title, title_en, date, type, series, summary, full_text, topics, status)
  VALUES
    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const insertGuidanceAll = db.transaction(() => {
  for (const g of guidance) {
    insertGuidance.run(
      g.reference,
      g.title,
      g.title_en,
      g.date,
      g.type,
      g.series,
      g.summary,
      g.full_text,
      g.topics,
      g.status,
    );
  }
});

insertGuidanceAll();
console.log(`Inserted ${guidance.length} guidance documents`);

// --- Advisories --------------------------------------------------------------

interface AdvisoryRow {
  reference: string;
  title: string;
  date: string;
  severity: string;
  affected_products: string;
  summary: string;
  full_text: string;
  cve_references: string;
}

const advisories: AdvisoryRow[] = [
  // Advisory: critical VPN vulnerability
  {
    reference: "BSI-CB-K24-0001",
    title: "Kritische Sicherheitsluecke in VPN-Gateways mehrerer Hersteller",
    date: "2024-02-14",
    severity: "critical",
    affected_products: JSON.stringify([
      "Fortinet FortiOS",
      "Ivanti Connect Secure",
      "Palo Alto Networks PAN-OS",
    ]),
    summary:
      "Das BSI warnt vor aktiv ausgenutzten kritischen Sicherheitsluecken in VPN-Gateways fuehrender Hersteller. Angreifer koennen ohne Authentifizierung Schadcode ausfuehren und vollstaendigen Zugriff auf interne Netzwerke erlangen. Sofortiges Patchen oder temporaere Abschaltung betroffener Systeme wird dringend empfohlen.",
    full_text:
      "Das BSI hat eine Warnung der Hoechststufe (Kritisch) fuer Sicherheitsluecken in VPN-Gateways herausgegeben, die aktiv durch staatliche und kriminelle Angreifer ausgenutzt werden. Schwachstellenbeschreibung: Die Schwachstellen (CVE-2024-21762, CVE-2024-22024) ermoeglichen es nicht authentifizierten Angreifern aus dem Internet, beliebigen Code auf den betroffenen Geraeten auszufuehren (Remote Code Execution, RCE). Dies ermoeglicht die vollstaendige Kompromittierung des VPN-Gateways und einen unkontrollierten Zugang zum angeschlossenen Netzwerk. Angriffsmuster: Angriffe werden weltweit beobachtet; erste Anzeichen deuten auf APT-Akteure (Advanced Persistent Threat) hin. Betroffene Systeme: Fortinet FortiOS 7.x und 6.x (bestimmte Versionen), Ivanti Connect Secure (alle aktuellen Versionen), Palo Alto Networks PAN-OS (bestimmte Versionen). Sofortmassnahmen: (1) Sofortiges Einspielen verfuegbarer Sicherheits-Updates; (2) Falls kein Patch verfuegbar: temporaere Abschaltung oder Isolation des betroffenen Systems; (3) Ueberpruefung aller Verbindungsprotokoll auf Anzeichen einer Kompromittierung; (4) Passwort-Reset fuer alle VPN-Nutzerkonten nach Patchen; (5) Meldung von Sicherheitsvorfaellen an das BSI.",
    cve_references: JSON.stringify(["CVE-2024-21762", "CVE-2024-22024"]),
  },
  // Advisory: ransomware campaign
  {
    reference: "BSI-CB-K24-0042",
    title: "Warnung vor gezielten Ransomware-Angriffen auf kritische Infrastrukturen",
    date: "2024-05-08",
    severity: "high",
    affected_products: JSON.stringify([
      "Windows Server (alle Versionen)",
      "Active Directory",
      "VMware ESXi",
    ]),
    summary:
      "Das BSI warnt vor einer aktiven Ransomware-Kampagne, die gezielt kritische Infrastrukturen in Deutschland angreift. Die Angreifer nutzen gestohlene Zugangsdaten und ungepatchte Schwachstellen, um sich lateral im Netzwerk zu bewegen und anschliessend Daten zu verschluesseln.",
    full_text:
      "Das BSI beobachtet eine signifikante Zunahme von Ransomware-Angriffen auf KRITIS-Betreiber (Kritische Infrastrukturen) in Deutschland. Angriffsmethodik: Die Angreifer gehen in mehreren Phasen vor: Phase 1 -- Initialer Zugang: Spear-Phishing-E-Mails mit infizierten Office-Dokumenten oder Ausnutzung von VPN-Schwachstellen, alternativ Nutzung gestohlener RDP-Zugangsdaten aus dem Darknet. Phase 2 -- Lateral Movement: Einsatz von Tools wie Cobalt Strike, Mimikatz (zur Credential-Extraktion), BloodHound (zur AD-Enumeration). Die Angreifer bewegen sich typischerweise 2-4 Wochen unentdeckt im Netzwerk. Phase 3 -- Exfiltration: Vor der Verschluesselung werden sensible Daten exfiltriert (Double Extortion). Phase 4 -- Ransomware-Deployment: Deployment der Ransomware auf moeglichst viele Systeme, einschliesslich ESXi-Hypervisoren und Backup-Systeme. Schutzmassnahmen: Technisch: Aktivierung von Windows Defender Credential Guard, Deaktivierung von NTLM-Authentifizierung wo moeglich, Netz-Segmentierung (insbesondere Backup-Netz), Monitoring auf LSASS-Zugriffe und ungewoehnliche AD-Abfragen. Organisatorisch: Regelmaessige Backup-Tests (3-2-1-Regel: 3 Kopien, 2 verschiedene Medien, 1 offline), Incident-Response-Plan testen, Mitarbeiter zu Phishing sensibilisieren. Meldepflichten: KRITIS-Betreiber sind nach BSI-Gesetz verpflichtet, erhebliche Stoerungen an das BSI zu melden.",
    cve_references: JSON.stringify([]),
  },
  // Advisory: supply chain attack
  {
    reference: "BSI-CB-K24-0078",
    title: "Supply-Chain-Angriff auf verbreitete Open-Source-Bibliothek",
    date: "2024-07-22",
    severity: "high",
    affected_products: JSON.stringify([
      "Anwendungen mit xz-utils 5.6.0-5.6.1",
      "Linux-Distributionen (Debian, Fedora, openSUSE -- Entwicklungsversionen)",
    ]),
    summary:
      "Das BSI warnt vor einem Supply-Chain-Angriff, bei dem eine bekannte Open-Source-Bibliothek mit einem Backdoor kompromittiert wurde. Betroffene Systeme ermoeglichen einem Angreifer moeglicherweise eine unauthentifizierte Remote-Code-Ausfuehrung ueber SSH. Betroffen sind primaer Entwicklungs- und Rolling-Release-Versionen gaengiger Linux-Distributionen.",
    full_text:
      "Das BSI gibt eine Sicherheitswarnung zu einem kritischen Supply-Chain-Angriff auf die xz-utils-Bibliothek heraus (CVE-2024-3094). Hintergrund: Ein Angreifer hat ueber einen Zeitraum von zwei Jahren das Vertrauen der xz-utils-Community aufgebaut und dann in den Versionen 5.6.0 und 5.6.1 einen Backdoor eingebaut. Die manipulierten Versionen wurden in Entwicklungsversionen von Debian, Fedora und openSUSE eingebunden. Technische Details: Der Backdoor modifiziert die liblzma-Bibliothek, die von systemd-sshd genutzt wird. Dies ermoeglicht es einem Angreifer mit dem zugehoerigen privaten Schluessel, SSH-Authentifizierung zu umgehen und als root Code auszufuehren. Die Stable-Releases grosser Linux-Distributionen (Ubuntu LTS, Debian stable, RHEL) sind nicht betroffen. Betroffene Systeme identifizieren: Ueberpruefung der installierten xz-utils-Version (xz --version). Version 5.6.0 oder 5.6.1 bei Nutzung von systemd: sofortige Massnahmen erforderlich. Sofortmassnahmen: Downgrade auf xz-utils 5.4.x; System auf Kompromittierung untersuchen; Ueberpruefung aller SSH-Schluessel und Protokolle auf unberechtigte Zugriffe; Meldung an BSI falls Kompromittierung festgestellt. Lehren: Dieser Angriff zeigt die Notwendigkeit systematischer Ueberpruefung von Open-Source-Abhaengigkeiten (Software Composition Analysis, SCA) und kryptographischer Verifikation von Software-Releases (Signaturen).",
    cve_references: JSON.stringify(["CVE-2024-3094"]),
  },
];

const insertAdvisory = db.prepare(`
  INSERT OR IGNORE INTO advisories
    (reference, title, date, severity, affected_products, summary, full_text, cve_references)
  VALUES
    (?, ?, ?, ?, ?, ?, ?, ?)
`);

const insertAdvisoriesAll = db.transaction(() => {
  for (const a of advisories) {
    insertAdvisory.run(
      a.reference,
      a.title,
      a.date,
      a.severity,
      a.affected_products,
      a.summary,
      a.full_text,
      a.cve_references,
    );
  }
});

insertAdvisoriesAll();
console.log(`Inserted ${advisories.length} advisories`);

// --- Summary -----------------------------------------------------------------

const guidanceCount = (
  db.prepare("SELECT count(*) as cnt FROM guidance").get() as { cnt: number }
).cnt;
const advisoryCount = (
  db.prepare("SELECT count(*) as cnt FROM advisories").get() as { cnt: number }
).cnt;
const frameworkCount = (
  db.prepare("SELECT count(*) as cnt FROM frameworks").get() as { cnt: number }
).cnt;
const guidanceFtsCount = (
  db.prepare("SELECT count(*) as cnt FROM guidance_fts").get() as { cnt: number }
).cnt;
const advisoryFtsCount = (
  db.prepare("SELECT count(*) as cnt FROM advisories_fts").get() as { cnt: number }
).cnt;

console.log(`\nDatabase summary:`);
console.log(`  Frameworks:     ${frameworkCount}`);
console.log(`  Guidance docs:  ${guidanceCount} (FTS entries: ${guidanceFtsCount})`);
console.log(`  Advisories:     ${advisoryCount} (FTS entries: ${advisoryFtsCount})`);
console.log(`\nDone. Database ready at ${DB_PATH}`);

db.close();
