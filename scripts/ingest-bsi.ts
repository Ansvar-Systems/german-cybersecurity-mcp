/**
 * BSI Ingestion Crawler
 *
 * Scrapes the BSI website (bsi.bund.de) and populates the SQLite database
 * with real guidance documents (Technical Guidelines, BSI Standards,
 * IT-Grundschutz building blocks) and security advisories from CERT-Bund.
 *
 * Data sources:
 *   1. Technical Guidelines (TR) — listed at bsi.bund.de TR-nach-Thema-sortiert
 *   2. BSI Standards 200-1 through 200-4 — individual detail pages
 *   3. IT-Grundschutz Kompendium building blocks — edition download page
 *   4. CERT-Bund security advisories — RSS feed + individual advisory pages
 *
 * Usage:
 *   npx tsx scripts/ingest-bsi.ts                  # full crawl
 *   npx tsx scripts/ingest-bsi.ts --resume          # resume from last checkpoint
 *   npx tsx scripts/ingest-bsi.ts --dry-run         # log what would be inserted
 *   npx tsx scripts/ingest-bsi.ts --force            # drop and recreate DB first
 *   npx tsx scripts/ingest-bsi.ts --advisories-only  # only crawl advisories
 *   npx tsx scripts/ingest-bsi.ts --guidance-only    # only crawl guidance
 */

import Database from "better-sqlite3";
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DB_PATH = process.env["BSI_DB_PATH"] ?? "data/bsi.db";
const PROGRESS_FILE = resolve(dirname(DB_PATH), "ingest-progress.json");
const BASE_URL = "https://www.bsi.bund.de";
const WID_RSS_URL = "https://wid.cert-bund.de/content/public/securityAdvisory/rss";
const WID_BASE = "https://wid.cert-bund.de";

const RATE_LIMIT_MS = 1500;
const MAX_RETRIES = 3;
const RETRY_BACKOFF_MS = 2000;
const USER_AGENT =
  "AnsvarBSICrawler/1.0 (+https://ansvar.eu; compliance research)";

// CLI flags
const args = process.argv.slice(2);
const force = args.includes("--force");
const dryRun = args.includes("--dry-run");
const resume = args.includes("--resume");
const advisoriesOnly = args.includes("--advisories-only");
const guidanceOnly = args.includes("--guidance-only");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface GuidanceRow {
  reference: string;
  title: string;
  title_en: string | null;
  date: string | null;
  type: string;
  series: string;
  summary: string;
  full_text: string;
  topics: string;
  status: string;
}

interface AdvisoryRow {
  reference: string;
  title: string;
  date: string | null;
  severity: string | null;
  affected_products: string | null;
  summary: string;
  full_text: string;
  cve_references: string | null;
}

interface FrameworkRow {
  id: string;
  name: string;
  name_en: string | null;
  description: string;
  document_count: number;
}

interface Progress {
  completed_tr_urls: string[];
  completed_grundschutz_refs: string[];
  completed_standards: string[];
  completed_advisory_refs: string[];
  last_updated: string;
}

// ---------------------------------------------------------------------------
// Utility: rate-limited fetch with retry
// ---------------------------------------------------------------------------

let lastRequestTime = 0;

async function rateLimitedFetch(
  url: string,
  opts?: RequestInit,
): Promise<Response> {
  const now = Date.now();
  const elapsed = now - lastRequestTime;
  if (elapsed < RATE_LIMIT_MS) {
    await sleep(RATE_LIMIT_MS - elapsed);
  }

  let lastError: Error | null = null;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      lastRequestTime = Date.now();
      const resp = await fetch(url, {
        headers: { "User-Agent": USER_AGENT, Accept: "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8" },
        redirect: "follow",
        signal: AbortSignal.timeout(30_000),
        ...opts,
      });
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status} for ${url}`);
      }
      return resp;
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      console.warn(
        `  [retry ${attempt}/${MAX_RETRIES}] ${url}: ${lastError.message}`,
      );
      if (attempt < MAX_RETRIES) {
        await sleep(RETRY_BACKOFF_MS * attempt);
      }
    }
  }
  throw lastError!;
}

async function fetchText(url: string): Promise<string> {
  const resp = await rateLimitedFetch(url);
  return resp.text();
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ---------------------------------------------------------------------------
// Lightweight HTML helpers (no cheerio dependency)
// ---------------------------------------------------------------------------

/**
 * Minimal HTML text extraction. Strips tags, decodes common entities,
 * and collapses whitespace. Good enough for extracting readable text
 * from BSI page sections.
 */
function htmlToText(html: string): string {
  return html
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "")
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n\n")
    .replace(/<\/li>/gi, "\n")
    .replace(/<\/h[1-6]>/gi, "\n\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&auml;/g, "ä")
    .replace(/&ouml;/g, "ö")
    .replace(/&uuml;/g, "ü")
    .replace(/&Auml;/g, "Ä")
    .replace(/&Ouml;/g, "Ö")
    .replace(/&Uuml;/g, "Ü")
    .replace(/&szlig;/g, "ß")
    .replace(/&#\d+;/g, "")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

/**
 * Extract all <a> tags matching a pattern from raw HTML.
 * Returns array of { href, text }.
 */
function extractLinks(
  html: string,
  hrefPattern?: RegExp,
): Array<{ href: string; text: string }> {
  const results: Array<{ href: string; text: string }> = [];
  const re = /<a\s[^>]*href\s*=\s*"([^"]*)"[^>]*>([\s\S]*?)<\/a>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const href = m[1]!;
    const text = htmlToText(m[2]!);
    if (!hrefPattern || hrefPattern.test(href)) {
      results.push({ href, text });
    }
  }
  return results;
}

/**
 * Extract content between a start marker and end marker in HTML.
 */
function extractSection(
  html: string,
  startPattern: RegExp,
  endPattern: RegExp,
): string {
  const startMatch = startPattern.exec(html);
  if (!startMatch) return "";
  const startIdx = startMatch.index + startMatch[0].length;
  const rest = html.slice(startIdx);
  const endMatch = endPattern.exec(rest);
  const endIdx = endMatch ? endMatch.index : rest.length;
  return rest.slice(0, endIdx);
}

/**
 * Extract the main content area from a BSI page.
 * BSI pages use various content container patterns.
 */
function extractMainContent(html: string): string {
  // Try common BSI content containers
  const patterns: Array<[RegExp, RegExp]> = [
    [/<main[^>]*>/i, /<\/main>/i],
    [/<div[^>]*class="[^"]*content[^"]*"[^>]*>/i, /<\/div>\s*<footer/i],
    [/<article[^>]*>/i, /<\/article>/i],
    [/<div[^>]*id="content"[^>]*>/i, /<\/div>\s*<footer/i],
  ];

  for (const [start, end] of patterns) {
    const section = extractSection(html, start, end);
    if (section.length > 200) {
      return section;
    }
  }

  // Fallback: use everything between </nav> and <footer>
  const fallback = extractSection(html, /<\/nav>/i, /<footer/i);
  if (fallback.length > 100) return fallback;

  return html;
}

/**
 * Parse XML RSS items. Minimal RSS parser without external deps.
 */
function parseRssItems(xml: string): Array<Record<string, string>> {
  const items: Array<Record<string, string>> = [];
  const itemRe = /<item>([\s\S]*?)<\/item>/gi;
  let itemMatch: RegExpExecArray | null;
  while ((itemMatch = itemRe.exec(xml)) !== null) {
    const itemXml = itemMatch[1]!;
    const item: Record<string, string> = {};
    const tagRe = /<(\w+)>([\s\S]*?)<\/\1>/g;
    let tagMatch: RegExpExecArray | null;
    while ((tagMatch = tagRe.exec(itemXml)) !== null) {
      item[tagMatch[1]!] = tagMatch[2]!
        .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
        .trim();
    }
    items.push(item);
  }
  return items;
}

// ---------------------------------------------------------------------------
// Progress tracking
// ---------------------------------------------------------------------------

function loadProgress(): Progress {
  if (resume && existsSync(PROGRESS_FILE)) {
    try {
      const raw = readFileSync(PROGRESS_FILE, "utf-8");
      const p = JSON.parse(raw) as Progress;
      console.log(
        `Resuming from checkpoint (${p.last_updated}): ` +
          `${p.completed_tr_urls.length} TRs, ` +
          `${p.completed_grundschutz_refs.length} Grundschutz modules, ` +
          `${p.completed_standards.length} standards, ` +
          `${p.completed_advisory_refs.length} advisories`,
      );
      return p;
    } catch {
      console.warn("Could not parse progress file, starting fresh");
    }
  }
  return {
    completed_tr_urls: [],
    completed_grundschutz_refs: [],
    completed_standards: [],
    completed_advisory_refs: [],
    last_updated: new Date().toISOString(),
  };
}

function saveProgress(progress: Progress): void {
  progress.last_updated = new Date().toISOString();
  writeFileSync(PROGRESS_FILE, JSON.stringify(progress, null, 2));
}

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------

function initDatabase(): Database.Database {
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
  return db;
}

// ---------------------------------------------------------------------------
// Framework definitions (static — these don't change often)
// ---------------------------------------------------------------------------

const FRAMEWORKS: FrameworkRow[] = [
  {
    id: "it-grundschutz",
    name: "IT-Grundschutz-Kompendium",
    name_en: "IT-Grundschutz Compendium",
    description:
      "Das IT-Grundschutz-Kompendium des BSI enthält Bausteine, Gefährdungen und Anforderungen für den Aufbau eines Informationssicherheitsmanagementsystems (ISMS). Es gliedert sich in Schichten: ISMS, ORP (Organisation und Personal), CON (Konzeption und Vorgehensweise), OPS (Betrieb), DER (Detektion und Reaktion), APP (Anwendungen), SYS (IT-Systeme), IND (Industrielle IT), NET (Netze und Kommunikation), INF (Infrastruktur).",
    document_count: 0, // updated after crawl
  },
  {
    id: "bsi-tr",
    name: "BSI Technische Richtlinien (TR)",
    name_en: "BSI Technical Guidelines (TR)",
    description:
      "BSI Technische Richtlinien (TR) geben konkrete technische Empfehlungen zu spezifischen IT-Sicherheitsthemen. Sie richten sich an Hersteller, Betreiber und Anwender und decken Bereiche wie Kryptographie, eID, TLS, Cloud-Sicherheit und biometrische Verfahren ab.",
    document_count: 0,
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

// ---------------------------------------------------------------------------
// 1. Crawl Technical Guidelines (TR)
// ---------------------------------------------------------------------------

const TR_LIST_URL = `${BASE_URL}/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr-nach-thema-sortiert_node.html`;

interface TrEntry {
  reference: string;
  title: string;
  detailUrl: string;
  archived: boolean;
}

async function discoverTechnicalGuidelines(): Promise<TrEntry[]> {
  console.log("\n--- Discovering Technical Guidelines ---");
  const html = await fetchText(TR_LIST_URL);
  const links = extractLinks(html, /Technische-Richtlinien\/TR-nach-Thema-sortiert\//i);

  const entries: TrEntry[] = [];
  const seen = new Set<string>();

  for (const link of links) {
    // Extract TR reference from link text (e.g. "BSI TR-02102 Kryptographische...")
    const refMatch = link.text.match(/BSI\s+TR[-\s](\d{5}(?:-\d+)?)/i);
    if (!refMatch) continue;

    const ref = `BSI TR-${refMatch[1]}`;
    if (seen.has(ref)) continue;
    seen.add(ref);

    const archived = /archiviert/i.test(link.text);
    const titleClean = link.text
      .replace(/BSI\s+TR[-\s]\d{5}(?:-\d+)?\s*/i, "")
      .replace(/\s*\(archiviert\)\s*/i, "")
      .trim();

    const detailUrl = link.href.startsWith("http")
      ? link.href
      : `${BASE_URL}${link.href}`;

    entries.push({
      reference: ref,
      title: titleClean || ref,
      detailUrl,
      archived,
    });
  }

  console.log(`  Found ${entries.length} Technical Guidelines`);
  return entries;
}

async function crawlTrDetail(entry: TrEntry): Promise<GuidanceRow | null> {
  try {
    const html = await fetchText(entry.detailUrl);
    const mainContent = extractMainContent(html);
    const bodyText = htmlToText(mainContent);

    if (bodyText.length < 50) {
      console.warn(`  Skipping ${entry.reference}: page content too short`);
      return null;
    }

    // Try to extract a date from the page (format DD.MM.YYYY or YYYY-MM)
    const dateMatch = bodyText.match(
      /(?:Version|Stand|Datum|Date)[:\s]*(\d{4}[-/]\d{2}(?:[-/]\d{2})?|\d{2}\.\d{2}\.\d{4})/i,
    );
    let date: string | null = null;
    if (dateMatch?.[1]) {
      const raw = dateMatch[1];
      if (/^\d{2}\.\d{2}\.\d{4}$/.test(raw)) {
        // DD.MM.YYYY -> YYYY-MM-DD
        const [d, m, y] = raw.split(".");
        date = `${y}-${m}-${d}`;
      } else if (/^\d{4}[-/]\d{2}$/.test(raw)) {
        date = raw.replace("/", "-");
      } else {
        date = raw.replace(/\//g, "-");
      }
    }

    // Extract English title if the page has one
    let titleEn: string | null = null;
    const enMatch = mainContent.match(
      /(?:english|englisch)[^<]*<[^>]*>([^<]+)/i,
    );
    if (enMatch?.[1]) {
      titleEn = htmlToText(enMatch[1]);
    }

    // Extract summary: first substantial paragraph
    const paragraphs = bodyText.split(/\n\n+/).filter((p) => p.length > 60);
    const summary = paragraphs[0] ?? bodyText.slice(0, 500);

    // Detect topics from content
    const topics = detectTopics(bodyText, entry.reference);

    return {
      reference: entry.reference,
      title: entry.title || entry.reference,
      title_en: titleEn,
      date,
      type: "technical_guideline",
      series: "TR",
      summary: summary.slice(0, 2000),
      full_text: bodyText.slice(0, 50_000),
      topics: JSON.stringify(topics),
      status: entry.archived ? "archived" : "current",
    };
  } catch (err) {
    console.error(
      `  Error crawling ${entry.reference}: ${err instanceof Error ? err.message : err}`,
    );
    return null;
  }
}

// ---------------------------------------------------------------------------
// 2. Crawl BSI Standards (200-1 through 200-4)
// ---------------------------------------------------------------------------

const BSI_STANDARDS = [
  {
    reference: "BSI-Standard 200-1",
    path: "/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/BSI-Standards/BSI-Standard-200-1-Managementsysteme-fuer-Informationssicherheit/bsi-standard-200-1-managementsysteme-fuer-informationssicherheit_node.html",
    title: "Managementsysteme für Informationssicherheit (ISMS)",
    title_en: "Information Security Management Systems (ISMS)",
  },
  {
    reference: "BSI-Standard 200-2",
    path: "/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/BSI-Standards/BSI-Standard-200-2-IT-Grundschutz-Methodik/bsi-standard-200-2-it-grundschutz-methodik_node.html",
    title: "IT-Grundschutz-Methodik",
    title_en: "IT-Grundschutz Methodology",
  },
  {
    reference: "BSI-Standard 200-3",
    path: "/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/BSI-Standards/BSI-Standard-200-3-Risikomanagement/bsi-standard-200-3-risikomanagement_node.html",
    title: "Risikomanagement",
    title_en: "Risk Management",
  },
  {
    reference: "BSI-Standard 200-4",
    path: "/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/BSI-Standards/BSI-Standard-200-4-Business-Continuity-Management/bsi-standard-200-4_Business_Continuity_Management_node.html",
    title: "Business Continuity Management",
    title_en: "Business Continuity Management",
  },
];

async function crawlBsiStandard(
  std: (typeof BSI_STANDARDS)[number],
): Promise<GuidanceRow | null> {
  try {
    const url = `${BASE_URL}${std.path}`;
    const html = await fetchText(url);
    const mainContent = extractMainContent(html);
    const bodyText = htmlToText(mainContent);

    if (bodyText.length < 50) {
      console.warn(`  Skipping ${std.reference}: page content too short`);
      return null;
    }

    // Extract date
    const dateMatch = bodyText.match(
      /(?:Version|Stand|Datum|Oktober|November|Dezember|Januar|Februar|März)\s*(\d{4})/i,
    );
    const date = dateMatch?.[1] ? `${dateMatch[1]}-01-01` : null;

    const paragraphs = bodyText.split(/\n\n+/).filter((p) => p.length > 60);
    const summary = paragraphs[0] ?? bodyText.slice(0, 500);

    const topics = detectTopics(bodyText, std.reference);

    return {
      reference: std.reference,
      title: std.title,
      title_en: std.title_en,
      date,
      type: "standard",
      series: "BSI-Standard",
      summary: summary.slice(0, 2000),
      full_text: bodyText.slice(0, 50_000),
      topics: JSON.stringify(topics),
      status: "current",
    };
  } catch (err) {
    console.error(
      `  Error crawling ${std.reference}: ${err instanceof Error ? err.message : err}`,
    );
    return null;
  }
}

// ---------------------------------------------------------------------------
// 3. Crawl IT-Grundschutz building blocks
// ---------------------------------------------------------------------------

const GRUNDSCHUTZ_DOWNLOAD_URL = `${BASE_URL}/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/IT-Grundschutz-Kompendium/IT-Grundschutz-Bausteine/Bausteine_Download_Edition_node.html`;

/**
 * Complete catalogue of IT-Grundschutz building blocks (Edition 2023).
 * Reference IDs and German titles from the official Kompendium listing.
 * The crawler fetches detail pages for each module to get full content.
 */
const GRUNDSCHUTZ_MODULES: Array<{
  ref: string;
  title: string;
  title_en: string;
  layer: string;
}> = [
  // ISMS
  { ref: "ISMS.1", title: "Sicherheitsmanagement", title_en: "Security Management", layer: "ISMS" },
  // ORP
  { ref: "ORP.1", title: "Organisation", title_en: "Organisation", layer: "ORP" },
  { ref: "ORP.2", title: "Personal", title_en: "Personnel", layer: "ORP" },
  { ref: "ORP.3", title: "Sensibilisierung und Schulung zur Informationssicherheit", title_en: "Security Awareness and Training", layer: "ORP" },
  { ref: "ORP.4", title: "Identitäts- und Berechtigungsmanagement", title_en: "Identity and Access Management", layer: "ORP" },
  { ref: "ORP.5", title: "Compliance Management (Anforderungsmanagement)", title_en: "Compliance Management", layer: "ORP" },
  // CON
  { ref: "CON.1", title: "Kryptokonzept", title_en: "Cryptography Concept", layer: "CON" },
  { ref: "CON.2", title: "Datenschutz", title_en: "Data Protection", layer: "CON" },
  { ref: "CON.3", title: "Datensicherungskonzept", title_en: "Backup Concept", layer: "CON" },
  { ref: "CON.6", title: "Löschen und Vernichten", title_en: "Deletion and Destruction", layer: "CON" },
  { ref: "CON.7", title: "Informationssicherheit auf Auslandsreisen", title_en: "Information Security During International Travel", layer: "CON" },
  { ref: "CON.8", title: "Software-Entwicklung", title_en: "Software Development", layer: "CON" },
  { ref: "CON.9", title: "Informationsaustausch", title_en: "Information Exchange", layer: "CON" },
  { ref: "CON.10", title: "Entwicklung von Webanwendungen", title_en: "Web Application Development", layer: "CON" },
  { ref: "CON.11.1", title: "Geheimschutz VS-NUR FÜR DEN DIENSTGEBRAUCH (VS-NfD)", title_en: "Classified Information Protection (RESTRICTED)", layer: "CON" },
  // OPS
  { ref: "OPS.1.1.1", title: "Allgemeiner IT-Betrieb", title_en: "General IT Operations", layer: "OPS" },
  { ref: "OPS.1.1.2", title: "Ordnungsgemäße IT-Administration", title_en: "Proper IT Administration", layer: "OPS" },
  { ref: "OPS.1.1.3", title: "Patch- und Änderungsmanagement", title_en: "Patch and Change Management", layer: "OPS" },
  { ref: "OPS.1.1.4", title: "Schutz vor Schadprogrammen", title_en: "Malware Protection", layer: "OPS" },
  { ref: "OPS.1.1.5", title: "Protokollierung", title_en: "Logging", layer: "OPS" },
  { ref: "OPS.1.1.6", title: "Software-Tests und -Freigaben", title_en: "Software Testing and Releases", layer: "OPS" },
  { ref: "OPS.1.1.7", title: "Systemmanagement", title_en: "Systems Management", layer: "OPS" },
  { ref: "OPS.1.2.2", title: "Archivierung", title_en: "Archiving", layer: "OPS" },
  { ref: "OPS.1.2.4", title: "Telearbeit", title_en: "Telework", layer: "OPS" },
  { ref: "OPS.1.2.5", title: "Fernwartung", title_en: "Remote Maintenance", layer: "OPS" },
  { ref: "OPS.1.2.6", title: "NTP-Zeitsynchronisation", title_en: "NTP Time Synchronisation", layer: "OPS" },
  { ref: "OPS.2.2", title: "Cloud-Nutzung", title_en: "Cloud Usage", layer: "OPS" },
  { ref: "OPS.2.3", title: "Nutzung von Outsourcing", title_en: "Outsourcing Usage", layer: "OPS" },
  { ref: "OPS.3.2", title: "Anbieten von Outsourcing", title_en: "Outsourcing Provision", layer: "OPS" },
  // DER
  { ref: "DER.1", title: "Detektion von sicherheitsrelevanten Ereignissen", title_en: "Detection of Security-Relevant Events", layer: "DER" },
  { ref: "DER.2.1", title: "Behandlung von Sicherheitsvorfällen", title_en: "Security Incident Handling", layer: "DER" },
  { ref: "DER.2.2", title: "Vorsorge für die IT-Forensik", title_en: "IT Forensics Preparation", layer: "DER" },
  { ref: "DER.2.3", title: "Bereinigung weitreichender Sicherheitsvorfälle", title_en: "Remediation of Major Security Incidents", layer: "DER" },
  { ref: "DER.3.1", title: "Audits und Revisionen", title_en: "Audits and Reviews", layer: "DER" },
  { ref: "DER.3.2", title: "Revision auf Basis des Leitfadens IS-Revision", title_en: "Review Based on IS-Revision Guide", layer: "DER" },
  { ref: "DER.4", title: "Notfallmanagement", title_en: "Emergency Management", layer: "DER" },
  // APP
  { ref: "APP.1.1", title: "Office-Produkte", title_en: "Office Products", layer: "APP" },
  { ref: "APP.1.2", title: "Webbrowser", title_en: "Web Browser", layer: "APP" },
  { ref: "APP.1.4", title: "Mobile Anwendungen (Apps)", title_en: "Mobile Applications (Apps)", layer: "APP" },
  { ref: "APP.2.1", title: "Allgemeiner Verzeichnisdienst", title_en: "General Directory Service", layer: "APP" },
  { ref: "APP.2.2", title: "Active Directory Domain Services", title_en: "Active Directory Domain Services", layer: "APP" },
  { ref: "APP.2.3", title: "OpenLDAP", title_en: "OpenLDAP", layer: "APP" },
  { ref: "APP.3.1", title: "Webanwendungen und Webservices", title_en: "Web Applications and Web Services", layer: "APP" },
  { ref: "APP.3.2", title: "Webserver", title_en: "Web Server", layer: "APP" },
  { ref: "APP.3.3", title: "Fileserver", title_en: "File Server", layer: "APP" },
  { ref: "APP.3.4", title: "Samba", title_en: "Samba", layer: "APP" },
  { ref: "APP.3.6", title: "DNS-Server", title_en: "DNS Server", layer: "APP" },
  { ref: "APP.4.2", title: "SAP-ERP-System", title_en: "SAP ERP System", layer: "APP" },
  { ref: "APP.4.3", title: "Relationale Datenbanksysteme", title_en: "Relational Database Systems", layer: "APP" },
  { ref: "APP.4.4", title: "Kubernetes", title_en: "Kubernetes", layer: "APP" },
  { ref: "APP.4.6", title: "SAP ABAP-Programmierung", title_en: "SAP ABAP Programming", layer: "APP" },
  { ref: "APP.5.2", title: "Microsoft Exchange und Outlook", title_en: "Microsoft Exchange and Outlook", layer: "APP" },
  { ref: "APP.5.3", title: "Allgemeiner E-Mail-Client und -Server", title_en: "General Email Client and Server", layer: "APP" },
  { ref: "APP.5.4", title: "Unified Communications und Collaboration", title_en: "Unified Communications and Collaboration", layer: "APP" },
  { ref: "APP.6", title: "Allgemeine Software", title_en: "General Software", layer: "APP" },
  { ref: "APP.7", title: "Entwicklung von Individualsoftware", title_en: "Custom Software Development", layer: "APP" },
  // SYS
  { ref: "SYS.1.1", title: "Allgemeiner Server", title_en: "General Server", layer: "SYS" },
  { ref: "SYS.1.2.2", title: "Windows Server 2012", title_en: "Windows Server 2012", layer: "SYS" },
  { ref: "SYS.1.2.3", title: "Windows Server", title_en: "Windows Server", layer: "SYS" },
  { ref: "SYS.1.3", title: "Server unter Linux und Unix", title_en: "Servers Running Linux and Unix", layer: "SYS" },
  { ref: "SYS.1.5", title: "Virtualisierung", title_en: "Virtualisation", layer: "SYS" },
  { ref: "SYS.1.6", title: "Containerisierung", title_en: "Containerisation", layer: "SYS" },
  { ref: "SYS.1.7", title: "IBM Z", title_en: "IBM Z", layer: "SYS" },
  { ref: "SYS.1.8", title: "Speicherlösungen", title_en: "Storage Solutions", layer: "SYS" },
  { ref: "SYS.1.9", title: "Terminalserver", title_en: "Terminal Server", layer: "SYS" },
  { ref: "SYS.2.1", title: "Allgemeiner Client", title_en: "General Client", layer: "SYS" },
  { ref: "SYS.2.2.3", title: "Clients unter Windows", title_en: "Clients Running Windows", layer: "SYS" },
  { ref: "SYS.2.3", title: "Clients unter Linux und Unix", title_en: "Clients Running Linux and Unix", layer: "SYS" },
  { ref: "SYS.2.4", title: "Clients unter macOS", title_en: "Clients Running macOS", layer: "SYS" },
  { ref: "SYS.2.5", title: "Client-Virtualisierung", title_en: "Client Virtualisation", layer: "SYS" },
  { ref: "SYS.2.6", title: "Virtual Desktop Infrastructure", title_en: "Virtual Desktop Infrastructure", layer: "SYS" },
  { ref: "SYS.3.1", title: "Laptops", title_en: "Laptops", layer: "SYS" },
  { ref: "SYS.3.2.1", title: "Allgemeine Smartphones und Tablets", title_en: "General Smartphones and Tablets", layer: "SYS" },
  { ref: "SYS.3.2.2", title: "Mobile Device Management (MDM)", title_en: "Mobile Device Management (MDM)", layer: "SYS" },
  { ref: "SYS.3.2.3", title: "iOS (for Enterprise)", title_en: "iOS (for Enterprise)", layer: "SYS" },
  { ref: "SYS.3.2.4", title: "Android", title_en: "Android", layer: "SYS" },
  { ref: "SYS.3.3", title: "Mobiltelefon", title_en: "Mobile Phone", layer: "SYS" },
  { ref: "SYS.4.1", title: "Drucker, Kopierer und Multifunktionsgeräte", title_en: "Printers, Copiers and Multifunction Devices", layer: "SYS" },
  { ref: "SYS.4.3", title: "Eingebettete Systeme", title_en: "Embedded Systems", layer: "SYS" },
  { ref: "SYS.4.4", title: "Allgemeines IoT-Gerät", title_en: "General IoT Device", layer: "SYS" },
  { ref: "SYS.4.5", title: "Wechseldatenträger", title_en: "Removable Media", layer: "SYS" },
  // IND
  { ref: "IND.1", title: "Prozessleit- und Automatisierungstechnik", title_en: "Process Control and Automation Technology", layer: "IND" },
  { ref: "IND.2.1", title: "Allgemeine ICS-Komponente", title_en: "General ICS Component", layer: "IND" },
  { ref: "IND.2.2", title: "Speicherprogrammierbare Steuerung (SPS)", title_en: "Programmable Logic Controller (PLC)", layer: "IND" },
  { ref: "IND.2.3", title: "Sensoren und Aktoren", title_en: "Sensors and Actuators", layer: "IND" },
  { ref: "IND.2.4", title: "Maschine", title_en: "Machine", layer: "IND" },
  { ref: "IND.2.7", title: "Safety Instrumented Systems", title_en: "Safety Instrumented Systems", layer: "IND" },
  { ref: "IND.3.2", title: "Fernwartung im industriellen Umfeld", title_en: "Remote Maintenance in Industrial Environments", layer: "IND" },
  // NET
  { ref: "NET.1.1", title: "Netzarchitektur und -design", title_en: "Network Architecture and Design", layer: "NET" },
  { ref: "NET.1.2", title: "Netzmanagement", title_en: "Network Management", layer: "NET" },
  { ref: "NET.2.1", title: "WLAN-Betrieb", title_en: "WLAN Operations", layer: "NET" },
  { ref: "NET.2.2", title: "WLAN-Nutzung", title_en: "WLAN Usage", layer: "NET" },
  { ref: "NET.3.1", title: "Router und Switches", title_en: "Routers and Switches", layer: "NET" },
  { ref: "NET.3.2", title: "Firewall", title_en: "Firewall", layer: "NET" },
  { ref: "NET.3.3", title: "VPN", title_en: "VPN", layer: "NET" },
  { ref: "NET.3.4", title: "Network Access Control (NAC)", title_en: "Network Access Control (NAC)", layer: "NET" },
  { ref: "NET.4.1", title: "TK-Anlagen", title_en: "Telecommunications Systems", layer: "NET" },
  { ref: "NET.4.2", title: "VoIP", title_en: "VoIP", layer: "NET" },
  { ref: "NET.4.3", title: "Faxgeräte und Faxserver", title_en: "Fax Machines and Fax Servers", layer: "NET" },
  // INF
  { ref: "INF.1", title: "Allgemeines Gebäude", title_en: "General Building", layer: "INF" },
  { ref: "INF.2", title: "Rechenzentrum sowie Serverraum", title_en: "Data Centre and Server Room", layer: "INF" },
  { ref: "INF.5", title: "Raum sowie Schrank für technische Infrastruktur", title_en: "Room and Cabinet for Technical Infrastructure", layer: "INF" },
  { ref: "INF.6", title: "Datenträgerarchiv", title_en: "Media Archive", layer: "INF" },
  { ref: "INF.7", title: "Büroarbeitsplatz", title_en: "Office Workplace", layer: "INF" },
  { ref: "INF.8", title: "Häuslicher Arbeitsplatz", title_en: "Home Office Workplace", layer: "INF" },
  { ref: "INF.9", title: "Mobiler Arbeitsplatz", title_en: "Mobile Workplace", layer: "INF" },
  { ref: "INF.10", title: "Besprechungs-, Veranstaltungs- und Schulungsräume", title_en: "Meeting, Event and Training Rooms", layer: "INF" },
  { ref: "INF.11", title: "Allgemeines Fahrzeug", title_en: "General Vehicle", layer: "INF" },
  { ref: "INF.12", title: "Verkabelung", title_en: "Cabling", layer: "INF" },
  { ref: "INF.13", title: "Technisches Gebäudemanagement", title_en: "Technical Building Management", layer: "INF" },
  { ref: "INF.14", title: "Gebäudeautomation", title_en: "Building Automation", layer: "INF" },
];

/**
 * Build the URL for a Grundschutz module detail page.
 *
 * BSI hosts individual module pages under the IT-Grundschutz-Kompendium
 * section. The URL pattern varies slightly per module, so we use the
 * download listing page to discover actual links. If we can't find a
 * specific detail page, we fall back to the download listing page and
 * extract what we can.
 */
async function crawlGrundschutzModule(
  mod: (typeof GRUNDSCHUTZ_MODULES)[number],
): Promise<GuidanceRow | null> {
  // Build a search URL on the BSI site for this specific module
  const searchUrl = `${BASE_URL}/SiteGlobals/Forms/Suche/BSI/Sicherheitsberatung/Sicherheitsberatung_Formular.html?nn=132646&searchIssued_dt.GROUP=1&templateQueryString=${encodeURIComponent(mod.ref + " " + mod.title)}&cl2Categories_Format_fq=Baustein`;

  try {
    // Try the Kompendium section to find the individual module page
    const kompendiumBase = `${BASE_URL}/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/IT-Grundschutz-Kompendium`;

    // Map layer to BSI section path
    const layerPaths: Record<string, string> = {
      ISMS: "ISMS",
      ORP: "ORP",
      CON: "CON",
      OPS: "OPS",
      DER: "DER",
      APP: "APP",
      SYS: "SYS",
      IND: "IND",
      NET: "NET",
      INF: "INF",
    };

    const layerPath = layerPaths[mod.layer] ?? mod.layer;

    // Try fetching the module detail page directly
    // BSI uses various URL patterns for modules — try the most common ones
    const refSlug = mod.ref.replace(/\./g, "_");
    const candidateUrls = [
      `${kompendiumBase}/${layerPath}/${mod.ref}/${mod.ref}_node.html`,
      `${kompendiumBase}/${layerPath}/${refSlug}/${refSlug}_node.html`,
    ];

    let bodyText = "";
    let fetchedUrl = "";

    for (const candidateUrl of candidateUrls) {
      try {
        const html = await fetchText(candidateUrl);
        const mainContent = extractMainContent(html);
        bodyText = htmlToText(mainContent);
        if (bodyText.length > 100) {
          fetchedUrl = candidateUrl;
          break;
        }
      } catch {
        // URL variant did not work, try next
      }
    }

    // If direct page fetch failed, use the download listing page
    // and extract the description for this module
    if (bodyText.length < 100) {
      const listHtml = await fetchText(GRUNDSCHUTZ_DOWNLOAD_URL);
      // Find the section for this module in the listing
      const refEscaped = mod.ref.replace(/\./g, "\\.");
      const sectionRe = new RegExp(
        `${refEscaped}[\\s\\S]{0,200}${mod.title.slice(0, 30).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`,
        "i",
      );
      const sectionMatch = sectionRe.exec(listHtml);

      // Build a description from what we know
      bodyText = `IT-Grundschutz-Baustein ${mod.ref} ${mod.title}. ` +
        `Schicht: ${mod.layer}. ` +
        `Dieser Baustein ist Teil des IT-Grundschutz-Kompendiums des BSI und beschreibt Sicherheitsanforderungen für ${mod.title}.`;

      if (sectionMatch) {
        const surrounding = listHtml.slice(
          Math.max(0, sectionMatch.index - 200),
          sectionMatch.index + 1000,
        );
        const surroundingText = htmlToText(surrounding);
        if (surroundingText.length > bodyText.length) {
          bodyText = surroundingText;
        }
      }
      fetchedUrl = GRUNDSCHUTZ_DOWNLOAD_URL;
    }

    const topics = detectGrundschutzTopics(mod);

    return {
      reference: mod.ref,
      title: mod.title,
      title_en: mod.title_en,
      date: "2023-02-01", // Edition 2023
      type: "it_grundschutz",
      series: "IT-Grundschutz",
      summary:
        `IT-Grundschutz-Baustein ${mod.ref} beschreibt Sicherheitsanforderungen für ${mod.title}. ` +
        `Schicht: ${mod.layer} (${getLayerName(mod.layer)}).`,
      full_text: bodyText.slice(0, 50_000),
      topics: JSON.stringify(topics),
      status: "current",
    };
  } catch (err) {
    console.error(
      `  Error crawling ${mod.ref}: ${err instanceof Error ? err.message : err}`,
    );
    return null;
  }
}

function getLayerName(layer: string): string {
  const names: Record<string, string> = {
    ISMS: "Sicherheitsmanagement",
    ORP: "Organisation und Personal",
    CON: "Konzeption und Vorgehensweise",
    OPS: "Betrieb",
    DER: "Detektion und Reaktion",
    APP: "Anwendungen",
    SYS: "IT-Systeme",
    IND: "Industrielle IT",
    NET: "Netze und Kommunikation",
    INF: "Infrastruktur",
  };
  return names[layer] ?? layer;
}

function detectGrundschutzTopics(
  mod: (typeof GRUNDSCHUTZ_MODULES)[number],
): string[] {
  const topics: string[] = [mod.layer.toLowerCase()];
  const titleLower = mod.title.toLowerCase();

  const topicMap: Array<[RegExp, string]> = [
    [/server/i, "server"],
    [/client/i, "client"],
    [/netz|network/i, "netzwerk"],
    [/firewall/i, "firewall"],
    [/vpn/i, "vpn"],
    [/wlan|wifi/i, "wlan"],
    [/cloud/i, "cloud"],
    [/container|docker|kubernetes/i, "container"],
    [/virtualis/i, "virtualisierung"],
    [/datenbank|database/i, "datenbank"],
    [/web/i, "web"],
    [/e-?mail/i, "e-mail"],
    [/mobil|smartphone|tablet/i, "mobil"],
    [/industri|ics|sps|plc/i, "industrie"],
    [/krypto/i, "kryptographie"],
    [/daten.*schutz|privacy/i, "datenschutz"],
    [/patch|update|änderung/i, "patch-management"],
    [/protokoll|logging/i, "protokollierung"],
    [/forensi/i, "forensik"],
    [/notfall|emergency/i, "notfallmanagement"],
    [/audit|revision/i, "audit"],
    [/personal|schulung|sensibilis/i, "awareness"],
    [/outsourcing/i, "outsourcing"],
    [/archiv/i, "archivierung"],
    [/gebäude|raum|infrastruktur/i, "physische-sicherheit"],
    [/iot/i, "iot"],
    [/drucker|print/i, "peripherie"],
    [/active.?directory|ldap|verzeichnis/i, "verzeichnisdienst"],
    [/sap/i, "sap"],
    [/office/i, "office"],
    [/browser/i, "browser"],
    [/dns/i, "dns"],
    [/samba/i, "dateifreigabe"],
    [/telearbeit|home.?office/i, "telearbeit"],
    [/fernwartung|remote.?maintenance/i, "fernwartung"],
  ];

  for (const [pattern, topic] of topicMap) {
    if (pattern.test(titleLower) || pattern.test(mod.ref)) {
      if (!topics.includes(topic)) {
        topics.push(topic);
      }
    }
  }

  return topics;
}

// ---------------------------------------------------------------------------
// 4. Crawl CERT-Bund security advisories
// ---------------------------------------------------------------------------

interface RssAdvisory {
  reference: string;
  title: string;
  link: string;
  description: string;
  date: string | null;
  severity: string | null;
  category: string | null;
}

async function fetchAdvisoriesFromRss(): Promise<RssAdvisory[]> {
  console.log("\n--- Fetching CERT-Bund advisories from RSS ---");
  const xml = await fetchText(WID_RSS_URL);
  const items = parseRssItems(xml);
  console.log(`  RSS feed returned ${items.length} items`);

  const advisories: RssAdvisory[] = [];

  for (const item of items) {
    const title = item["title"] ?? "";
    const link = item["link"] ?? "";
    const description = item["description"] ?? "";
    const category = item["category"] ?? null;
    const pubDate = item["pubDate"] ?? null;

    // Extract WID-SEC reference from link
    const refMatch = link.match(/WID-SEC-\d{4}-\d{4,}/);
    if (!refMatch) continue;

    const reference = refMatch[0];

    // Parse date from pubDate (RFC 2822)
    let date: string | null = null;
    if (pubDate) {
      try {
        const d = new Date(pubDate);
        if (!isNaN(d.getTime())) {
          date = d.toISOString().slice(0, 10);
        }
      } catch {
        // ignore invalid dates
      }
    }

    // Extract severity from title pattern: [NEU] [hoch] or [UPDATE] [kritisch]
    let severity: string | null = null;
    const sevMatch = title.match(
      /\[(kritisch|hoch|mittel|niedrig|critical|high|medium|low)\]/i,
    );
    if (sevMatch?.[1]) {
      severity = normaliseSeverity(sevMatch[1]);
    } else if (category) {
      severity = normaliseSeverity(category);
    }

    advisories.push({
      reference,
      title: title
        .replace(/\[NEU\]\s*/g, "")
        .replace(/\[UPDATE\]\s*/g, "")
        .replace(/\[UNGEPATCHT\]\s*/g, "")
        .replace(/\[(kritisch|hoch|mittel|niedrig|critical|high|medium|low)\]\s*/gi, "")
        .trim(),
      link,
      description,
      date,
      severity,
      category,
    });
  }

  console.log(`  Parsed ${advisories.length} advisories with valid references`);
  return advisories;
}

function normaliseSeverity(raw: string): string {
  const lower = raw.toLowerCase().trim();
  if (/kritisch|critical|sehr\s*hoch/i.test(lower)) return "critical";
  if (/hoch|high/i.test(lower)) return "high";
  if (/mittel|medium/i.test(lower)) return "medium";
  if (/niedrig|low|gering/i.test(lower)) return "low";
  return lower;
}

async function crawlAdvisoryDetail(
  adv: RssAdvisory,
): Promise<AdvisoryRow | null> {
  try {
    const html = await fetchText(adv.link);
    const mainContent = extractMainContent(html);
    const bodyText = htmlToText(mainContent);

    // Extract affected products — look for a products/software section
    let affectedProducts: string[] = [];
    const productSection = extractSection(
      mainContent,
      /(?:Betroffene\s+Software|Betroffene\s+Systeme|Betroffene\s+Produkte|Affected\s+Software|Software)[:\s]*(?:<[^>]*>)*/i,
      /(?:<h[2-4]|<\/(?:ul|ol|table|div)>)/i,
    );
    if (productSection) {
      const productText = htmlToText(productSection);
      affectedProducts = productText
        .split(/\n|,|;/)
        .map((p) => p.trim())
        .filter((p) => p.length > 2 && p.length < 200);
    }

    // Extract CVE references
    const cveRe = /CVE-\d{4}-\d{4,}/g;
    const cves: string[] = [];
    let cveMatch: RegExpExecArray | null;
    const fullText = bodyText || adv.description;
    while ((cveMatch = cveRe.exec(fullText)) !== null) {
      if (!cves.includes(cveMatch[0])) {
        cves.push(cveMatch[0]);
      }
    }

    // If no severity from RSS, try to extract from detail page
    let severity = adv.severity;
    if (!severity) {
      const sevDetailMatch = bodyText.match(
        /(?:Bedrohungsstufe|Risikostufe|Schweregrad|Severity)[:\s]*(\d+|kritisch|hoch|mittel|niedrig|critical|high|medium|low)/i,
      );
      if (sevDetailMatch?.[1]) {
        const raw = sevDetailMatch[1];
        if (/^\d+$/.test(raw)) {
          const level = parseInt(raw, 10);
          severity = level >= 3 ? "critical" : level === 2 ? "high" : "medium";
        } else {
          severity = normaliseSeverity(raw);
        }
      }
    }

    // Build the full_text from page content or fall back to RSS description
    const detailText = bodyText.length > 100 ? bodyText : adv.description;

    return {
      reference: adv.reference,
      title: adv.title,
      date: adv.date,
      severity: severity ?? "medium",
      affected_products:
        affectedProducts.length > 0
          ? JSON.stringify(affectedProducts)
          : null,
      summary: adv.description.slice(0, 2000) || detailText.slice(0, 2000),
      full_text: detailText.slice(0, 50_000),
      cve_references: cves.length > 0 ? JSON.stringify(cves) : null,
    };
  } catch (err) {
    // If detail page fetch fails, build row from RSS data alone
    console.warn(
      `  Could not fetch detail for ${adv.reference}, using RSS data: ${err instanceof Error ? err.message : err}`,
    );

    // Still extract CVEs from description
    const cveRe = /CVE-\d{4}-\d{4,}/g;
    const cves: string[] = [];
    let cveMatch: RegExpExecArray | null;
    while ((cveMatch = cveRe.exec(adv.description)) !== null) {
      if (!cves.includes(cveMatch[0])) {
        cves.push(cveMatch[0]);
      }
    }

    return {
      reference: adv.reference,
      title: adv.title,
      date: adv.date,
      severity: adv.severity ?? "medium",
      affected_products: null,
      summary: adv.description.slice(0, 2000),
      full_text: adv.description || adv.title,
      cve_references: cves.length > 0 ? JSON.stringify(cves) : null,
    };
  }
}

// ---------------------------------------------------------------------------
// 5. Crawl BSI Cyber-Sicherheitswarnungen (high-level warnings page)
// ---------------------------------------------------------------------------

const CSW_URL = `${BASE_URL}/DE/Themen/Unternehmen-und-Organisationen/Cyber-Sicherheitslage/Technische-Sicherheitshinweise-und-Warnungen/Cyber-Sicherheitswarnungen/cyber-sicherheitswarnungen_node.html`;

async function fetchCyberSecurityWarnings(): Promise<AdvisoryRow[]> {
  console.log("\n--- Fetching BSI Cyber-Sicherheitswarnungen ---");
  const results: AdvisoryRow[] = [];

  try {
    const html = await fetchText(CSW_URL);
    const links = extractLinks(html, /Cybersicherheitswarnungen\/DE\//i);

    console.log(`  Found ${links.length} warning links on page`);

    for (const link of links) {
      // Extract a reference from the filename
      const fileMatch = link.href.match(
        /(\d{4}[-_]\d+[-_]\d+|\d{4}[-_][A-Za-z_]+)/,
      );
      if (!fileMatch) continue;

      const refSegment = fileMatch[1];
      if (!refSegment) continue;
      const ref = `BSI-CSW-${refSegment.replace(/_/g, "-")}`;

      // Parse severity from link text
      let severity: string | null = null;
      const sevMatch = link.text.match(/Bedrohungsstufe\s*(\d+)/);
      if (sevMatch?.[1]) {
        const level = parseInt(sevMatch[1], 10);
        severity = level >= 3 ? "critical" : level === 2 ? "high" : "medium";
      }

      // Parse date from link text (DD.MM.YYYY)
      let date: string | null = null;
      const dateMatch = link.text.match(/(\d{2})\.(\d{2})\.(\d{4})/);
      if (dateMatch) {
        date = `${dateMatch[3]}-${dateMatch[2]}-${dateMatch[1]}`;
      }

      // Clean up title
      const title = link.text
        .replace(/BSI-IT-Sicherheitsmitteilungen.*$/i, "")
        .replace(/Sicherheitshinweis.*$/i, "")
        .replace(/\d{2}\.\d{2}\.\d{4}/g, "")
        .replace(/Bedrohungsstufe\s*\d+\s*(Sehr\s*)?(hoch|mittel|niedrig)/gi, "")
        .replace(/Version\s+[\d.]+:?\s*/gi, "")
        .replace(/\s+/g, " ")
        .trim();

      if (!title || title.length < 5) continue;

      results.push({
        reference: ref,
        title,
        date,
        severity: severity ?? "high",
        affected_products: null,
        summary: link.text.replace(/\s+/g, " ").trim(),
        full_text: link.text.replace(/\s+/g, " ").trim(),
        cve_references: null,
      });
    }
  } catch (err) {
    console.error(
      `  Error fetching CSW page: ${err instanceof Error ? err.message : err}`,
    );
  }

  console.log(`  Extracted ${results.length} warnings`);
  return results;
}

// ---------------------------------------------------------------------------
// Topic detection for Technical Guidelines
// ---------------------------------------------------------------------------

function detectTopics(text: string, reference: string): string[] {
  const topics: string[] = [];
  const lower = text.toLowerCase();

  const topicPatterns: Array<[RegExp, string]> = [
    [/kryptograph|verschlüssel|cipher|aes|rsa|hash/i, "kryptographie"],
    [/tls|ssl|https|transport.*sicher/i, "tls"],
    [/e-?mail|smtp|imap/i, "e-mail"],
    [/cloud/i, "cloud"],
    [/smart\s*card|chipkart|eid|personalausweis|npa/i, "eid"],
    [/de-?mail/i, "de-mail"],
    [/biometri/i, "biometrie"],
    [/signatur|zertifikat|pki/i, "pki"],
    [/random|zufall|rng|trng/i, "zufallszahlen"],
    [/rfid|nfc/i, "rfid"],
    [/web.*(anwendung|applic|sicher)|owasp/i, "web-sicherheit"],
    [/mobil.*(sicher|app)|smartphone/i, "mobile-sicherheit"],
    [/authen.*verfahren|mfa|2fa|passwort/i, "authentifizierung"],
    [/netz.*sicher|firewall|ids|ips/i, "netzwerksicherheit"],
    [/daten.*schutz|gdpr|dsgvo/i, "datenschutz"],
    [/scada|ics|industri.*steuer|ot.?sicher/i, "industrielle-sicherheit"],
    [/smart.?meter|messeinricht|gateway/i, "smart-metering"],
    [/block.*chain|distributed.*ledger/i, "blockchain"],
    [/ki|künstliche.*intelligenz|machine.*learn|ai/i, "ki"],
    [/satellit/i, "satellit"],
    [/vsn?fd|geheim.*schutz|verschlusssache/i, "geheimschutz"],
    [/archiv|langzeit.*speicher|beweis.*wert/i, "archivierung"],
    [/backup|datensicher/i, "datensicherung"],
    [/server|rechenzentrum/i, "server"],
    [/client|arbeitsplatz/i, "client"],
  ];

  for (const [pattern, topic] of topicPatterns) {
    if (pattern.test(lower) || pattern.test(reference.toLowerCase())) {
      if (!topics.includes(topic)) {
        topics.push(topic);
      }
    }
  }

  // Add a generic topic based on the TR number range
  const trNum = reference.match(/TR[-\s]*(\d{2})/);
  if (trNum?.[1]) {
    const prefix = trNum[1];
    const trTopics: Record<string, string> = {
      "01": "sicherheitsbewertung",
      "02": "kryptographie",
      "03": "egovernment",
    };
    const t = trTopics[prefix];
    if (t && !topics.includes(t)) {
      topics.push(t);
    }
  }

  return topics.length > 0 ? topics : ["allgemein"];
}

// ---------------------------------------------------------------------------
// Database insert helpers
// ---------------------------------------------------------------------------

function createInsertStatements(db: Database.Database) {
  const insertGuidance = db.prepare(`
    INSERT OR REPLACE INTO guidance
      (reference, title, title_en, date, type, series, summary, full_text, topics, status)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertAdvisory = db.prepare(`
    INSERT OR REPLACE INTO advisories
      (reference, title, date, severity, affected_products, summary, full_text, cve_references)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertFramework = db.prepare(
    "INSERT OR REPLACE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)",
  );

  const updateFrameworkCount = db.prepare(
    "UPDATE frameworks SET document_count = (SELECT count(*) FROM guidance WHERE series = ?) WHERE id = ?",
  );

  return { insertGuidance, insertAdvisory, insertFramework, updateFrameworkCount };
}

// ---------------------------------------------------------------------------
// Main orchestrator
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("BSI Ingestion Crawler");
  console.log("=====================");
  console.log(`  Database:       ${DB_PATH}`);
  console.log(`  Flags:          ${[force && "--force", dryRun && "--dry-run", resume && "--resume", advisoriesOnly && "--advisories-only", guidanceOnly && "--guidance-only"].filter(Boolean).join(", ") || "(none)"}`);
  console.log(`  Rate limit:     ${RATE_LIMIT_MS}ms between requests`);
  console.log(`  Max retries:    ${MAX_RETRIES}`);
  console.log();

  const db = dryRun ? null : initDatabase();
  const stmts = db ? createInsertStatements(db) : null;
  const progress = loadProgress();

  let guidanceInserted = 0;
  let advisoriesInserted = 0;

  // ── Frameworks ──────────────────────────────────────────────────────────

  if (!advisoriesOnly && stmts && db) {
    console.log("\n=== Inserting frameworks ===");
    const insertFrameworks = db.transaction(() => {
      for (const f of FRAMEWORKS) {
        stmts.insertFramework.run(f.id, f.name, f.name_en, f.description, f.document_count);
      }
    });
    insertFrameworks();
    console.log(`  Inserted ${FRAMEWORKS.length} frameworks`);
  }

  // ── Technical Guidelines ────────────────────────────────────────────────

  if (!advisoriesOnly) {
    const trEntries = await discoverTechnicalGuidelines();
    console.log(`\n=== Crawling ${trEntries.length} Technical Guidelines ===`);

    for (let i = 0; i < trEntries.length; i++) {
      const entry = trEntries[i]!;
      if (progress.completed_tr_urls.includes(entry.detailUrl)) {
        console.log(
          `  [${i + 1}/${trEntries.length}] ${entry.reference} — skipped (already completed)`,
        );
        continue;
      }

      console.log(
        `  [${i + 1}/${trEntries.length}] ${entry.reference}: ${entry.title.slice(0, 60)}...`,
      );

      const row = await crawlTrDetail(entry);
      if (row) {
        if (dryRun) {
          console.log(
            `    [dry-run] Would insert: ${row.reference} (${row.full_text.length} chars)`,
          );
        } else if (stmts) {
          stmts.insertGuidance.run(
            row.reference, row.title, row.title_en, row.date,
            row.type, row.series, row.summary, row.full_text,
            row.topics, row.status,
          );
          guidanceInserted++;
        }
      }

      progress.completed_tr_urls.push(entry.detailUrl);
      if ((i + 1) % 5 === 0) {
        saveProgress(progress);
      }
    }
    saveProgress(progress);
  }

  // ── BSI Standards ───────────────────────────────────────────────────────

  if (!advisoriesOnly) {
    console.log(`\n=== Crawling ${BSI_STANDARDS.length} BSI Standards ===`);

    for (let i = 0; i < BSI_STANDARDS.length; i++) {
      const std = BSI_STANDARDS[i]!;
      if (progress.completed_standards.includes(std.reference)) {
        console.log(
          `  [${i + 1}/${BSI_STANDARDS.length}] ${std.reference} — skipped (already completed)`,
        );
        continue;
      }

      console.log(
        `  [${i + 1}/${BSI_STANDARDS.length}] ${std.reference}: ${std.title}`,
      );

      const row = await crawlBsiStandard(std);
      if (row) {
        if (dryRun) {
          console.log(
            `    [dry-run] Would insert: ${row.reference} (${row.full_text.length} chars)`,
          );
        } else if (stmts) {
          stmts.insertGuidance.run(
            row.reference, row.title, row.title_en, row.date,
            row.type, row.series, row.summary, row.full_text,
            row.topics, row.status,
          );
          guidanceInserted++;
        }
      }

      progress.completed_standards.push(std.reference);
    }
    saveProgress(progress);
  }

  // ── IT-Grundschutz building blocks ──────────────────────────────────────

  if (!advisoriesOnly) {
    console.log(
      `\n=== Crawling ${GRUNDSCHUTZ_MODULES.length} IT-Grundschutz modules ===`,
    );

    for (let i = 0; i < GRUNDSCHUTZ_MODULES.length; i++) {
      const mod = GRUNDSCHUTZ_MODULES[i]!;
      if (progress.completed_grundschutz_refs.includes(mod.ref)) {
        console.log(
          `  [${i + 1}/${GRUNDSCHUTZ_MODULES.length}] ${mod.ref} — skipped (already completed)`,
        );
        continue;
      }

      console.log(
        `  [${i + 1}/${GRUNDSCHUTZ_MODULES.length}] ${mod.ref}: ${mod.title}`,
      );

      const row = await crawlGrundschutzModule(mod);
      if (row) {
        if (dryRun) {
          console.log(
            `    [dry-run] Would insert: ${row.reference} (${row.full_text.length} chars)`,
          );
        } else if (stmts) {
          stmts.insertGuidance.run(
            row.reference, row.title, row.title_en, row.date,
            row.type, row.series, row.summary, row.full_text,
            row.topics, row.status,
          );
          guidanceInserted++;
        }
      }

      progress.completed_grundschutz_refs.push(mod.ref);
      if ((i + 1) % 10 === 0) {
        saveProgress(progress);
      }
    }
    saveProgress(progress);
  }

  // ── Security advisories (CERT-Bund RSS) ─────────────────────────────────

  if (!guidanceOnly) {
    const rssAdvisories = await fetchAdvisoriesFromRss();
    console.log(
      `\n=== Crawling ${rssAdvisories.length} advisory detail pages ===`,
    );

    for (let i = 0; i < rssAdvisories.length; i++) {
      const adv = rssAdvisories[i]!;
      if (progress.completed_advisory_refs.includes(adv.reference)) {
        console.log(
          `  [${i + 1}/${rssAdvisories.length}] ${adv.reference} — skipped (already completed)`,
        );
        continue;
      }

      console.log(
        `  [${i + 1}/${rssAdvisories.length}] ${adv.reference}: ${adv.title.slice(0, 60)}...`,
      );

      const row = await crawlAdvisoryDetail(adv);
      if (row) {
        if (dryRun) {
          console.log(
            `    [dry-run] Would insert: ${row.reference} (${row.full_text.length} chars)`,
          );
        } else if (stmts) {
          stmts.insertAdvisory.run(
            row.reference, row.title, row.date, row.severity,
            row.affected_products, row.summary, row.full_text,
            row.cve_references,
          );
          advisoriesInserted++;
        }
      }

      progress.completed_advisory_refs.push(adv.reference);
      if ((i + 1) % 10 === 0) {
        saveProgress(progress);
      }
    }
    saveProgress(progress);

    // Also crawl the BSI Cyber-Sicherheitswarnungen page for high-level warnings
    const cswAdvisories = await fetchCyberSecurityWarnings();
    console.log(
      `\n=== Inserting ${cswAdvisories.length} Cyber-Sicherheitswarnungen ===`,
    );

    for (const row of cswAdvisories) {
      if (progress.completed_advisory_refs.includes(row.reference)) {
        continue;
      }

      if (dryRun) {
        console.log(`  [dry-run] Would insert: ${row.reference}`);
      } else if (stmts) {
        stmts.insertAdvisory.run(
          row.reference, row.title, row.date, row.severity,
          row.affected_products, row.summary, row.full_text,
          row.cve_references,
        );
        advisoriesInserted++;
      }

      progress.completed_advisory_refs.push(row.reference);
    }
    saveProgress(progress);
  }

  // ── Update framework document counts ────────────────────────────────────

  if (stmts && db && !dryRun) {
    stmts.updateFrameworkCount.run("TR", "bsi-tr");
    stmts.updateFrameworkCount.run("BSI-Standard", "bsi-standard");
    stmts.updateFrameworkCount.run("IT-Grundschutz", "it-grundschutz");
    console.log("\n  Updated framework document counts");
  }

  // ── Summary ─────────────────────────────────────────────────────────────

  if (db && !dryRun) {
    const guidanceCount = (
      db.prepare("SELECT count(*) as cnt FROM guidance").get() as { cnt: number }
    ).cnt;
    const advisoryCount = (
      db.prepare("SELECT count(*) as cnt FROM advisories").get() as {
        cnt: number;
      }
    ).cnt;
    const frameworkCount = (
      db.prepare("SELECT count(*) as cnt FROM frameworks").get() as {
        cnt: number;
      }
    ).cnt;
    const guidanceFtsCount = (
      db.prepare("SELECT count(*) as cnt FROM guidance_fts").get() as {
        cnt: number;
      }
    ).cnt;
    const advisoryFtsCount = (
      db.prepare("SELECT count(*) as cnt FROM advisories_fts").get() as {
        cnt: number;
      }
    ).cnt;

    console.log("\n=====================");
    console.log("Database summary:");
    console.log(`  Frameworks:      ${frameworkCount}`);
    console.log(
      `  Guidance docs:   ${guidanceCount} (FTS entries: ${guidanceFtsCount}) [+${guidanceInserted} this run]`,
    );
    console.log(
      `  Advisories:      ${advisoryCount} (FTS entries: ${advisoryFtsCount}) [+${advisoriesInserted} this run]`,
    );
    console.log(`\nDatabase ready at ${DB_PATH}`);

    db.close();
  } else if (dryRun) {
    console.log("\n=====================");
    console.log("[dry-run] No database changes made");
    console.log(
      `  Would have inserted ~${progress.completed_tr_urls.length} TRs, ` +
        `${BSI_STANDARDS.length} standards, ` +
        `${GRUNDSCHUTZ_MODULES.length} Grundschutz modules, ` +
        `and CERT-Bund advisories from RSS feed`,
    );
  }

  // Clean up progress file on successful full run (not resume)
  if (!resume && !dryRun && existsSync(PROGRESS_FILE)) {
    unlinkSync(PROGRESS_FILE);
    console.log("Cleaned up progress file");
  }

  console.log("\nDone.");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

main().catch((err) => {
  console.error("\nFatal error:", err);
  process.exit(1);
});
