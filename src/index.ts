#!/usr/bin/env node

/**
 * German Cybersecurity MCP — stdio entry point.
 *
 * Provides MCP tools for querying BSI (Bundesamt für Sicherheit in der
 * Informationstechnik) guidelines, technical reports, security advisories,
 * and IT-Grundschutz frameworks.
 *
 * Tool prefix: de_cyber_
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import {
  searchGuidance,
  getGuidance,
  searchAdvisories,
  getAdvisory,
  listFrameworks,
  getDataFreshness,
} from "./db.js";
import { buildCitation } from "./utils/citation.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let pkgVersion = "0.1.0";
try {
  const pkg = JSON.parse(
    readFileSync(join(__dirname, "..", "package.json"), "utf8"),
  ) as { version: string };
  pkgVersion = pkg.version;
} catch {
  // fallback to default
}

const SERVER_NAME = "german-cybersecurity-mcp";

// --- Tool definitions ---------------------------------------------------------

const TOOLS = [
  {
    name: "de_cyber_search_guidance",
    description:
      "Full-text search across BSI guidelines and technical reports. Covers Technical Guidelines (TR series), IT-Grundschutz building blocks, BSI Standards, and recommendations. Returns matching documents with reference, title, series, and summary.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query (e.g., 'TLS Kryptographie', 'IT-Grundschutz Server', 'ISMS Sicherheitsmanagement')",
        },
        type: {
          type: "string",
          enum: ["technical_guideline", "it_grundschutz", "standard", "recommendation"],
          description: "Filter by document type. Optional.",
        },
        series: {
          type: "string",
          enum: ["TR", "IT-Grundschutz", "BSI-Standard"],
          description: "Filter by BSI series. Optional.",
        },
        status: {
          type: "string",
          enum: ["current", "superseded", "draft"],
          description: "Filter by document status. Defaults to returning all statuses.",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "de_cyber_get_guidance",
    description:
      "Get a specific BSI guidance document by reference (e.g., 'BSI TR-03116', 'BSI TR-02102', 'BSI-Standard 200-1', 'SYS.1.1').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: {
          type: "string",
          description: "BSI document reference (e.g., 'BSI TR-03116', 'BSI-Standard 200-2', 'SYS.1.1')",
        },
      },
      required: ["reference"],
    },
  },
  {
    name: "de_cyber_search_advisories",
    description:
      "Search BSI security advisories and alerts. Returns advisories with severity, affected products, and CVE references where available.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query (e.g., 'kritische Schwachstelle', 'Ransomware', 'VPN')",
        },
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description: "Filter by severity level. Optional.",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "de_cyber_get_advisory",
    description:
      "Get a specific BSI security advisory by reference (e.g., 'BSI-CB-K24-0001').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: {
          type: "string",
          description: "BSI advisory reference (e.g., 'BSI-CB-K24-0001')",
        },
      },
      required: ["reference"],
    },
  },
  {
    name: "de_cyber_list_frameworks",
    description:
      "List all BSI frameworks and standard series covered in this MCP, including IT-Grundschutz Kompendium, BSI Technical Guideline (TR) series, and BSI Standards series.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "de_cyber_about",
    description: "Return metadata about this MCP server: version, data source, coverage, and tool list.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "de_cyber_list_sources",
    description: "List all data sources ingested into this MCP: BSI guidance portal and advisory feed.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "de_cyber_check_data_freshness",
    description: "Return the most recent document date in the local database for guidance and advisories, indicating how up-to-date the data is.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
];

// --- Zod schemas for argument validation --------------------------------------

const SearchGuidanceArgs = z.object({
  query: z.string().min(1),
  type: z.enum(["technical_guideline", "it_grundschutz", "standard", "recommendation"]).optional(),
  series: z.enum(["TR", "IT-Grundschutz", "BSI-Standard"]).optional(),
  status: z.enum(["current", "superseded", "draft"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetGuidanceArgs = z.object({
  reference: z.string().min(1),
});

const SearchAdvisoriesArgs = z.object({
  query: z.string().min(1),
  severity: z.enum(["critical", "high", "medium", "low"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetAdvisoryArgs = z.object({
  reference: z.string().min(1),
});

// --- Helpers -----------------------------------------------------------------

function buildMeta() {
  const freshness = getDataFreshness();
  return {
    disclaimer:
      "BSI content reproduced for informational purposes only. Verify current content at the official BSI portal before relying on it for compliance or security decisions.",
    copyright:
      "© Bundesamt für Sicherheit in der Informationstechnik (BSI). All rights reserved.",
    source_url: "https://www.bsi.bund.de/",
    data_age: {
      guidance_latest_date: freshness.guidance_latest_date,
      advisories_latest_date: freshness.advisories_latest_date,
    },
  };
}

function textContent(data: unknown) {
  return {
    content: [
      { type: "text" as const, text: JSON.stringify(data, null, 2) },
    ],
  };
}

function errorContent(message: string) {
  return {
    content: [{ type: "text" as const, text: message }],
    isError: true as const,
  };
}

// --- Server setup ------------------------------------------------------------

const server = new Server(
  { name: SERVER_NAME, version: pkgVersion },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

  try {
    switch (name) {
      case "de_cyber_search_guidance": {
        const parsed = SearchGuidanceArgs.parse(args);
        const results = searchGuidance({
          query: parsed.query,
          type: parsed.type,
          series: parsed.series,
          status: parsed.status,
          limit: parsed.limit,
        });
        return textContent({ results, count: results.length, _meta: buildMeta() });
      }

      case "de_cyber_get_guidance": {
        const parsed = GetGuidanceArgs.parse(args);
        const doc = getGuidance(parsed.reference);
        if (!doc) {
          return errorContent(`Guidance document not found: ${parsed.reference}`);
        }
        const d = doc as Record<string, unknown>;
        return textContent({
          ...doc,
          _citation: buildCitation(
            String(d.reference ?? parsed.reference),
            String(d.title ?? d.reference ?? parsed.reference),
            "de_cyber_get_guidance",
            { reference: parsed.reference },
            d.url as string | undefined,
          ),
          _meta: buildMeta(),
        });
      }

      case "de_cyber_search_advisories": {
        const parsed = SearchAdvisoriesArgs.parse(args);
        const results = searchAdvisories({
          query: parsed.query,
          severity: parsed.severity,
          limit: parsed.limit,
        });
        return textContent({ results, count: results.length, _meta: buildMeta() });
      }

      case "de_cyber_get_advisory": {
        const parsed = GetAdvisoryArgs.parse(args);
        const advisory = getAdvisory(parsed.reference);
        if (!advisory) {
          return errorContent(`Advisory not found: ${parsed.reference}`);
        }
        const a = advisory as Record<string, unknown>;
        return textContent({
          ...advisory,
          _citation: buildCitation(
            String(a.reference ?? parsed.reference),
            String(a.title ?? a.reference ?? parsed.reference),
            "de_cyber_get_advisory",
            { reference: parsed.reference },
            a.url as string | undefined,
          ),
          _meta: buildMeta(),
        });
      }

      case "de_cyber_list_frameworks": {
        const frameworks = listFrameworks();
        return textContent({ frameworks, count: frameworks.length, _meta: buildMeta() });
      }

      case "de_cyber_about": {
        return textContent({
          name: SERVER_NAME,
          version: pkgVersion,
          description:
            "BSI (Bundesamt für Sicherheit in der Informationstechnik — German Federal Office for Information Security) MCP server. Provides access to BSI technical guidelines, IT-Grundschutz building blocks, BSI Standards, and security advisories.",
          data_source: "BSI (https://www.bsi.bund.de/)",
          coverage: {
            guidance: "BSI Technical Guidelines (TR series), IT-Grundschutz building blocks, BSI Standards (200 series)",
            advisories: "BSI security advisories and alerts (CB-K series)",
            frameworks: "IT-Grundschutz Kompendium, BSI TR series, BSI Standards series",
          },
          tools: TOOLS.map((t) => ({ name: t.name, description: t.description })),
          _meta: buildMeta(),
        });
      }

      case "de_cyber_list_sources": {
        return textContent({
          sources: [
            {
              id: "bsi-guidance",
              name: "BSI Technical Guidelines and Standards",
              name_de: "BSI Technische Richtlinien und Standards",
              url: "https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/",
              types: ["technical_guideline", "it_grundschutz", "standard", "recommendation"],
              series: ["TR", "IT-Grundschutz", "BSI-Standard"],
            },
            {
              id: "bsi-advisories",
              name: "BSI Security Advisories (CB-K series)",
              name_de: "BSI-Sicherheitshinweise (CB-K-Reihe)",
              url: "https://www.bsi.bund.de/SiteGlobals/Forms/Suche/BSI/Sicherheitswarnungen/Sicherheitswarnungen_Formular.html",
              types: ["advisory"],
              series: ["CB-K"],
            },
          ],
          _meta: buildMeta(),
        });
      }

      case "de_cyber_check_data_freshness": {
        const freshness = getDataFreshness();
        return textContent({
          ...freshness,
          status: "ok",
          note: "Dates reflect the most recent document date in the local database. Run the ingest script to refresh.",
          _meta: buildMeta(),
        });
      }

      default:
        return errorContent(`Unknown tool: ${name}`);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return errorContent(`Error executing ${name}: ${message}`);
  }
});

// --- Main --------------------------------------------------------------------

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(`${SERVER_NAME} v${pkgVersion} running on stdio\n`);
}

main().catch((err) => {
  process.stderr.write(`Fatal error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
