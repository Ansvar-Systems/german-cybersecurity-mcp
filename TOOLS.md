# Tools Reference — German Cybersecurity MCP

All tools use the `de_cyber_` prefix. Tool responses include a `_meta` block with disclaimer, copyright, source URL, and data age.

---

## Search and Retrieval Tools

### `de_cyber_search_guidance`

Full-text search across BSI guidelines and technical reports.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | yes | Search query (e.g., `"TLS Kryptographie"`, `"IT-Grundschutz Server"`) |
| `type` | enum | no | Filter by document type: `technical_guideline`, `it_grundschutz`, `standard`, `recommendation` |
| `series` | enum | no | Filter by series: `TR`, `IT-Grundschutz`, `BSI-Standard` |
| `status` | enum | no | Filter by status: `current`, `superseded`, `draft` |
| `limit` | number | no | Maximum results to return (default: 20, max: 100) |

**Returns:** `{ results: Guidance[], count: number, _meta: Meta }`

---

### `de_cyber_get_guidance`

Fetch a specific BSI guidance document by its reference identifier.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `reference` | string | yes | BSI document reference (e.g., `"BSI TR-03116"`, `"BSI-Standard 200-2"`, `"SYS.1.1"`) |

**Returns:** Full guidance document with `_citation` and `_meta` blocks.

---

### `de_cyber_search_advisories`

Search BSI security advisories and alerts.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | yes | Search query (e.g., `"kritische Schwachstelle"`, `"Ransomware"`, `"VPN"`) |
| `severity` | enum | no | Filter by severity: `critical`, `high`, `medium`, `low` |
| `limit` | number | no | Maximum results to return (default: 20, max: 100) |

**Returns:** `{ results: Advisory[], count: number, _meta: Meta }`

---

### `de_cyber_get_advisory`

Fetch a specific BSI security advisory by its reference identifier.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `reference` | string | yes | BSI advisory reference (e.g., `"BSI-CB-K24-0001"`) |

**Returns:** Full advisory with `_citation` and `_meta` blocks.

---

### `de_cyber_list_frameworks`

List all BSI frameworks and standard series covered by this MCP.

**Input:** none

**Returns:** `{ frameworks: Framework[], count: number, _meta: Meta }`

---

## Meta Tools

### `de_cyber_about`

Return metadata about this MCP server: version, data source, coverage summary, and tool list.

**Input:** none

**Returns:** Server metadata object including `coverage` and `tools` array.

---

### `de_cyber_list_sources`

List all data sources ingested into this MCP with URLs and document type coverage.

**Input:** none

**Returns:** `{ sources: Source[], _meta: Meta }`

Each source includes:
- `id` — Source identifier
- `name` / `name_de` — English and German names
- `url` — Official portal URL
- `types` — Document types from this source
- `series` — Series identifiers

---

### `de_cyber_check_data_freshness`

Return the most recent document date in the local database, indicating how up-to-date the data is.

**Input:** none

**Returns:**
```json
{
  "guidance_latest_date": "2024-11-15",
  "advisories_latest_date": "2025-01-08",
  "checked_at": "2026-04-09T10:00:00.000Z",
  "status": "ok",
  "note": "...",
  "_meta": { ... }
}
```

---

## Response Envelope

### `_citation` block (get_* tools only)

```json
{
  "_citation": {
    "canonical_ref": "BSI TR-03116",
    "display_text": "BSI TR-03116",
    "source_url": "https://www.bsi.bund.de/...",
    "lookup": {
      "tool": "de_cyber_get_guidance",
      "args": { "reference": "BSI TR-03116" }
    }
  }
}
```

### `_meta` block (all tools)

```json
{
  "_meta": {
    "disclaimer": "BSI content reproduced for informational purposes only. Verify current content at the official BSI portal before relying on it for compliance or security decisions.",
    "copyright": "© Bundesamt für Sicherheit in der Informationstechnik (BSI). All rights reserved.",
    "source_url": "https://www.bsi.bund.de/",
    "data_age": {
      "guidance_latest_date": "2024-11-15",
      "advisories_latest_date": "2025-01-08"
    }
  }
}
```
