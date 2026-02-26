# NLP Enricher (OpenCTI IOC Extractor)

`nlp-enricher` is a lightweight enrichment service that continuously pulls recent **Reports** from **OpenCTI**, extracts common **Indicators of Compromise (IOCs)** from report text (name + description), and pushes them back into OpenCTI as **STIX Cyber Observables** (and optionally Indicators). CVEs are pushed as **Vulnerabilities**.

It’s designed to run as a container alongside OpenCTI in a CTI platform stack.

---

## What it does

On a loop (default every 120s), the service:

1. Fetches the most recent OpenCTI reports (configurable limit).
2. Skips reports older than a configured age window.
3. Optionally tracks processed reports in a local SQLite “state DB” to avoid reprocessing.
4. Extracts IOCs from report `name` + `description` using regex patterns:
   - IPv4 / IPv6
   - URLs
   - Domains (with optional TLD ignore list)
   - MD5 / SHA1 / SHA256
   - CVEs (CVE-YYYY-NNNN…)
5. Normalizes & deduplicates extracted values.
6. Pushes results into OpenCTI:
   - Hashes → `StixFile` observables with proper `hashes` field
   - IPs → `IPv4-Addr` / `IPv6-Addr`
   - Domains → `Domain-Name`
   - URLs → `Url`
   - CVEs → `Vulnerability`
7. Optionally adds a label (default: `auto-extracted`) and can create Indicators.

---

## Requirements

- OpenCTI reachable over the network (default `http://opencti:8080`)
- A valid OpenCTI API token (`OPENCTI_TOKEN`)
- Docker / Docker Compose (recommended)

---

## Configuration (Environment Variables)

| Variable | Default | Description |
|---------|---------|-------------|
| `OPENCTI_BASE` | `http://opencti:8080` | Base URL of OpenCTI |
| `OPENCTI_TOKEN` | *(required)* | OpenCTI API token (Bearer) |
| `RUN_EVERY_SECONDS` | `120` | Loop interval (seconds) |
| `NLP_FETCH_LIMIT` | `20` | Number of most recent reports to pull each cycle |
| `NLP_MAX_AGE_DAYS` | `14` | Skip reports older than this many days |
| `NLP_LABEL` | `auto-extracted` | Label applied to created observables (and created once if missing) |
| `NLP_CREATE_INDICATOR` | `true` | If true, OpenCTI will also create Indicators when adding observables |
| `NLP_STATE_DB` | *(empty)* | Path to SQLite DB to track processed report IDs (recommended for production) |
| `NLP_IGNORE_TLDS` | `html,htm,php,aspx,jsp` | Comma-separated list of “TLDs” to ignore to avoid false-positive domains |

> Notes:
> - If `NLP_STATE_DB` is not set, the service may reprocess the same reports each loop.
> - If `OPENCTI_TOKEN` is empty, the service exits with an error.

---

## How scoring works

Each extracted IOC is assigned an `x_opencti_score` (capped at 95) based on type:

- Hashes get a higher baseline confidence
- IPs and CVEs get a boost
- URLs get a small boost
- Deep domains (>= 2 dots) get a small boost

This score is used when creating observables (and vulnerabilities for CVEs).

---

## Running with Docker

### Build

```bash
docker build -t nlp-enricher:latest .
````

### Run

```bash
docker run --rm \
  -e OPENCTI_BASE="http://opencti:8080" \
  -e OPENCTI_TOKEN="YOUR_TOKEN_HERE" \
  -e RUN_EVERY_SECONDS="120" \
  -e NLP_FETCH_LIMIT="20" \
  -e NLP_MAX_AGE_DAYS="14" \
  -e NLP_LABEL="auto-extracted" \
  -e NLP_CREATE_INDICATOR="true" \
  nlp-enricher:latest
```

---

## Recommended: Docker Compose example

```yaml
services:
  nlp-enricher:
    build: ./services/nlp-enricher
    environment:
      OPENCTI_BASE: "http://opencti:8080"
      OPENCTI_TOKEN: "${OPENCTI_TOKEN}"
      RUN_EVERY_SECONDS: "120"
      NLP_FETCH_LIMIT: "20"
      NLP_MAX_AGE_DAYS: "14"
      NLP_LABEL: "auto-extracted"
      NLP_CREATE_INDICATOR: "true"
      NLP_IGNORE_TLDS: "html,htm,php,aspx,jsp"
      NLP_STATE_DB: "/state/nlp.db"
    volumes:
      - nlp_enricher_state:/state
    depends_on:
      - opencti
    restart: unless-stopped

volumes:
  nlp_enricher_state:
```

---

## Output / Logs

The container prints simple status logs to stdout, for example:

* startup confirmation
* label creation readiness
* number of IOCs found
* push errors (duplicates, schema mismatch, API errors)

---

## Troubleshooting

### `OPENCTI_TOKEN is empty`

Set `OPENCTI_TOKEN` in your environment or compose `.env`.

### No observables appear in OpenCTI

* Ensure `OPENCTI_BASE` is reachable from this container.
* Confirm the token has permissions.
* Check logs for `observable push failed` or GraphQL errors.

### Too many false-positive domains (e.g., `index.php`)

Add extensions into `NLP_IGNORE_TLDS`, e.g.:

```bash
-e NLP_IGNORE_TLDS="html,htm,php,asp,aspx,jsp"
```

### Reprocessing the same reports

Set `NLP_STATE_DB` and mount a persistent volume.

---

## IOC Types → OpenCTI Object Mapping

| Extracted Type          | OpenCTI Type              |
| ----------------------- | ------------------------- |
| `ipv4`                  | `IPv4-Addr`               |
| `ipv6`                  | `IPv6-Addr`               |
| `domain`                | `Domain-Name`             |
| `url`                   | `Url`                     |
| `md5`, `sha1`, `sha256` | `StixFile` (hashes field) |
| `cve`                   | `Vulnerability`           |

---

## Security Notes

* Treat `OPENCTI_TOKEN` as a secret. Use Docker secrets or environment injection from a secure source.
* Consider restricting outbound network access if running in a hardened environment.

---

## License

Part of the **Cyber Threat Intelligence Platform with Automated Collection, Analysis and Dissemination** project.

