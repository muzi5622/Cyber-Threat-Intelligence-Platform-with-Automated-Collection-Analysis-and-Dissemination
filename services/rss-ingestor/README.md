# RSS Ingestor (OpenCTI Report Creator)

`rss-ingestor` is an automated OSINT collection service that reads a list of CTI RSS/Atom feeds, pulls recent items, and creates **OpenCTI Reports** from those items. Each created report includes an **External Reference** pointing back to the original article and is attributed to a configurable **producer identity** (createdBy).

It is designed to run as a container alongside OpenCTI in a CTI platform stack.

---

## What it does

On a loop (default every 300s), the service:

1. Loads feed URLs from `feeds.txt` (configurable path).
2. Parses each RSS/Atom feed using `feedparser`.
3. Filters items by a lookback window (default 30 days).
4. Deduplicates items using a SQLite state DB (can be disabled).
5. For each accepted entry (up to `MAX_ITEMS_PER_FEED` per feed):
   - Creates an **External Reference** with the entry URL (and notes the source feed URL)
   - Creates an **OpenCTI Report** (`report_types: ["threat-report"]`)
   - Sets `published` to the feed item timestamp (ISO datetime)
   - Sets `createdBy` to a producer **Identity** (Organization), created if missing
6. Logs progress and errors to stdout.

---

## Requirements

- OpenCTI reachable over the network (default `http://opencti:8080`)
- A valid OpenCTI API token (`OPENCTI_TOKEN`)
- A feed list file (`feeds.txt`)
- Docker / Docker Compose (recommended)

---

## Files

- `app.py` — main ingestion loop + OpenCTI GraphQL calls
- `Dockerfile` — container build (Python slim + dependencies)
- `feeds.txt` — list of RSS/Atom feed URLs (one per line; supports comments)

### `feeds.txt` format

- One feed URL per line
- Blank lines ignored
- Lines starting with `#` are comments

Example:

```txt
# Threat intel feeds
https://example.com/rss.xml
https://another-source.org/atom.xml
````

---

## Configuration (Environment Variables)

| Variable             | Default                                            | Description                                      |
| -------------------- | -------------------------------------------------- | ------------------------------------------------ |
| `OPENCTI_BASE`       | `http://opencti:8080`                              | Base URL of OpenCTI                              |
| `OPENCTI_TOKEN`      | *(required)*                                       | OpenCTI API token (Bearer)                       |
| `RUN_EVERY_SECONDS`  | `300`                                              | Loop interval (seconds)                          |
| `FEEDS_FILE`         | `/app/feeds.txt`                                   | Path to feeds file inside container              |
| `MAX_ITEMS_PER_FEED` | `5`                                                | Maximum reports to create per feed per cycle     |
| `LOOKBACK_DAYS`      | `30`                                               | Only ingest items published within last N days   |
| `DISABLE_DEDUP`      | `false`                                            | If true, disables deduplication entirely         |
| `RSS_STATE_DB`       | `/state/rss.db`                                    | SQLite DB path for dedup state (mount a volume!) |
| `RSS_PRODUCER_NAME`  | `RSS Feed Ingestor`                                | OpenCTI Identity name used for `createdBy`       |
| `RSS_PRODUCER_DESC`  | `Automated OSINT collection from CTI RSS sources.` | Identity description                             |
| `RSS_CONFIDENCE`     | `50`                                               | Confidence value applied to created reports      |

> Notes:
>
> * Deduplication uses a stable SHA-256 hash of `feed_url + entry.id + entry.link + entry.title`.
> * If `DISABLE_DEDUP=true`, the service may recreate the same reports on every run.

---

## Running with Docker

### Build

```bash
docker build -t rss-ingestor:latest .
```

### Run (with persistent state)

```bash
docker run --rm \
  -e OPENCTI_BASE="http://opencti:8080" \
  -e OPENCTI_TOKEN="YOUR_TOKEN_HERE" \
  -e LOOKBACK_DAYS="30" \
  -e MAX_ITEMS_PER_FEED="5" \
  -e RSS_STATE_DB="/state/rss.db" \
  -v rss_ingestor_state:/state \
  rss-ingestor:latest
```

---

## Recommended: Docker Compose example

```yaml
services:
  rss-ingestor:
    build: ./services/rss-ingestor
    environment:
      OPENCTI_BASE: "http://opencti:8080"
      OPENCTI_TOKEN: "${OPENCTI_TOKEN}"
      RUN_EVERY_SECONDS: "300"
      FEEDS_FILE: "/app/feeds.txt"
      LOOKBACK_DAYS: "30"
      MAX_ITEMS_PER_FEED: "5"
      RSS_CONFIDENCE: "50"
      RSS_STATE_DB: "/state/rss.db"
      RSS_PRODUCER_NAME: "RSS Feed Ingestor"
      RSS_PRODUCER_DESC: "Automated OSINT collection from CTI RSS sources."
      DISABLE_DEDUP: "false"
    volumes:
      - rss_ingestor_state:/state
      # Optional: override feeds from host repo
      # - ./services/rss-ingestor/feeds.txt:/app/feeds.txt:ro
    depends_on:
      - opencti
    restart: unless-stopped

volumes:
  rss_ingestor_state:
```

---

## Output / Logs

The container logs:

* number of feeds loaded and active settings
* per-feed progress (`created=N`)
* each created report title (truncated)
* failures (externalReferenceAdd/reportAdd/OpenCTI connectivity)

Example log lines:

* `[rss-ingestor] loaded 12 feeds | lookback=30d | max_items_per_feed=5`
* `[rss-ingestor] +report (1/5) Some Threat Report Title...`
* `[rss-ingestor] feed done: https://... | created=5`

---

## Troubleshooting

### `OPENCTI_TOKEN is empty`

Set `OPENCTI_TOKEN` in your environment or compose `.env`.

### OpenCTI not ready / connection issues

The ingestor performs a basic GraphQL health check (`about { version }`). If it fails:

* confirm `OPENCTI_BASE` is reachable from the container network
* confirm OpenCTI is running and healthy
* confirm token permissions

### Duplicate reports still being created

* Ensure `/state` is mounted to a persistent volume
* Verify `RSS_STATE_DB` points to the mounted path
* Make sure `DISABLE_DEDUP` is not enabled

### Some feed items missing dates

The service tries multiple date fields and falls back to “now” if parsing fails. If a feed uses unusual date formats, items may be treated as new.

---

## Security Notes

* Treat `OPENCTI_TOKEN` as a secret (use secrets manager or env injection).
* Prefer mounting `feeds.txt` read-only if overriding it from host.

---

## License

Part of the **Cyber-Threat-Intelligence-Platform-with-Automated-Collection-Analysis-and-Dissemination** project.

