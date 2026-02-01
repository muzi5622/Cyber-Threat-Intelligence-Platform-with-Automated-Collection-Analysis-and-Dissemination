# CTI Platform (EduQual Level 6) — Automated Collection → Analysis → Dissemination

**Project Title:** Comprehensive Cyber Threat Intelligence Platform with Automated Collection, Analysis, and Dissemination

**Student:** Muzammal

**Diploma:** Diploma in Artificial Intelligence Operations (EduQual Level 6)

**Platform Core:** OpenCTI + RSS OSINT + NLP IOC Extraction + TAXII-style STIX export

## 1) What This Project Does (End-to-End)

This platform automates the full CTI lifecycle:

1. **Collection (OSINT):** Pulls CTI articles from 23 RSS feeds (TrendMicro, HackerNews, SANS, etc.) and creates **OpenCTI Reports** automatically.
2. **Analysis & Enrichment (NLP):** Reads recent reports, extracts IOCs (domains, URLs, IPs, hashes, CVEs), assigns confidence score, and creates **OpenCTI Observables + Indicators**.
3. **Dissemination (Sharing):** Exports the extracted intelligence as a **STIX 2.1 JSON bundle** and serves it via a demo “TAXII-like” endpoint.
4. **Strategic Decision Support:** Provides a unified OpenCTI dashboard for reports, observables, indicators (evidence for executive briefings / SOC usage).

---

## 2) Architecture (Layered)

### Layer 3 (Core Dependencies)

* **Redis**: cache / internal OpenCTI use
* **Elasticsearch**: indexing and search backend for OpenCTI
* **RabbitMQ**: queue for async tasks and worker communication
* **MinIO**: object storage (OpenCTI uses it for attachments/files)

### Layer 3 (CTI Knowledge Base)

* **OpenCTI Platform**: UI dashboard + GraphQL API
* **OpenCTI Worker**: background jobs (connectors, indexing)

### Layer 1 (OSINT Collection)

* **RSS Ingestor (custom)**: reads `/app/feeds.txt`, creates OpenCTI Reports automatically
* **SpiderFoot**: optional OSINT recon (web UI)

### Layer 4 (NLP/ML Enrichment)

* **NLP Enricher (custom)**: extracts IOCs from report text and pushes Observables/Indicators

### Layer 5 (Sharing / Dissemination)

* **TAXII Exporter (custom)**: creates STIX bundle JSON from OpenCTI intelligence
* **TAXII Demo Server**: serves the STIX bundle at `http://localhost:9000/bundle.json`

---

## 3) Folder Structure

```
cti-platform/
├─ docker-compose.yml
├─ .env
├─ data/
│  ├─ opencti-export/         # output for STIX bundle
│  ├─ rss/                    # rss-ingestor state DB
│  └─ nlp/                    # nlp-enricher state DB
└─ services/
   ├─ rss-ingestor/
   │  ├─ Dockerfile
   │  ├─ app.py
   │  └─ feeds.txt
   ├─ nlp-enricher/
   │  ├─ Dockerfile
   │  └─ app.py
   ├─ taxii-exporter/
   │  └─ ... exporter code
   └─ spiderfoot-web/
      └─ default.conf
```

---

## 4) Requirements

* Linux VM (recommended Ubuntu 22.04+)
* Docker + Docker Compose plugin

### Install Docker (Ubuntu quick)

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker
```

Verify:

```bash
docker --version
docker compose version
```

---

## 5) Environment Setup (.env)

Create `.env` in the project root:

```env
OPENCTI_ADMIN_EMAIL=admin@demo.local
OPENCTI_ADMIN_PASSWORD=ChangeMe_Admin123!
OPENCTI_ADMIN_TOKEN=3f3b8b7a-3cfe-4b6a-9f9c-7d0b0a0b0b0b

RABBITMQ_USER=opencti
RABBITMQ_PASS=opencti_password_change_me

MINIO_USER=opencti
MINIO_PASS=opencti_password_change_me

APP_BASE_URL=http://localhost:8080
```

**Important:** When using curl, load env vars:

```bash
set -a; source ./.env; set +a
```

---

## 6) docker-compose.yml (Services Summary)

Your compose file runs:

* redis, elasticsearch, rabbitmq, minio
* opencti platform + worker
* spiderfoot (+ optional nginx front)
* rss-ingestor (custom)
* nlp-enricher (custom)
* taxii-exporter (custom)
* taxii-server (demo static STIX server)

---

## 7) Start the Platform

From project root:

```bash
docker compose up -d --build
docker compose ps
```

---

## 8) Access URLs (Web UIs)

* **OpenCTI Dashboard:** `http://<server-ip>:8080`
* **RabbitMQ Management:** `http://<server-ip>:15672`
* **SpiderFoot UI (direct):** `http://<server-ip>:5001`
* **SpiderFoot Clean URL (nginx):** `http://<server-ip>:5002/spiderfoot`
* **STIX Bundle (TAXII demo):** `http://<server-ip>:9000/bundle.json`
* **Intel API (if enabled):** `http://<server-ip>:8000`

---

## 9) How Automation Works (End-to-End Flow)

### A) RSS Ingestor → OpenCTI Reports (Collection)

* Reads `feeds.txt` (23 feeds)
* Fetches items from each feed
* Creates Reports in OpenCTI using GraphQL
* Uses sqlite state DB so it does not ingest duplicates

**RSS ingestor logs show:**

* `loaded 23 feeds`
* `+report ...`
* `feed done ... created=X`

Run logs:

```bash
docker compose logs -f rss-ingestor
```

### B) NLP Enricher → Observables/Indicators (Analysis)

* Fetches latest OpenCTI reports
* Extracts IOCs using regex (IPv4/IPv6/Domain/URL/Hashes/CVE)
* Creates Observables via correct OpenCTI mutation:

  * DomainName `{value}`
  * Url `{value}`
  * IPv4Addr `{value}`
  * StixFile `{hashes: [{algorithm, hash}]}`
* Adds label `auto-extracted`
* `createIndicator=true` creates indicators automatically (better for TAXII export)

Logs:

```bash
docker compose logs -f nlp-enricher
```

### C) TAXII Exporter → STIX Bundle JSON (Dissemination)

* Exports intelligence to a STIX bundle file in `data/opencti-export/`
* TAXII demo server serves it at `/bundle.json`

Restart exporter to refresh output:

```bash
docker compose restart taxii-exporter
curl -s http://127.0.0.1:9000/bundle.json | head -n 40
```

---

## 10) Verification Checklist (Proof Everything Works)

Use these commands in your presentation as “evidence”.

### ✅ 1) OpenCTI is up

```bash
curl -I http://127.0.0.1:8080/
```

Expected: `HTTP/1.1 200 OK`

### ✅ 2) Reports are being created (Collection OK)

```bash
set -a; source ./.env; set +a

curl -s http://127.0.0.1:8080/graphql \
  -H "Authorization: Bearer ${OPENCTI_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { reports(first:20, orderBy:created_at, orderMode:desc){ edges{ node{ name created_at }}}}"}'
```

Expected: multiple report titles from multiple feeds.

### ✅ 3) NLP enrichment is creating observables (Analysis OK)

```bash
curl -s http://127.0.0.1:8080/graphql \
  -H "Authorization: Bearer ${OPENCTI_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { stixCyberObservables(first:20, orderBy:created_at, orderMode:desc){ edges{ node{ observable_value x_opencti_score created_at }}}}"}'
```

Expected: domains, urls, ips, hashes with confidence score.

### ✅ 4) TAXII bundle is not empty (Dissemination OK)

```bash
curl -s http://127.0.0.1:9000/bundle.json | head -n 40
```

Expected: `objects` includes indicators/observables.

### ✅ 5) RSS ingestor feed count is correct

```bash
docker compose exec rss-ingestor sh -lc 'wc -l /app/feeds.txt && sed -n "1,30p" /app/feeds.txt'
```

Expected: `23 /app/feeds.txt`

---

## 11) How to Generate MORE Reports (Demo Mode)

If you want a lot of reports quickly (for exam demo), set rss-ingestor env in compose:

```yaml
MAX_ITEMS_PER_FEED: "10"
LOOKBACK_DAYS: "180"
DISABLE_DEDUP: "true"
```

Then:

```bash
docker compose up -d --build --force-recreate rss-ingestor
docker compose logs -f rss-ingestor
```

After you generate enough reports, switch `DISABLE_DEDUP` back to `false`.

---

## 12) Troubleshooting

### A) “You must be logged in” from GraphQL

Your shell doesn’t have the token loaded.
Fix:

```bash
set -a; source ./.env; set +a
echo $OPENCTI_ADMIN_TOKEN
```

### B) OpenCTI health shows “unhealthy”

It can be “starting” for a while because Elasticsearch indexing takes time.
Check logs:

```bash
docker compose logs --tail=200 opencti
docker compose logs --tail=200 elasticsearch
```

### C) RSS only creates 1 report

Cause: ingestor logic/dedup/old entries.
Fix: use the provided rss-ingestor app.py with:

* MAX_ITEMS_PER_FEED
* LOOKBACK_DAYS
* sqlite state DB

### D) SpiderFoot returns 404 on `/`

SpiderFoot UI is not at `/` for some builds; use:

* `http://<ip>:5001/` or through nginx `http://<ip>:5002/spiderfoot`

---

## 13) “Working Evidence” (Your current real outputs)

From your terminal results:

### Working Observables

You already have observables in OpenCTI:

* `https://www.trendmicro.com/...`
* `feeds.trendmicro.com`
* `www.trendmicro.com`

### Working TAXII bundle

Your `/bundle.json` shows objects like:

* `indicator` with patterns referencing observables

This proves:
✅ Collection → Reports created
✅ Analysis → Observables + Indicators created
✅ Dissemination → STIX bundle exported and served

---

## 14) How to Stop / Reset

Stop:

```bash
docker compose down
```

Full reset (removes volumes/data):

```bash
docker compose down -v
rm -rf data/rss data/nlp data/opencti-export
```

---
, including every port, volume, and environment variable so nothing is missed.
